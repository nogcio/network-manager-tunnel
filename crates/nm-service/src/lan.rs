//! Pure IPv4 capture/LAN bypass planning. NetworkManager installs all normal routes.
use ipnet::{Ipv4Net, Ipv4Subnets};
use std::{io, net::Ipv4Addr};

/// Validated activation-local authority; never accepts arbitrary imported routes.
/// Dropping this value owns no kernel resources. Uplink changes require reconnect.
#[derive(Clone, Default)]
pub(crate) struct Plan {
    subnets: Vec<Ipv4Net>,
    connected: Vec<Ipv4Net>,
    brokered: bool,
    source_capture: bool,
    private_bypass: bool,
}

impl Plan {
    /// Accept only wholly RFC1918 connected prefixes. Public addresses create no
    /// exception; broad private-address/public-prefix combinations reject atomically.
    pub fn connected(addresses: &[(Ipv4Addr, u8)]) -> io::Result<Self> {
        if addresses.len() > 16 {
            return Err(invalid());
        }
        let mut subnets = Vec::new();
        for &(address, prefix) in addresses {
            let net = Ipv4Net::new(address, prefix)
                .map_err(|_| invalid())?
                .trunc();
            if address.is_private() {
                if !net.network().is_private() || !net.broadcast().is_private() {
                    return Err(invalid());
                }
                subnets.push(net);
            }
        }
        if subnets.is_empty() {
            return Err(invalid());
        }
        Ok(Self {
            subnets: Ipv4Net::aggregate(&subnets),
            connected: subnets,
            brokered: false,
            source_capture: false,
            private_bypass: false,
        })
    }

    /// Source-policy capture, not Direct authority. Cover every selected-uplink
    /// connected/static prefix with more-specific VPN routes. /31-/32 cannot be
    /// safely overridden by this NM route contract and reject before networking.
    pub fn capture(addresses: &[(Ipv4Addr, u8)]) -> io::Result<Self> {
        if addresses.len() > 64 {
            return Err(invalid());
        }
        let mut connected = Vec::new();
        for &(address, prefix) in addresses {
            if !(1..=30).contains(&prefix) {
                return Err(invalid());
            }
            connected.push(
                Ipv4Net::new(address, prefix)
                    .map_err(|_| invalid())?
                    .trunc(),
            );
        }
        Ok(Self {
            subnets: Ipv4Net::aggregate(&connected),
            connected,
            brokered: true,
            source_capture: true,
            private_bypass: false,
        })
    }

    /// All RFC1918, not inferred from a connected address or a requester prefix.
    /// Physical routing remains NM's existing routing; this creates no gateway.
    pub fn private() -> io::Result<Self> {
        Ok(Self {
            subnets: vec![
                Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 8).map_err(|_| invalid())?,
                Ipv4Net::new(Ipv4Addr::new(172, 16, 0, 0), 12).map_err(|_| invalid())?,
                Ipv4Net::new(Ipv4Addr::new(192, 168, 0, 0), 16).map_err(|_| invalid())?,
            ],
            private_bypass: true,
            ..Default::default()
        })
    }

    pub fn private_bypass(&self) -> bool {
        self.private_bypass
    }

    pub fn source_conflicts(&self, policy: &nm_tunnel_profile::SourcePolicy) -> bool {
        let Ok(tun) = Ipv4Net::new(policy.tun_address(), policy.tun_prefix()) else {
            return true;
        };
        self.connected.iter().any(|net| {
            net.contains(&policy.tun_address())
                || tun.contains(&net.network())
                || net.contains(&Ipv4Addr::new(198, 18, 0, 0))
                || net.contains(&Ipv4Addr::new(198, 19, 255, 255))
                || policy.synthetic(net.network())
                || policy.synthetic(net.broadcast())
        })
    }

    /// DNS interception needs LAN traffic inside TUN too. Reject point-to-point
    /// prefixes here: split more-specific routes and unicast host bounds would
    /// otherwise not have the semantics of this connected-subnet mode.
    pub fn with_interception(mut self, enabled: bool) -> io::Result<Self> {
        if self.private_bypass {
            return Ok(self);
        }
        if enabled && self.connected.iter().any(|net| net.prefix_len() > 30) {
            return Err(invalid());
        }
        self.brokered = enabled && self.enabled();
        Ok(self)
    }

    pub fn worker_addresses(&self) -> Vec<(Ipv4Addr, u8)> {
        if !self.brokered {
            return Vec::new();
        }
        self.connected
            .iter()
            .map(|net| (net.network(), net.prefix_len()))
            .collect()
    }

    pub fn from_worker(
        profile: &nm_tunnel_profile::Profile,
        addresses: &[(Ipv4Addr, u8)],
    ) -> io::Result<Self> {
        if profile.lan_bypass() == nm_tunnel_profile::LanBypass::Private && addresses.is_empty() {
            Self::private()
        } else if profile.network().source().is_some() {
            Self::capture(addresses)
        } else if profile.lan_bypass() == nm_tunnel_profile::LanBypass::Connected
            && profile.network().intercepts_dns()
        {
            Self::connected(addresses)?.with_interception(true)
        } else if addresses.is_empty() {
            Ok(Self::default())
        } else {
            Err(invalid())
        }
    }

    /// Shared eligibility check, but not shared authority: the supervisor owns
    /// its independent NM-derived snapshot, never a worker-provided prefix list.
    /// DNS cannot obtain a raw LAN socket, even from a compromised worker.
    pub fn authorizes(&self, destination: std::net::SocketAddr) -> bool {
        let std::net::IpAddr::V4(ip) = destination.ip() else {
            return false;
        };
        !self.source_capture
            && self.is_local(destination)
            && !matches!(destination.port(), 0 | 53)
            && !self
                .connected
                .iter()
                .any(|net| ip == net.network() || ip == net.broadcast())
    }

    /// Recognize local destinations separately from permission, so a rejected
    /// local broadcast/DNS flow cannot fall through to a different outbound.
    pub fn is_local(&self, destination: std::net::SocketAddr) -> bool {
        let std::net::IpAddr::V4(ip) = destination.ip() else {
            return false;
        };
        (self.brokered || self.private_bypass) && self.subnets.iter().any(|net| net.contains(&ip))
    }

    pub fn enabled(&self) -> bool {
        self.source_capture || !self.subnets.is_empty()
    }

    /// Bounded VPN routes: a disjoint LAN complement normally, or a full IPv4
    /// cover with more-specific connected-LAN halves when interception is enabled.
    /// No /0: full coverage uses two /1s so physical default metrics cannot win.
    /// Protected/FakeIP destinations must never escape via physical default.
    /// NM routes are destination/prefix/next-hop/metric; addresses use network byte order.
    pub fn routes(&self) -> Vec<Vec<u32>> {
        let mut routes = Vec::new();
        if self.brokered {
            // Two /1s instead of a default, plus more-specific LAN halves to
            // beat the physical connected routes. NM installs every route.
            for net in Ipv4Subnets::new(Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST, 1) {
                append_route(&mut routes, net);
            }
            for net in &self.connected {
                for half in Ipv4Subnets::new(net.network(), net.broadcast(), net.prefix_len() + 1) {
                    append_route(&mut routes, half);
                }
            }
            routes.sort_unstable();
            routes.dedup();
            return routes;
        }
        let mut start = 0_u64;
        for net in &self.subnets {
            let end = u32::from(net.network()) as u64;
            if start < end {
                append(&mut routes, start as u32, (end - 1) as u32);
            }
            start = u32::from(net.broadcast()) as u64 + 1;
        }
        if start <= u32::MAX as u64 {
            append(&mut routes, start as u32, u32::MAX);
        }
        routes
    }

    /// The interface has already been checked against NM's Linux-name bounds.
    /// Recheck here before interpolating into an nft program, even for internal callers.
    pub fn guard_rule(&self, interface: &str) -> io::Result<String> {
        if !valid_interface(interface) {
            return Err(invalid());
        }
        if !self.enabled() || self.brokered {
            return Ok(String::new());
        }
        let networks = self
            .subnets
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        if self.private_bypass {
            Ok(format!("  ip daddr {{ {networks} }} accept\n"))
        } else {
            Ok(format!(
                "  oifname \"{interface}\" ip daddr {{ {networks} }} accept\n"
            ))
        }
    }
}

pub(crate) fn valid_interface(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.:".contains(&b))
        && !matches!(value, "lo" | "nmtun0")
}

fn append(routes: &mut Vec<Vec<u32>>, start: u32, end: u32) {
    for net in Ipv4Subnets::new(start.into(), end.into(), 1) {
        append_route(routes, net);
    }
}

fn append_route(routes: &mut Vec<Vec<u32>>, net: Ipv4Net) {
    routes.push(vec![
        u32::from_ne_bytes(net.network().octets()),
        u32::from(net.prefix_len()),
        0,
        0,
    ]);
}

fn invalid() -> io::Error {
    io::Error::other("No safe connected RFC1918 LAN bypass plan.")
}

impl nm_tunnel_dataplane::LanScope for Plan {
    fn is_local(&self, destination: std::net::SocketAddr) -> bool {
        self.is_local(destination)
    }
    fn authorizes(&self, destination: std::net::SocketAddr) -> bool {
        self.authorizes(destination)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_capture_beats_any_physical_default_without_granting_direct_authority()
    -> io::Result<()> {
        let plan = Plan::default();
        assert_eq!(
            plan.routes(),
            vec![
                vec![u32::from_ne_bytes([0, 0, 0, 0]), 1, 0, 0],
                vec![u32::from_ne_bytes([128, 0, 0, 0]), 1, 0, 0],
            ]
        );
        assert!(!plan.enabled(), "route capture does not enable LAN bypass");
        assert!(plan.guard_rule("enp1s0")?.is_empty());
        for destination in ["1.1.1.1:53", "198.51.100.10:443", "192.168.1.1:80"] {
            assert!(!plan.authorizes(destination.parse().map_err(io::Error::other)?));
        }
        Ok(())
    }

    #[test]
    fn private_mode_excludes_rfc1918_routes_and_scopes_non_dns_root_authority() -> io::Result<()> {
        let plan = Plan::private()?.with_interception(true)?;
        let routes = plan.routes();
        for text in [
            "10.2.2.1",
            "10.255.255.254",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.68.1",
        ] {
            let address: Ipv4Addr = text.parse().map_err(io::Error::other)?;
            assert!(!routes.iter().any(|r| {
                Ipv4Net::new(Ipv4Addr::from(r[0].to_ne_bytes()), r[1] as u8)
                    .is_ok_and(|net| net.contains(&address))
            }));
            assert!(plan.authorizes(std::net::SocketAddr::from((address, 80))));
            assert!(!plan.authorizes(std::net::SocketAddr::from((address, 53))));
        }
        for text in [
            "1.1.1.1",
            "100.64.0.1",
            "169.254.0.1",
            "198.18.0.2",
            "198.19.0.2",
            "172.32.0.1",
        ] {
            let address: Ipv4Addr = text.parse().map_err(io::Error::other)?;
            assert!(routes.iter().any(|r| {
                Ipv4Net::new(Ipv4Addr::from(r[0].to_ne_bytes()), r[1] as u8)
                    .is_ok_and(|net| net.contains(&address))
            }));
        }
        assert!(plan.worker_addresses().is_empty());
        assert!(!plan.guard_rule("enp1s0")?.contains("oifname"));
        assert!(plan.guard_rule("invalid;rule").is_err());
        assert_eq!(plan.routes(), routes);
        Ok(())
    }

    #[test]
    fn source_capture_routes_never_become_direct_authority_and_reject_unoverridable_prefixes()
    -> io::Result<()> {
        let captured = Plan::capture(&[
            (Ipv4Addr::new(192, 168, 1, 5), 24),
            (Ipv4Addr::new(10, 0, 0, 0), 8),
            (Ipv4Addr::new(203, 0, 113, 0), 24),
        ])?;
        assert!(captured.enabled());
        assert!(captured.guard_rule("enp1s0")?.is_empty());
        assert_eq!(captured.routes().len(), 8);
        for destination in ["192.168.1.1:80", "10.1.2.3:80", "203.0.113.1:80"] {
            assert!(!captured.authorizes(destination.parse().map_err(io::Error::other)?));
        }
        for prefix in [0, 31, 32] {
            assert!(Plan::capture(&[(Ipv4Addr::new(10, 0, 0, 1), prefix)]).is_err());
        }
        let profile = crate::test_support::source_profile()?;
        let policy = profile.network().source().ok_or_else(invalid)?;
        assert!(!captured.source_conflicts(policy));
        assert!(Plan::capture(&[(Ipv4Addr::new(172, 19, 0, 3), 30)])?.source_conflicts(policy));
        assert!(Plan::capture(&[(Ipv4Addr::new(198, 19, 0, 0), 16)])?.source_conflicts(policy));
        assert!(Plan::capture(&[(Ipv4Addr::new(198, 0, 0, 0), 8)])?.source_conflicts(policy));
        assert_eq!(captured.routes().len(), 8);
        Ok(())
    }

    #[test]
    fn interception_keeps_lan_in_tun_without_a_physical_guard_exception() -> io::Result<()> {
        let plain = Plan::connected(&[(Ipv4Addr::new(192, 168, 1, 2), 24)])?;
        let combined = plain.clone().with_interception(true)?;
        assert!(combined.guard_rule("enp1s0")?.is_empty());
        assert!(!plain.guard_rule("enp1s0")?.is_empty());
        let routes = combined.routes();
        assert_eq!(routes.len(), 4);
        let prefixes: Vec<_> = routes
            .iter()
            .map(|route| Ipv4Net::new(Ipv4Addr::from(route[0].to_ne_bytes()), route[1] as u8))
            .collect::<Result<_, _>>()
            .map_err(io::Error::other)?;
        let local: Ipv4Addr = "192.168.1.1".parse().map_err(io::Error::other)?;
        assert_eq!(
            prefixes
                .iter()
                .filter(|net| net.contains(&local))
                .map(Ipv4Net::prefix_len)
                .max(),
            Some(25)
        );
        for destination in ["192.168.1.1:80", "192.168.1.254:123"] {
            assert!(combined.authorizes(destination.parse().map_err(io::Error::other)?));
            assert!(!plain.authorizes(destination.parse().map_err(io::Error::other)?));
        }
        for destination in [
            "192.168.1.1:53",
            "192.168.1.1:0",
            "192.168.1.0:80",
            "192.168.1.255:80",
            "192.168.2.1:80",
            "1.1.1.1:443",
            "198.18.0.2:80",
            "[fd00::1]:80",
        ] {
            assert!(!combined.authorizes(destination.parse().map_err(io::Error::other)?));
        }
        for prefix in [31, 32] {
            assert!(
                Plan::connected(&[(Ipv4Addr::new(10, 1, 1, 1), prefix)])?
                    .with_interception(true)
                    .is_err()
            );
        }
        let adjacent = Plan::connected(&[
            (Ipv4Addr::new(192, 168, 1, 1), 30),
            (Ipv4Addr::new(192, 168, 1, 5), 30),
        ])?
        .with_interception(true)?;
        for address in ["192.168.1.3:80", "192.168.1.4:80"] {
            assert!(
                !adjacent.authorizes(address.parse().map_err(io::Error::other)?),
                "aggregation cannot turn an original subnet boundary into authorized unicast"
            );
        }
        let overlap = Plan::connected(&[
            (Ipv4Addr::new(192, 168, 1, 2), 24),
            (Ipv4Addr::new(192, 168, 1, 3), 28),
        ])?
        .with_interception(true)?;
        assert!(
            overlap.routes().iter().any(|route| route[1] == 29),
            "must capture the original more-specific connected prefix too"
        );
        Ok(())
    }

    #[test]
    fn worker_snapshot_requires_the_combined_mode_and_does_not_mutate_the_supervisor_plan()
    -> io::Result<()> {
        let mut draft = nm_tunnel_profile::import_vless("vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example").map_err(io::Error::other)?;
        let addresses = [(Ipv4Addr::new(192, 168, 1, 2), 24)];
        let plan = Plan::connected(&addresses)?.with_interception(true)?;
        let before = plan.routes();
        let profile = draft.validate().map_err(|_| invalid())?;
        assert!(Plan::from_worker(&profile, &addresses).is_err());
        draft.lan_bypass = true;
        draft.dns_interception = true;
        let profile = draft.validate().map_err(|_| invalid())?;
        assert!(Plan::from_worker(&profile, &[]).is_err());
        assert!(Plan::from_worker(&profile, &[(Ipv4Addr::new(1, 1, 1, 1), 0)]).is_err());
        let worker = Plan::from_worker(&profile, &plan.worker_addresses())?;
        assert_eq!(worker.routes(), before);
        assert_eq!(plan.routes(), before);
        Ok(())
    }

    #[test]
    fn routes_and_guard_share_only_connected_private_authority() -> io::Result<()> {
        let plan = Plan::connected(&[
            (Ipv4Addr::new(192, 168, 1, 12), 24),
            (Ipv4Addr::new(10, 3, 1, 4), 16),
        ])?;
        let routes = plan.routes();
        let routed: Vec<_> = routes
            .iter()
            .map(|r| Ipv4Net::new(Ipv4Addr::from(r[0].to_ne_bytes()), r[1] as u8))
            .collect::<Result<_, _>>()
            .map_err(io::Error::other)?;
        let total: u64 = routed.iter().map(|r| 1_u64 << (32 - r.prefix_len())).sum();
        assert_eq!(total, (1_u64 << 32) - 256 - 65536);
        for pair in routed.windows(2) {
            assert!(
                pair[0].broadcast() < pair[1].network(),
                "VPN routes must be disjoint and ordered"
            );
        }
        let duplicate = Plan::connected(&[
            (Ipv4Addr::new(192, 168, 1, 12), 24),
            (Ipv4Addr::new(192, 168, 1, 13), 25),
            (Ipv4Addr::new(10, 3, 1, 4), 16),
            (Ipv4Addr::new(1, 1, 1, 1), 24),
        ])?;
        assert_eq!(
            duplicate.routes(),
            routes,
            "extra public addresses cannot widen authority"
        );
        for (text, vpn) in [
            ("192.168.1.0", false),
            ("192.168.1.255", false),
            ("192.168.2.1", true),
            ("10.3.0.0", false),
            ("10.4.1.1", true),
            ("1.1.1.1", true),
            ("198.18.0.2", true),
            ("100.64.0.1", true),
            ("169.254.1.1", true),
        ] {
            let address: Ipv4Addr = text.parse().map_err(io::Error::other)?;
            assert_eq!(routed.iter().any(|r| r.contains(&address)), vpn);
        }
        let rule = plan.guard_rule("enp1s0")?;
        assert_eq!(
            rule,
            "  oifname \"enp1s0\" ip daddr { 10.3.0.0/16, 192.168.1.0/24 } accept\n"
        );
        assert!(!Plan::default().enabled());
        assert!(Plan::default().guard_rule("enp1s0")?.is_empty());
        for interface in ["", "lo", "nmtun0", "eth0\" accept", "eth0\n"] {
            assert!(plan.guard_rule(interface).is_err());
        }
        Ok(())
    }

    #[test]
    fn malformed_or_broad_prefixes_reject_without_changing_an_existing_plan() -> io::Result<()> {
        let plan = Plan::connected(&[(Ipv4Addr::new(192, 168, 1, 1), 24)])?;
        let before = plan.routes();
        for addresses in [
            vec![],
            vec![(Ipv4Addr::new(1, 1, 1, 1), 24)],
            vec![(Ipv4Addr::new(10, 1, 1, 1), 0)],
            vec![(Ipv4Addr::new(192, 168, 1, 1), 15)],
            vec![(Ipv4Addr::new(10, 1, 1, 1), 33)],
            vec![(Ipv4Addr::new(10, 1, 1, 1), 24); 17],
        ] {
            assert!(Plan::connected(&addresses).is_err());
            assert_eq!(plan.routes(), before);
        }
        Ok(())
    }
}
