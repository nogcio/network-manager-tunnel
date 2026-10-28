//! Pure activation planning. No TUN, firewall, processes, journals or sockets are created.
use crate::{dns, lan};
use nm_tunnel_profile::{LanBypass, Profile, RoutingPolicy};
use std::{io, net::Ipv4Addr};

/// Bounded observation supplied by the NM adapter, never by a worker request.
pub(super) struct Uplink {
    pub interface: String,
    pub dns: Ipv4Addr,
    pub addresses: Vec<(Ipv4Addr, u8)>,
}

/// Immutable decisions consumed by resource setup and independent broker authority.
pub(super) struct Plan {
    pub profile: Profile,
    pub interface: String,
    pub bootstrap_dns: Ipv4Addr,
    pub advertised_dns: Ipv4Addr,
    pub lan: lan::Plan,
}

impl Plan {
    /// Reject incompatible uplinks before touching host networking or identity state.
    pub fn new(profile: Profile, uplink: Uplink) -> io::Result<Self> {
        if !lan::valid_interface(&uplink.interface) || !crate::dns::valid_uplink_server(uplink.dns)
        {
            return Err(io::Error::other("Invalid activation uplink."));
        }
        let lan = match profile.routing() {
            RoutingPolicy::Complete(_) => lan::Plan::capture(&uplink.addresses)?,
            RoutingPolicy::Legacy(_) => match profile.lan_bypass() {
                LanBypass::None => lan::Plan::default(),
                LanBypass::Connected => lan::Plan::connected(&uplink.addresses)?,
                LanBypass::Private => lan::Plan::private()?,
            },
        }
        .with_interception(profile.network().intercepts_dns())?;
        if let RoutingPolicy::Complete(policy) = profile.routing()
            && lan.source_conflicts(policy)
        {
            return Err(io::Error::other(
                "Source tunnel/FakeIP reservation conflicts with the selected uplink.",
            ));
        }
        let advertised_dns = if profile.network().fake_ip() {
            dns::INTERNAL_DNS
        } else {
            dns::profile_dns(profile.network().dns_override())
        };
        Ok(Self {
            profile,
            interface: uplink.interface,
            bootstrap_dns: uplink.dns,
            advertised_dns,
            lan,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uplink(addresses: Vec<(Ipv4Addr, u8)>) -> Uplink {
        Uplink {
            interface: "enp1s0".into(),
            dns: Ipv4Addr::new(192, 168, 1, 1),
            addresses,
        }
    }

    #[test]
    fn complete_capture_conflicts_reject_without_changing_the_profile() -> io::Result<()> {
        let profile = crate::test_support::source_profile()?;
        let before = profile
            .network()
            .source()
            .ok_or_else(|| io::Error::other("Missing policy"))?
            .as_json()
            .to_owned();
        for addresses in [
            vec![(Ipv4Addr::new(172, 19, 0, 3), 30)],
            vec![(Ipv4Addr::new(198, 19, 0, 1), 24)],
            vec![(Ipv4Addr::new(10, 0, 0, 1), 32)],
        ] {
            assert!(Plan::new(profile.clone(), uplink(addresses)).is_err());
            assert_eq!(
                profile.network().source().map(|policy| policy.as_json()),
                Some(before.as_str())
            );
        }
        let plan = Plan::new(profile, uplink(vec![(Ipv4Addr::new(192, 168, 1, 2), 24)]))?;
        assert!(plan.lan.guard_rule("enp1s0")?.is_empty());
        assert!(
            !plan
                .lan
                .authorizes("192.168.1.1:80".parse().map_err(io::Error::other)?)
        );
        assert_eq!(plan.advertised_dns, dns::INTERNAL_DNS);
        Ok(())
    }

    #[test]
    fn private_and_connected_plans_preserve_different_authority() -> io::Result<()> {
        let mut draft = nm_tunnel_profile::import_vless("vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example").map_err(io::Error::other)?;
        draft.lan_bypass = true;
        draft.dns_interception = true;
        let profile = draft
            .validate()
            .map_err(|_| io::Error::other("Invalid profile"))?;
        assert!(Plan::new(profile.clone(), uplink(vec![])).is_err());
        let connected = Plan::new(profile, uplink(vec![(Ipv4Addr::new(192, 168, 1, 2), 24)]))?;
        assert!(
            !connected
                .lan
                .authorizes("10.2.3.4:80".parse().map_err(io::Error::other)?)
        );
        draft.lan_bypass = false;
        draft.private_lan_bypass = true;
        let private = Plan::new(
            draft
                .validate()
                .map_err(|_| io::Error::other("Invalid profile"))?,
            uplink(vec![]),
        )?;
        assert!(
            private
                .lan
                .authorizes("10.2.3.4:80".parse().map_err(io::Error::other)?)
        );
        assert!(
            !private
                .lan
                .authorizes("10.2.3.4:53".parse().map_err(io::Error::other)?)
        );
        Ok(())
    }
}
