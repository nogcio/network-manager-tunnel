//! Per-profile resolver selection, independent of imported transport credentials.
use std::net::Ipv4Addr;

/// Explicit profile override. Inherit preserves the imported/default policy;
/// current URI-only profiles have the documented legacy VPN DNS default.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum DnsOverride {
    /// No override of an admitted source/default resolver policy.
    #[default]
    Inherit,
    /// Resolve using the selected NM uplink's DNS, reread on every activation.
    /// The actual server address is never persisted in the profile. This permits
    /// plaintext DNS outside the VPN on bounded supervisor-created sockets.
    CurrentNetwork,
    /// Use this public IPv4 resolver through the VPN, without direct fallback.
    ProxyIpv4(Ipv4Addr),
}

impl std::fmt::Debug for DnsOverride {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Inherit => "DnsOverride::Inherit",
            Self::CurrentNetwork => "DnsOverride::CurrentNetwork",
            Self::ProxyIpv4(_) => "DnsOverride::ProxyIpv4([redacted])",
        })
    }
}

/// Sanitized DNS override error, never containing untrusted text or addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DnsOverrideError {
    /// The requested resolver cannot be represented safely by the current mode.
    #[error("Choose the current network DNS or a public IPv4 DNS server through the VPN.")]
    InvalidResolver,
    /// Reject incompatible DNS/routing combinations instead of dropping policy
    /// or allowing verification/interception bypass through another resolver.
    #[error(
        "This DNS override is incompatible with the routing policy. Direct hostname rules cannot yet use a manual through-VPN resolver; choose current network DNS instead."
    )]
    IncompatiblePolicy,
}

impl DnsOverride {
    /// Decode the bounded NM representation. Absence of this field means Inherit;
    /// unknown modes, IPv6, LAN/loopback/non-unicast proxy resolvers are rejected.
    /// No lookup, fallback or state/resource mutation occurs on rejection.
    pub fn from_nm(value: &str) -> Result<Self, DnsOverrideError> {
        if value == "current-network" {
            return Ok(Self::CurrentNetwork);
        }
        let ip = value
            .strip_prefix("proxy-ipv4:")
            .ok_or(DnsOverrideError::InvalidResolver)?
            .parse::<Ipv4Addr>()
            .map_err(|_| DnsOverrideError::InvalidResolver)?;
        let policy = Self::ProxyIpv4(ip);
        policy.validate()?;
        Ok(policy)
    }

    /// Canonical non-secret NM value; no current DHCP resolver is stored here.
    pub fn to_nm(self) -> Option<String> {
        match self {
            Self::Inherit => None,
            Self::CurrentNetwork => Some("current-network".into()),
            Self::ProxyIpv4(ip) => Some(format!("proxy-ipv4:{ip}")),
        }
    }

    /// Validate before profile encoding or privileged admission. A manual resolver
    /// goes through TUN; protected/local addresses need CurrentNetwork instead.
    pub fn validate(self) -> Result<(), DnsOverrideError> {
        if let Self::ProxyIpv4(ip) = self {
            let [a, b, _, _] = ip.octets();
            if ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || a == 0
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 198 && matches!(b, 18 | 19))
            {
                return Err(DnsOverrideError::InvalidResolver);
            }
        }
        Ok(())
    }
}
