//! One owner for version admission and non-secret network-policy metadata.
pub use nm_tunnel_profile::LanBypass;
use nm_tunnel_profile::{DnsOverride, Draft, NetworkPolicy, SourcePolicy, TcpDomainPolicy};
/// Read supported schema-v1/v2 policy without secrets or I/O.
/// Unknown modes and contradictory combinations reject without source mutation.
pub fn decode_policy(data: &crate::Strings) -> Result<NetworkPolicy, &'static str> {
    let extended = [
        "tcp-domain-policy",
        "dns-override",
        "lan-bypass",
        "dns-interception",
        "dns-fakeip",
        "source-policy",
    ]
    .iter()
    .any(|key| data.contains_key(*key));
    if !matches!(
        (data.get("schema-version").map(String::as_str), extended),
        (Some("1"), false) | (Some("2"), true)
    ) {
        return Err("Unsupported schema or policy version.");
    }
    let lan = match data.get("lan-bypass").map(String::as_str) {
        None => LanBypass::None,
        Some("connected-rfc1918") => LanBypass::Connected,
        Some("private-rfc1918") => LanBypass::Private,
        _ => return Err("Unsupported LAN bypass policy."),
    };
    let draft = Draft {
        tcp_domain_policy: data
            .get("tcp-domain-policy")
            .map(|text| TcpDomainPolicy::from_json(text))
            .transpose()
            .map_err(|_| "Unsupported TCP domain policy.")?,
        dns_override: data
            .get("dns-override")
            .map(|text| DnsOverride::from_nm(text))
            .transpose()
            .map_err(|_| "Unsupported DNS override.")?
            .unwrap_or_default(),
        lan_bypass: lan == LanBypass::Connected,
        private_lan_bypass: lan == LanBypass::Private,
        dns_interception: match data.get("dns-interception").map(String::as_str) {
            None => false,
            Some("tun-port53") => true,
            _ => return Err("Unsupported DNS interception policy."),
        },
        fake_ip: match data.get("dns-fakeip").map(String::as_str) {
            None => false,
            Some("persistent-ipv4-v1") => true,
            _ => return Err("Unsupported FakeIP policy."),
        },
        source_policy: data
            .get("source-policy")
            .map(|text| SourcePolicy::from_json(text))
            .transpose()
            .map_err(|_| "Unsupported complete IPv4 policy.")?,
        ..Draft::default()
    };
    NetworkPolicy::from_draft(&draft).map_err(|_| "Incompatible network policies.")
}
