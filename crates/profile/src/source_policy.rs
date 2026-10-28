//! Checked native IPv4 policy, not storage of a foreign client configuration.
use crate::{DomainAction, PolicyError, TcpDomainPolicy, canonical_domain};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};

/// Transport for the single selected real DNS upstream. No implicit fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsTransport {
    /// Plain DNS over UDP.
    Udp,
    /// Length-framed plain DNS over TCP.
    Tcp,
    /// Length-framed DNS over certificate-verified TLS.
    Tls,
    /// RFC 8484 POST over certificate-verified HTTPS, without redirects/fallback.
    Https,
}

/// One checked source DNS endpoint. Debug is redacted; names can identify a source.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDns {
    /// Explicit IPv4 address, not an implicit system lookup.
    pub address: Ipv4Addr,
    /// Optional ASCII resolver hostname, bootstrapped using the NM uplink. When
    /// present, `address` must be unspecified; resolved addresses are never saved.
    #[serde(default)]
    pub host: Option<String>,
    /// Explicit service port.
    pub port: u16,
    /// Wire transport, independent of the application's query transport.
    pub transport: DnsTransport,
    /// Whether this DNS connection travels through the selected VLESS node.
    pub via_proxy: bool,
    /// TLS verification identity; empty for plain DNS, never verification-disabled.
    pub tls_name: String,
    /// Bounded origin-form DoH path, without query tokens; empty on other transports.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub http_path: String,
}

impl std::fmt::Debug for SourceDns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SourceDns([redacted])")
    }
}

impl SourceDns {
    /// Validate and canonicalize one DNS endpoint without I/O. Used by profile
    /// admission and by the importer for every declared real DNS server, including
    /// unselected ones. Addresses, TLS identities and paths never appear in errors.
    /// No resolver lookup, route permission or fallback is implied by success.
    ///
    /// # Errors
    /// Returns [`PolicyError`] for unsupported addresses, contradictory host/IP,
    /// zero ports, invalid TLS identity or nonrepresentable HTTP paths/options.
    pub fn validated(mut self) -> Result<Self, PolicyError> {
        if self.port == 0
            || (self.host.is_none()
                && crate::DnsOverride::ProxyIpv4(self.address)
                    .validate()
                    .is_err())
        {
            return Err(PolicyError);
        }
        if let Some(host) = &mut self.host {
            if !self.address.is_unspecified() {
                return Err(PolicyError);
            }
            *host = canonical_domain(host).ok_or(PolicyError)?;
        }
        if matches!(self.transport, DnsTransport::Tls | DnsTransport::Https) {
            if let Some(name) = canonical_domain(&self.tls_name) {
                self.tls_name = name;
            } else if self.host.is_some()
                || self.tls_name.parse::<Ipv4Addr>().ok() != Some(self.address)
            {
                return Err(PolicyError);
            }
        } else if !self.tls_name.is_empty() {
            return Err(PolicyError);
        }
        if self.transport == DnsTransport::Https {
            if self.http_path.is_empty() {
                self.http_path = "/dns-query".into();
            }
            let path = &self.http_path;
            if path.len() > 1024
                || !path.starts_with('/')
                || path.starts_with("//")
                || !path
                    .bytes()
                    .all(|b| b.is_ascii_graphic() && !matches!(b, b'?' | b'#' | b'\\'))
                || path.parse::<http::uri::PathAndQuery>().is_err()
            {
                return Err(PolicyError);
            }
        } else if !self.http_path.is_empty() {
            return Err(PolicyError);
        }
        Ok(self)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    dns: SourceDns,
    domain_policy: String,
    fakeip_range: String,
    tun_address: Ipv4Addr,
    tun_prefix: u8,
    mtu: u16,
}

/// Native source-policy v1: sniff, DNS hijack, BitTorrent block, ordered domain
/// actions, non-public IPv4 Direct, otherwise the selected proxy. Only that exact
/// ordering is admitted. DNS caches are independent of bootstrap and FakeIP state.
/// Parsing has no I/O; errors/Debug never contain supplied settings or DNS names.
#[derive(Clone)]
pub struct SourcePolicy {
    document: Document,
    domains: TcpDomainPolicy,
    encoded: String,
}

impl std::fmt::Debug for SourcePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SourcePolicy([redacted])")
    }
}

impl SourcePolicy {
    /// Decode the bounded native v1 contract atomically. Unknown fields, pools,
    /// versions, resolver settings and invalid tunnel configuration reject.
    pub fn from_json(text: &str) -> Result<Self, PolicyError> {
        if text.len() > crate::MAX_POLICY_BYTES {
            return Err(PolicyError);
        }
        let mut document: Document = serde_json::from_str(text).map_err(|_| PolicyError)?;
        if document.version != 1
            || !matches!(
                document.fakeip_range.as_str(),
                "198.18.0.0/16" | "198.18.0.0/15"
            )
            || !document.tun_address.is_private()
            || !(1..=30).contains(&document.tun_prefix)
            || !(1280..=9000).contains(&document.mtu)
        {
            return Err(PolicyError);
        }
        document.dns = document.dns.validated()?;
        let mask = u32::MAX << (32 - document.tun_prefix);
        let network = u32::from(document.tun_address) & mask;
        let broadcast = network | !mask;
        if !Ipv4Addr::from(network).is_private()
            || !Ipv4Addr::from(broadcast).is_private()
            || matches!(u32::from(document.tun_address), ip if ip == network || ip == broadcast)
        {
            return Err(PolicyError);
        }
        let domains = TcpDomainPolicy::from_json(&document.domain_policy)?;
        document.domain_policy = domains.as_json().into();
        let encoded = serde_json::to_string(&document).map_err(|_| PolicyError)?;
        if encoded.len() > crate::MAX_POLICY_BYTES {
            return Err(PolicyError);
        }
        Ok(Self {
            document,
            domains,
            encoded,
        })
    }
    /// Canonical NM representation. Contains identifying names; never log it.
    pub fn as_json(&self) -> &str {
        &self.encoded
    }
    /// Checked real DNS endpoint; user overrides are applied independently.
    pub fn dns(&self) -> &SourceDns {
        &self.document.dns
    }
    /// Match an explicit domain action without confusing it with the default.
    pub fn domain_action(&self, name: Option<&str>) -> Option<DomainAction> {
        self.domains.matched_action(name)
    }
    /// Apply terminal rules after DNS hijacking. Known BitTorrent is blocked
    /// before all domain/IP decisions; domain actions precede non-public matching.
    pub fn action(
        &self,
        name: Option<&str>,
        destination: SocketAddr,
        bittorrent: bool,
    ) -> DomainAction {
        if bittorrent {
            return DomainAction::Block;
        }
        if let Some(action) = self.domain_action(name) {
            return action;
        }
        if matches!(destination.ip(), std::net::IpAddr::V4(ip) if non_public_ipv4(ip)) {
            DomainAction::Direct
        } else {
            DomainAction::Proxy
        }
    }
    /// Whether an address belongs to the source's synthetic reservation. Unknown
    /// identities in the reservation must reject, never become real destinations.
    pub fn synthetic(&self, ip: Ipv4Addr) -> bool {
        let [a, b, _, _] = ip.octets();
        a == 198 && (b == 18 || (b == 19 && self.document.fakeip_range.ends_with("/15")))
    }
    /// Source's checked native tunnel IPv4 address.
    pub fn tun_address(&self) -> Ipv4Addr {
        self.document.tun_address
    }
    /// Source's checked native tunnel IPv4 prefix.
    pub fn tun_prefix(&self) -> u8 {
        self.document.tun_prefix
    }
    /// Source's checked tunnel MTU.
    pub fn mtu(&self) -> u16 {
        self.document.mtu
    }
}

/// sing-box 1.12's IPv4 `ip_is_private` semantics, not an IANA/global-address
/// classifier: RFC1918, loopback, multicast, link-local and unspecified. CGNAT,
/// benchmarking and documentation ranges are deliberately not added here.
pub fn non_public_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_multicast()
        || ip.is_link_local()
        || ip.is_unspecified()
}
