//! Desktop-independent VLESS profile validation and strict share-link import.
mod connection;
mod dns;
mod import;
mod network;
mod policy;
mod profile;
mod route_policy;
mod source_dns_policy;
mod source_policy;
mod validation;

pub use connection::{Endpoint, PeerSecurity, RealitySettings, UdpMode, VlessSettings};
pub use dns::{DnsOverride, DnsOverrideError};
pub use import::import_vless;
pub use network::{DnsHandling, LanBypass, NetworkPolicy, RoutingPolicy};
pub use policy::{DomainAction, MAX_POLICY_BYTES, PolicyError, TcpDomainPolicy, canonical_domain};
pub use profile::{Credential, Profile};
pub use route_policy::RoutePolicy;
use secrecy::SecretString;
pub use source_dns_policy::SourceDnsSelection;
pub use source_policy::{DnsTransport, SourceDns, SourcePolicy, non_public_ipv4};
pub use validation::{Field, ValidationError};

/// Experimental local service identity, shared by the editor and NM backend.
/// See `crates/nm-service/README.md` for the service contract; production admission is pending.
pub const SERVICE_TYPE: &str = "org.freedesktop.NetworkManager.tunnel";

/// Transport security; unencrypted and insecure-certificate modes are not supported.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Security {
    /// Certificate-verified TLS.
    Tls,
    /// REALITY peer authentication.
    #[default]
    Reality,
}

/// Stream transport and its explicit wire settings. Debug redacts route/header values.
#[derive(Clone, Default, PartialEq, Eq)]
pub enum Transport {
    /// Direct TCP stream; compatible with TLS/REALITY and optional Vision.
    #[default]
    Tcp,
    /// WebSocket over certificate-verified TLS, without Vision.
    WebSocket {
        /// HTTP request path and optional query, starting with '/'.
        path: String,
        /// Optional HTTP Host override, separate from the TLS SNI.
        host: Option<String>,
    },
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Tcp => "Tcp",
            Self::WebSocket { .. } => "WebSocket([redacted])",
        })
    }
}

/// Editable input. Credentials are redacted from Debug output.
/// Strings remain untrusted until [`Draft::validate`] succeeds.
#[derive(Clone)]
pub struct Draft {
    /// Human-readable connection name.
    pub name: String,
    /// ASCII server hostname or IP literal, without a port or URL scheme.
    /// IDNs must use ASCII punycode; percent-encoded hostnames are rejected.
    pub server: String,
    /// Decimal server port.
    pub port: String,
    /// VLESS authentication UUID, never ordinary NM vpn.data.
    pub credential: SecretString,
    /// TLS or REALITY.
    pub security: Security,
    /// TCP or WebSocket, never inferred by discarding unrecognized link parameters.
    pub transport: Transport,
    /// ASCII TLS server hostname, required even when connecting to an IP.
    /// IDNs must use ASCII punycode; percent-encoded names are rejected.
    pub server_name: String,
    /// Browser fingerprint label applied by the experimental engine.
    /// Exact browser fidelity is not established; REALITY Android is unsupported.
    pub fingerprint: String,
    /// REALITY server public key, base64url without padding.
    pub public_key: String,
    /// REALITY short ID, zero to eight bytes encoded as even-length hex.
    pub short_id: String,
    /// Enable xtls-rprx-vision over the supported TCP transport.
    pub vision: bool,
    /// Optional comma-separated ALPN values; WebSocket cannot offer h2.
    pub alpn: String,
    /// Optional ordered HTTP Host/TLS SNI rules. Uses NM schema v2; legacy profiles
    /// without this field retain schema v1 and their existing full-tunnel behavior.
    /// Explicit FakeIP mode additionally applies these actions to owned TCP/UDP names.
    pub tcp_domain_policy: Option<TcpDomainPolicy>,
    /// Per-profile resolver override. Does not remove or disable routing rules.
    pub dns_override: DnsOverride,
    /// Bypass only connected RFC1918 IPv4 subnets of the selected NM uplink.
    /// Not equivalent to a source rule matching every non-public address.
    /// IPv6 remains blocked; NM owns routes and the guard restricts the uplink.
    /// With DNS interception, local TCP/UDP is relayed after DNS handling; other
    /// local IP protocols are unsupported in that combined mode.
    pub lan_bypass: bool,
    /// Explicit all-RFC1918 physical bypass, including routed private networks.
    /// Mutually exclusive with connected-only bypass and complete source policy.
    /// DNS interception, when enabled, remains before this physical exception.
    pub private_lan_bypass: bool,
    /// Intercept IPv4 UDP/TCP port 53 reaching TUN and use the selected resolver.
    /// Default-off; not DoH/DoT, IPv6, FakeIP or protocol sniffing on other ports.
    /// With LAN bypass, DNS is handled first and local TCP/UDP uses bounded broker
    /// sockets; other LAN IP protocols are not forwarded in that combined mode.
    pub dns_interception: bool,
    /// Experimental persistent IPv4 FakeIP ownership in 198.18.0.0/16.
    /// Requires DNS interception. IPv6 remains blocked and AAAA answers are empty;
    /// this is not admission of source policies requiring IPv6 FakeIP.
    pub fake_ip: bool,
    /// Checked complete IPv4 source policy. Requires interception and persistent
    /// FakeIP; cannot be combined with competing legacy hostname/LAN policies.
    pub source_policy: Option<SourcePolicy>,
}

impl std::fmt::Debug for Draft {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Draft([redacted])")
    }
}

impl Default for Draft {
    fn default() -> Self {
        Self {
            name: String::new(),
            server: String::new(),
            port: "443".into(),
            credential: SecretString::from(String::new()),
            security: Security::Reality,
            transport: Transport::Tcp,
            server_name: String::new(),
            fingerprint: "chrome".into(),
            public_key: String::new(),
            short_id: String::new(),
            vision: true,
            alpn: String::new(),
            tcp_domain_policy: None,
            dns_override: DnsOverride::Inherit,
            lan_bypass: false,
            private_lan_bypass: false,
            dns_interception: false,
            fake_ip: false,
            source_policy: None,
        }
    }
}
