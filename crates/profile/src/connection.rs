//! Typed node settings. No NM schema, resolver policy or credential storage lives here.
use std::num::NonZeroU16;

/// Checked endpoint identity. Hostname spelling is preserved; resolution is host-owned.
#[derive(Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub(crate) host: String,
    pub(crate) ipv4: Option<std::net::Ipv4Addr>,
    pub(crate) port: NonZeroU16,
}

impl Endpoint {
    /// ASCII hostname or concrete IPv4 literal, never a URL.
    pub fn host(&self) -> &str {
        &self.host
    }
    /// Validated nonzero service port, without runtime parsing.
    pub fn port(&self) -> u16 {
        self.port.get()
    }
    /// Parsed literal, if the configured identity is an IPv4 address rather than a hostname.
    /// Hostname resolution and approval of its returned address remain host-owned.
    pub fn ipv4(&self) -> Option<std::net::Ipv4Addr> {
        self.ipv4
    }
}

/// Decoded REALITY identity. The library owns authentication and cryptography.
#[derive(Clone, PartialEq, Eq)]
pub struct RealitySettings {
    pub(crate) public_key: [u8; 32],
    pub(crate) short_id: Vec<u8>,
}

impl RealitySettings {
    /// Validated nonzero 32-byte public key.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
    /// Zero to eight decoded bytes. The protocol adapter applies library padding.
    pub fn short_id(&self) -> &[u8] {
        &self.short_id
    }
}

/// Mutually exclusive peer authentication modes; TLS never contains REALITY fields.
#[derive(Clone, PartialEq, Eq)]
pub enum PeerSecurity {
    /// Mandatory certificate verification.
    Tls,
    /// REALITY peer identity.
    Reality(RealitySettings),
}

/// Required VLESS datagram framing, compiled from the admitted policy contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdpMode {
    /// Legacy destination-bound UDP-over-TCP.
    Bound,
    /// CommandMux/Mux.Cool XUDP; no bound-UDP fallback.
    Xudp,
}

/// Immutable, validated VLESS node configuration, independent of network policy.
#[derive(Clone, PartialEq, Eq)]
pub struct VlessSettings {
    pub(crate) endpoint: Endpoint,
    pub(crate) transport: crate::Transport,
    pub(crate) security: PeerSecurity,
    pub(crate) server_name: String,
    pub(crate) fingerprint: String,
    pub(crate) vision: bool,
    pub(crate) alpn: Vec<String>,
    pub(crate) udp_mode: UdpMode,
}

impl VlessSettings {
    /// Host-approved endpoint identity; this creates no socket or resolver.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
    /// Checked TCP or WebSocket settings.
    pub fn transport(&self) -> &crate::Transport {
        &self.transport
    }
    /// Checked peer authentication, with decoded REALITY material when selected.
    pub fn security(&self) -> &PeerSecurity {
        &self.security
    }
    /// TLS verification/SNI identity, separate from HTTP Host and endpoint host.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }
    /// Explicit validated fingerprint label; adapter capability checks still apply.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    /// Whether Vision is required on the supported TCP transport.
    pub fn vision(&self) -> bool {
        self.vision
    }
    /// Ordered ALPN offers, parsed once at the input boundary.
    pub fn alpn(&self) -> &[String] {
        &self.alpn
    }
    /// Required datagram framing, not inferred from a subscription at flow setup.
    pub fn udp_mode(&self) -> UdpMode {
        self.udp_mode
    }
}

macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => { $(
        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($ty), "([redacted])"))
            }
        }
    )+ };
}
redacted_debug!(Endpoint, RealitySettings, PeerSecurity, VlessSettings);
