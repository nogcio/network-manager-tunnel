//! Desktop-independent VLESS profile validation and strict share-link import.
mod import;
mod validation;

pub use import::import_vless;
use secrecy::SecretString;
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
        }
    }
}

/// A checked snapshot. Construction is restricted to validation/import.
#[derive(Clone, Debug)]
pub struct Profile(Draft);

impl Profile {
    /// Borrow validated fields. Mutations require a new draft and validation.
    pub fn fields(&self) -> &Draft {
        &self.0
    }
}
