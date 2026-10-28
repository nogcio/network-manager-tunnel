//! Validation owns project-specific profile constraints, not wire-protocol parsing.
use crate::{Draft, Profile, Security, Transport};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::ExposeSecret;

/// Field identifiers carry no imported values or credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    /// Connection name.
    Name,
    /// Proxy endpoint.
    Server,
    /// Server port.
    Port,
    /// Authentication UUID.
    Credential,
    /// TLS server name.
    ServerName,
    /// Browser fingerprint.
    Fingerprint,
    /// REALITY public key.
    PublicKey,
    /// REALITY short ID.
    ShortId,
    /// ALPN list.
    Alpn,
    /// Transport/security combination.
    Transport,
    /// WebSocket request path.
    WebSocketPath,
    /// WebSocket HTTP Host override.
    WebSocketHost,
    /// Imported share link.
    Link,
    /// Explicit resolver selection.
    Dns,
}

/// Safe-to-display error: never includes supplied values or third-party parse errors.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct ValidationError {
    /// The input to highlight.
    pub field: Field,
    /// Static explanation, without private input.
    pub message: &'static str,
}

impl ValidationError {
    pub(crate) fn new(field: Field, message: &'static str) -> Self {
        Self { field, message }
    }
}

pub(crate) fn hostname(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value.chars().any(char::is_whitespace)
        // Keep the spelling passed to DNS/TLS equivalent to the parsed host.
        // URL decoding and IDNA conversion must not validate a different string.
        && matches!(url::Host::parse(value), Ok(url::Host::Domain(domain)) if domain.eq_ignore_ascii_case(value))
        && !value.contains(['/', '\\', '@', ':', '[', ']'])
}

impl Draft {
    /// Validate only network-policy combinations, without credentials, I/O or mutation.
    /// Used by non-secret NM metadata observation as well as full validation.
    pub fn validate_policy(&self) -> Result<(), Vec<ValidationError>> {
        let mut errors = Vec::new();
        let mut require = |ok: bool, field, message| {
            if !ok {
                errors.push(ValidationError::new(field, message));
            }
        };
        require(
            self.dns_override.validate().is_ok(),
            Field::Dns,
            "Choose the current network DNS or a public IPv4 DNS server through the VPN.",
        );
        require(
            !self.fake_ip || self.dns_interception,
            Field::Dns,
            "IPv4 FakeIP requires explicit DNS interception; it cannot bypass domain ownership.",
        );
        require(
            self.source_policy.is_none()
                || (self.fake_ip
                    && self.dns_interception
                    && self.tcp_domain_policy.is_none()
                    && !self.lan_bypass
                    && !self.private_lan_bypass),
            Field::Dns,
            "Complete IPv4 policy requires FakeIP/interception and cannot be combined with legacy LAN or TCP-only routing.",
        );
        require(
            !(self.lan_bypass && self.private_lan_bypass),
            Field::Dns,
            "Choose connected-only or all-RFC1918 bypass, not both.",
        );
        require(
            !self.private_lan_bypass || self.tcp_domain_policy.is_none(),
            Field::Dns,
            "All-RFC1918 bypass cannot combine with legacy hostname routing; use a checked ordered source policy instead.",
        );
        require(
            !matches!(self.dns_override, crate::DnsOverride::ProxyIpv4(_))
                || !self
                    .tcp_domain_policy
                    .as_ref()
                    .is_some_and(|policy| policy.has_direct()),
            Field::Dns,
            "Direct hostname rules cannot yet use a manual through-VPN resolver; choose current network DNS instead.",
        );
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate a snapshot without DNS, I/O or credential logging.
    /// Unsupported modes and malformed fields fail rather than downgrade.
    pub fn validate(&self) -> Result<Profile, Vec<ValidationError>> {
        self.validate_fields(true)?;
        Profile::from_validated(self.clone()).map_err(|error| vec![error])
    }

    /// Validate non-secret configuration independently of credential availability.
    /// Success is not an executable profile and cannot be passed to the engine.
    pub fn validate_configuration(&self) -> Result<(), Vec<ValidationError>> {
        self.validate_fields(false)
    }

    fn validate_fields(&self, credentials: bool) -> Result<(), Vec<ValidationError>> {
        let mut errors = self.validate_policy().err().unwrap_or_default();
        let mut require = |ok: bool, field, message| {
            if !ok {
                errors.push(ValidationError::new(field, message));
            }
        };
        require(
            !self.name.trim().is_empty()
                && self.name.len() <= 128
                && !self.name.chars().any(char::is_control),
            Field::Name,
            "Enter a connection name (at most 128 bytes, without control characters).",
        );
        require(
            self.server.parse::<std::net::IpAddr>().is_ok() || hostname(&self.server),
            Field::Server,
            "Enter an ASCII server hostname or IP address, without URL encoding, scheme or port.",
        );
        require(
            !matches!(
                self.server.parse::<std::net::IpAddr>(),
                Ok(std::net::IpAddr::V6(_))
            ),
            Field::Server,
            "IPv6 endpoints are unsupported in this IPv4-only version; use an IPv4 address or a hostname with an A record.",
        );
        require(
            !matches!(self.server.parse::<std::net::Ipv4Addr>(), Ok(ip)
            if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast()),
            Field::Server,
            "The VPN endpoint must be a concrete unicast IPv4 address or a hostname with an A record.",
        );
        require(
            self.port.parse::<u16>().is_ok_and(|port| port != 0)
                && self.port.bytes().all(|byte| byte.is_ascii_digit()),
            Field::Port,
            "Enter a port between 1 and 65535.",
        );
        require(
            !credentials
                || (self.credential.expose_secret().len() == 36
                    && uuid::Uuid::parse_str(self.credential.expose_secret())
                        .is_ok_and(|id| !id.is_nil())),
            Field::Credential,
            "Enter a non-zero VLESS UUID.",
        );
        require(
            hostname(&self.server_name),
            Field::ServerName,
            "Enter an ASCII TLS hostname (SNI), without URL encoding, not an IP address or URL.",
        );
        require(
            (self.security == Security::Tls && self.fingerprint == "native")
                || matches!(
                    self.fingerprint.as_str(),
                    "chrome" | "firefox" | "safari" | "ios" | "android" | "edge"
                ),
            Field::Fingerprint,
            "Choose a supported browser fingerprint.",
        );
        if let Transport::WebSocket { path, host } = &self.transport {
            require(
                self.security == Security::Tls && !self.vision,
                Field::Transport,
                "WebSocket requires verified TLS without REALITY or Vision.",
            );
            require(
                !self.alpn.split(',').any(|value| value == "h2"),
                Field::Alpn,
                "WebSocket uses HTTP/1.1; omit ALPN or select only http/1.1.",
            );
            require(
                path.starts_with('/')
                    && path.len() <= 2048
                    && !path.contains('#')
                    && path.parse::<http::uri::PathAndQuery>().is_ok(),
                Field::WebSocketPath,
                "Enter a valid WebSocket path/query starting with '/', at most 2048 bytes.",
            );
            if let Some(host) = host {
                require(
                    !host.is_empty()
                        && host.len() <= 320
                        && !host.contains('@')
                        && host.parse::<http::uri::Authority>().is_ok(),
                    Field::WebSocketHost,
                    "Enter a WebSocket HTTP Host authority without userinfo, whitespace or a path.",
                );
            }
        }
        if self.security == Security::Reality {
            require(
                self.public_key.len() == 43
                    && URL_SAFE_NO_PAD.decode(&self.public_key).is_ok_and(|bytes| {
                        bytes.len() == 32 && bytes.iter().any(|byte| *byte != 0)
                    }),
                Field::PublicKey,
                "Enter a 32-byte REALITY public key in unpadded base64url format.",
            );
            require(
                self.short_id.len() <= 16
                    && self.short_id.len().is_multiple_of(2)
                    && self.short_id.bytes().all(|byte| byte.is_ascii_hexdigit()),
                Field::ShortId,
                "REALITY short ID must contain zero to sixteen hex digits in complete bytes.",
            );
        } else {
            require(
                self.public_key.is_empty() && self.short_id.is_empty(),
                Field::PublicKey,
                "Remove REALITY-only fields before using ordinary TLS.",
            );
        }
        require(
            self.alpn.is_empty()
                || self
                    .alpn
                    .split(',')
                    .all(|value| matches!(value, "h2" | "http/1.1")),
            Field::Alpn,
            "ALPN supports h2 and http/1.1, separated by a comma.",
        );
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}
