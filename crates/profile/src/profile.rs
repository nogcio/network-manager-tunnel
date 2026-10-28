//! Executable profile ownership: node, authentication material and network policy.
use crate::{
    Draft, Endpoint, Field, NetworkPolicy, PeerSecurity, RealitySettings, Security, UdpMode,
    ValidationError, VlessSettings,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret, SecretBox};
use std::num::NonZeroU16;

/// Parsed VLESS credential. Owned bytes are zeroized by secrecy on drop.
/// Explicit exposure is for the protocol adapter or NM secret encoding, never logs.
pub struct Credential(SecretBox<[u8; 16]>);

impl Clone for Credential {
    fn clone(&self) -> Self {
        Self(SecretBox::new(Box::new(*self.expose_uuid())))
    }
}

impl Credential {
    /// Borrow authentication bytes without reparsing a string on each flow.
    pub fn expose_uuid(&self) -> &[u8; 16] {
        self.0.expose_secret()
    }
    /// Create an owned, redacted secret string for an explicit boundary conversion.
    pub fn to_secret_string(&self) -> secrecy::SecretString {
        uuid::Uuid::from_bytes(*self.expose_uuid())
            .to_string()
            .into()
    }
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credential([redacted])")
    }
}

/// Checked executable snapshot. Only complete draft validation can construct it.
/// Runtime consumers borrow typed components; edits require an explicit new draft.
#[derive(Clone)]
pub struct Profile {
    name: String,
    node: VlessSettings,
    credential: Credential,
    policy: NetworkPolicy,
}

impl std::fmt::Debug for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Profile([redacted])")
    }
}

impl Profile {
    /// User-visible label. It can identify a source and must not be logged.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Immutable checked node parameters, without credentials or network policy.
    pub fn node(&self) -> &VlessSettings {
        &self.node
    }
    /// Owned authentication material, separate from non-secret node settings.
    pub fn credential(&self) -> &Credential {
        &self.credential
    }
    /// Checked network semantics, independent of URI and NM schema versions.
    pub fn network(&self) -> &NetworkPolicy {
        &self.policy
    }

    /// Explicit editable copy. Numeric/key/credential representations are canonical;
    /// endpoint and SNI spelling, ordered ALPN and policy semantics are preserved.
    /// Creates transient secret text, but performs no I/O or mutation of this profile.
    pub fn to_draft(&self) -> Draft {
        let (security, public_key, short_id) = match &self.node.security {
            PeerSecurity::Tls => (Security::Tls, String::new(), String::new()),
            PeerSecurity::Reality(reality) => (
                Security::Reality,
                URL_SAFE_NO_PAD.encode(reality.public_key),
                reality
                    .short_id
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
            ),
        };
        let mut draft = Draft {
            name: self.name.clone(),
            server: self.node.endpoint.host.clone(),
            port: self.node.endpoint.port.to_string(),
            credential: self.credential.to_secret_string(),
            security,
            transport: self.node.transport.clone(),
            server_name: self.node.server_name.clone(),
            fingerprint: self.node.fingerprint.clone(),
            public_key,
            short_id,
            vision: self.node.vision,
            alpn: self.node.alpn.join(","),
            ..Draft::default()
        };
        self.policy.apply_to(&mut draft);
        draft
    }

    pub(crate) fn from_validated(draft: Draft) -> Result<Self, ValidationError> {
        let port = draft
            .port
            .parse::<u16>()
            .ok()
            .and_then(NonZeroU16::new)
            .ok_or_else(|| ValidationError::new(Field::Port, "Invalid endpoint port."))?;
        let id = uuid::Uuid::parse_str(draft.credential.expose_secret())
            .map_err(|_| ValidationError::new(Field::Credential, "Invalid authentication UUID."))?;
        let security = match draft.security {
            Security::Tls => PeerSecurity::Tls,
            Security::Reality => {
                let public_key = URL_SAFE_NO_PAD
                    .decode(&draft.public_key)
                    .ok()
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                    .ok_or_else(|| {
                        ValidationError::new(Field::PublicKey, "Invalid REALITY public key.")
                    })?;
                let short_id = draft
                    .short_id
                    .as_bytes()
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| {
                        std::str::from_utf8(pair)
                            .ok()
                            .and_then(|value| u8::from_str_radix(value, 16).ok())
                            .ok_or_else(|| {
                                ValidationError::new(Field::ShortId, "Invalid REALITY short ID.")
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                PeerSecurity::Reality(RealitySettings {
                    public_key,
                    short_id,
                })
            }
        };
        let policy = NetworkPolicy::from_validated(&draft);
        let node = VlessSettings {
            endpoint: Endpoint {
                ipv4: draft.server.parse().ok(),
                host: draft.server,
                port,
            },
            transport: draft.transport,
            security,
            server_name: draft.server_name,
            fingerprint: draft.fingerprint,
            vision: draft.vision,
            alpn: if draft.alpn.is_empty() {
                Vec::new()
            } else {
                draft.alpn.split(',').map(str::to_owned).collect()
            },
            udp_mode: if policy.source().is_some() {
                UdpMode::Xudp
            } else {
                UdpMode::Bound
            },
        };
        Ok(Self {
            name: draft.name,
            node,
            credential: Credential(SecretBox::new(Box::new(*id.as_bytes()))),
            policy,
        })
    }
}
