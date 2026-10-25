//! Standard URL/base64 codecs plus project-specific subscription admission policy.
use crate::{MAX_BYTES, MAX_ENTRIES, SubscriptionError};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use nm_tunnel_profile::{Profile, import_vless};
use percent_encoding::percent_decode_str;

/// Subscription node. Unsupported entries are retained with a safe explanation.
#[derive(Clone)]
pub struct Entry {
    name: String,
    profile: Result<Profile, &'static str>,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Entry([redacted])")
    }
}

impl Entry {
    /// Display label, never the raw credential-bearing URI.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Validated profile or a static unsupported/invalid explanation.
    pub fn profile(&self) -> Result<&Profile, &'static str> {
        self.profile.as_ref().map_err(|reason| *reason)
    }
}

/// Atomic import result; source URL and raw links are not retained.
#[derive(Clone, Debug)]
pub struct Subscription {
    entries: Vec<Entry>,
}

impl Subscription {
    /// Nodes in source order, including unsupported records.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
    /// Number of entries currently understood by the shared VLESS model.
    pub fn supported_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.profile.is_ok())
            .count()
    }
}

/// Parse a plain UTF-8 URI list or standard/URL-safe base64, with or without padding.
/// Reject oversized/empty/non-list documents atomically. Unsupported individual
/// protocols/settings remain visible rather than being silently dropped.
pub fn parse_subscription(bytes: &[u8]) -> Result<Subscription, SubscriptionError> {
    if bytes.len() > MAX_BYTES {
        return Err(SubscriptionError::TooLarge);
    }
    let input = std::str::from_utf8(bytes)
        .map_err(|_| SubscriptionError::Format)?
        .trim_start_matches('\u{feff}')
        .trim();
    if input.is_empty() {
        return Err(SubscriptionError::Format);
    }
    let decoded;
    let text = if input.contains("://") {
        input
    } else {
        let compact: String = input
            .chars()
            .filter(|value| !value.is_ascii_whitespace())
            .collect();
        decoded = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
            .iter()
            .find_map(|engine| engine.decode(&compact).ok())
            .ok_or(SubscriptionError::Format)?;
        if decoded.len() > MAX_BYTES {
            return Err(SubscriptionError::TooLarge);
        }
        std::str::from_utf8(&decoded)
            .map_err(|_| SubscriptionError::Format)?
            .trim()
    };
    let mut entries = Vec::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        if entries.len() == MAX_ENTRIES {
            return Err(SubscriptionError::TooManyEntries);
        }
        // A whole HTML/JSON/YAML response is not a node list. We do not interpret
        // embedded hrefs, fetch nested URLs or execute subscription directives.
        let parsed = url::Url::parse(line).map_err(|_| SubscriptionError::Format)?;
        if !line
            .split_once("://")
            .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case(parsed.scheme()))
        {
            return Err(SubscriptionError::Format);
        }
        let name = parsed
            .fragment()
            .and_then(|value| percent_decode_str(value).decode_utf8().ok())
            .filter(|value| {
                !value.trim().is_empty()
                    && value.len() <= 128
                    && !value.chars().any(char::is_control)
            })
            .map(|value| value.into_owned())
            .unwrap_or_else(|| format!("Profile {}", entries.len() + 1));
        let profile = if parsed.scheme() == "vless" {
            import_vless(line)
                .and_then(|mut draft| {
                    draft.name = name.clone();
                    draft
                        .validate()
                        .map_err(|_| nm_tunnel_profile::ValidationError {
                            field: nm_tunnel_profile::Field::Link,
                            message: "Invalid VLESS profile fields.",
                        })
                })
                .map_err(|error| error.message)
        } else {
            Err(
                "This protocol is not supported yet. VLESS supports TCP with TLS/REALITY or WebSocket with TLS.",
            )
        };
        entries.push(Entry { name, profile });
    }
    if entries.is_empty() {
        return Err(SubscriptionError::Format);
    }
    Ok(Subscription { entries })
}
