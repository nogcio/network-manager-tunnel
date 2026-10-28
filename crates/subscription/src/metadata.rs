//! Bounded, advisory provider headers. Never authorize profiles, fetches or timers.
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::header::HeaderMap;

/// Advisory header state; malformed is distinct from omitted or unlimited.
#[derive(Clone, Default, PartialEq, Eq)]
pub enum MetadataValue<T> {
    /// The provider did not supply this header.
    #[default]
    Absent,
    /// Duplicated, oversized, ambiguous or malformed header; raw text is discarded.
    Invalid,
    /// A bounded, syntactically checked value, not independently verified usage.
    Value(T),
}

impl<T> std::fmt::Debug for MetadataValue<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Absent => "Absent",
            Self::Invalid => "Invalid",
            Self::Value(_) => "Value([redacted])",
        })
    }
}

/// Provider-reported bytes and Unix expiry seconds. Missing fields remain unknown.
/// Explicit zero total/expiry mean unlimited/no expiry under our header contract.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderUsage {
    /// Bytes uploaded according to the provider, not local tunnel counters.
    pub upload: Option<u64>,
    /// Bytes downloaded according to the provider.
    pub download: Option<u64>,
    /// Byte quota; zero explicitly denotes unlimited.
    pub total: Option<u64>,
    /// Unix timestamp, at most 9999-12-31T23:59:59Z; zero denotes no expiry.
    pub expire: Option<u64>,
}

/// Response-local hints; never persisted, logged or applied as configuration.
/// Failed body admission publishes none of these values. Clones own their data.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProviderMetadata {
    /// `subscription-userinfo`: checked unsigned decimal counters, no float coercion.
    pub usage: MetadataValue<ProviderUsage>,
    /// `profile-title`: plain UTF-8 or standard padded base64, at most 128 UTF-8 bytes.
    /// A suggestion only: never replaces the user's chosen subscription name.
    pub title: MetadataValue<String>,
    /// `profile-update-interval`: integer hours, 1 through 720. Does not start a timer.
    pub update_interval_hours: MetadataValue<u16>,
}

impl ProviderMetadata {
    pub(crate) fn from_headers(headers: &HeaderMap) -> Self {
        Self {
            usage: header(headers, "subscription-userinfo", 1024, usage),
            title: header(headers, "profile-title", 512, title),
            update_interval_hours: header(headers, "profile-update-interval", 8, |s| {
                let hours = decimal(s)?;
                (1..=720).contains(&hours).then_some(hours as u16)
            }),
        }
    }
}

fn header<T>(
    headers: &HeaderMap,
    name: &'static str,
    limit: usize,
    parse: impl FnOnce(&str) -> Option<T>,
) -> MetadataValue<T> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return MetadataValue::Absent;
    };
    if values.next().is_some() || value.as_bytes().len() > limit {
        return MetadataValue::Invalid;
    }
    // HeaderValue::to_str excludes non-ASCII, but profile-title permits UTF-8.
    std::str::from_utf8(value.as_bytes())
        .ok()
        .and_then(|s| parse(s.trim()))
        .map_or(MetadataValue::Invalid, MetadataValue::Value)
}

fn decimal(value: &str) -> Option<u64> {
    (!value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
        .then(|| value.parse().ok())
        .flatten()
}

fn usage(value: &str) -> Option<ProviderUsage> {
    let mut usage = ProviderUsage {
        upload: None,
        download: None,
        total: None,
        expire: None,
    };
    for field in value.split(';') {
        let (key, value) = field.trim().split_once('=')?;
        let slot = match key.trim().to_ascii_lowercase().as_str() {
            "upload" => &mut usage.upload,
            "download" => &mut usage.download,
            "total" => &mut usage.total,
            "expire" => &mut usage.expire,
            _ => return None,
        };
        if slot.is_some() {
            return None;
        }
        *slot = Some(decimal(value.trim())?);
    }
    if usage.expire.is_some_and(|v| v > 253_402_300_799)
        || usage
            .upload
            .zip(usage.download)
            .is_some_and(|(u, d)| u.checked_add(d).is_none())
    {
        return None;
    }
    Some(usage)
}

fn title(value: &str) -> Option<String> {
    let decoded = if let Some(encoded) = value.strip_prefix("base64:") {
        String::from_utf8(STANDARD.decode(encoded).ok()?).ok()?
    } else {
        value.to_owned()
    };
    let value = decoded.trim();
    if value.is_empty()
        || value.len() > 128
        || value.chars().any(|c| {
            c.is_control() || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
    {
        return None;
    }
    Some(value.to_owned())
}

#[cfg(test)]
#[path = "metadata_tests.rs"]
mod tests;
