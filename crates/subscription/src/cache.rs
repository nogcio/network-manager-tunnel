//! Memory-only HTTP validators bound to one canonical endpoint and request format.
use crate::{SubscriptionFormat, metadata::ProviderMetadata};
use reqwest::header::{ETAG, HeaderMap, HeaderValue, LAST_MODIFIED};
use secrecy::{ExposeSecret, SecretString};

#[derive(Clone)]
pub(crate) struct Validators {
    source: SecretString,
    format: SubscriptionFormat,
    pub etag: Option<HeaderValue>,
    pub modified: Option<HeaderValue>,
}

impl std::fmt::Debug for Validators {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Validators([redacted])")
    }
}

impl Validators {
    pub fn new(url: &url::Url, format: SubscriptionFormat, headers: &HeaderMap) -> Option<Self> {
        if !cacheable(headers) {
            return None;
        }
        let etag = validator(headers, ETAG);
        let modified = validator(headers, LAST_MODIFIED);
        if etag.is_none() && modified.is_none() {
            return None;
        }
        Some(Self {
            source: url.as_str().into(),
            format,
            etag,
            modified,
        })
    }

    pub fn matches(&self, url: &url::Url, format: SubscriptionFormat) -> bool {
        self.source.expose_secret() == url.as_str()
            && self.format == format
            && (self.etag.is_some() || self.modified.is_some())
    }

    pub fn refresh(&mut self, headers: &HeaderMap) {
        if !cacheable(headers) {
            self.etag = None;
            self.modified = None;
            return;
        }
        if headers.contains_key(ETAG) {
            self.etag = validator(headers, ETAG);
        }
        if headers.contains_key(LAST_MODIFIED) {
            self.modified = validator(headers, LAST_MODIFIED);
        }
    }
}

fn cacheable(headers: &HeaderMap) -> bool {
    headers
        .get_all(reqwest::header::CACHE_CONTROL)
        .iter()
        .all(|value| {
            value.to_str().ok().is_some_and(|value| {
                !value
                    .split(',')
                    .any(|directive| directive.trim().eq_ignore_ascii_case("no-store"))
            })
        })
}

fn validator(headers: &HeaderMap, name: reqwest::header::HeaderName) -> Option<HeaderValue> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    // Treat validators as opaque HTTP bytes, not display labels or instructions.
    // Ignore ambiguous/oversized validators rather than sending them back.
    (values.next().is_none()
        && !value.is_empty()
        && value.as_bytes().len() <= 1024
        && value.as_bytes().iter().all(|b| *b >= 0x20 && *b != 0x7f))
    .then(|| {
        let mut value = value.clone();
        value.set_sensitive(true);
        value
    })
}

pub(crate) fn refresh_metadata(old: &mut ProviderMetadata, headers: &HeaderMap) {
    let new = ProviderMetadata::from_headers(headers);
    if headers.contains_key("subscription-userinfo") {
        old.usage = new.usage;
    }
    if headers.contains_key("profile-title") {
        old.title = new.title;
    }
    if headers.contains_key("profile-update-interval") {
        old.update_interval_hours = new.update_interval_hours;
    }
}
