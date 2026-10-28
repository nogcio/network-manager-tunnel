//! Explicit HTTPS subscription loading and bounded share-link lists.
//! Source URLs and node credentials remain in memory and are redacted from Debug.
mod cache;
#[cfg(test)]
mod cache_tests;
mod complete;
mod metadata;
mod parse;
#[cfg(test)]
mod tests;
pub use complete::PolicyIssue;
pub use metadata::{MetadataValue, ProviderMetadata, ProviderUsage};
pub use parse::{Entry, Subscription, parse_subscription};
use secrecy::{ExposeSecret, SecretString};
use std::time::Duration;

/// Maximum downloaded/decoded payload, including unsupported records.
pub const MAX_BYTES: usize = 2 * 1024 * 1024;
/// Maximum non-comment records per subscription.
pub const MAX_ENTRIES: usize = 512;

/// Explicit response contract. Complete is the safe default; selecting NodesOnly
/// consents to importing share links without the provider's global DNS/routing.
/// This choice is memory-only and must never be used as an automatic retry/fallback.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SubscriptionFormat {
    /// Request the sing-box client configuration envelope; unsupported policies
    /// reject the entire response before any profiles can be published.
    #[default]
    Complete,
    /// Explicit legacy node-only import, with the application's default policy.
    NodesOnly,
}

impl SubscriptionFormat {
    fn user_agent(self) -> &'static str {
        match self {
            // Some providers require the platform-client prefix; the suffix
            // identifies us and explicitly does not claim runtime compatibility.
            Self::Complete => "SFA/1.12.0 network-manager-tunnel/0.1 (configuration-import-only)",
            Self::NodesOnly => "network-manager-tunnel/0.1",
        }
    }
    fn accept(self) -> &'static str {
        match self {
            Self::Complete => "application/json",
            Self::NodesOnly => "text/plain",
        }
    }
}

/// Safe-to-display errors contain no source URL, token, body or upstream error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SubscriptionError {
    /// An explicit HTTPS endpoint is required, without userinfo or fragments.
    #[error("Enter an HTTPS subscription URL without a username, password or fragment.")]
    InvalidUrl,
    /// Certificate verification is mandatory; redirects and non-success replies fail.
    #[error(
        "Could not load the subscription. Check the URL, TLS certificate and server response. Redirects are not followed."
    )]
    Download,
    /// The total download deadline expired.
    #[error("Subscription download timed out. The previous profile list is unchanged.")]
    Timeout,
    /// Encoded or decoded body exceeds the bound.
    #[error("The subscription exceeds the 2 MiB size limit.")]
    TooLarge,
    /// Refuse an excessive record count atomically.
    #[error("The subscription contains more than 512 records.")]
    TooManyEntries,
    /// Input does not match the explicitly selected format or its bounded syntax.
    #[error(
        "The subscription does not match the selected format. Expected a complete JSON configuration or, in explicit node-only mode, a URI list. No profiles were imported."
    )]
    Format,
    /// A complete request must never accept a node-only response as equivalent.
    #[error(
        "The server did not return a complete configuration. Node-only import must be selected explicitly; no fallback was attempted."
    )]
    FullConfigurationRequired,
    /// All-or-nothing admission; no node may be extracted from unsupported policy.
    #[error("{0}")]
    UnsupportedPolicy(PolicyIssue),
}

/// Validate the endpoint without resolving, fetching, logging or persisting it.
pub fn validate_url(input: &str) -> Result<(), SubscriptionError> {
    endpoint(input).map(|_| ())
}

fn endpoint(input: &str) -> Result<url::Url, SubscriptionError> {
    if input.len() > 8192 {
        return Err(SubscriptionError::InvalidUrl);
    }
    let url = url::Url::parse(input.trim()).map_err(|_| SubscriptionError::InvalidUrl)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(SubscriptionError::InvalidUrl);
    }
    Ok(url)
}

/// Download only after explicit user action. Never discovers local subscriptions,
/// follows redirects, bypasses certificate validation, retries or writes a cache.
/// A failure returns no partial list and must not replace the caller's last list.
pub async fn fetch_subscription(source: SecretString) -> Result<Subscription, SubscriptionError> {
    fetch_subscription_format(source, SubscriptionFormat::Complete).await
}

/// Download one explicitly selected format on user action. Requests complete
/// configuration by default through `fetch_subscription`; NodesOnly requires a
/// visible warning/explicit choice. No format discovery, second request or fallback.
/// Cancellation discards local work; failures return no partial profiles and must
/// disable additions from a retained older response until a successful reload.
pub async fn fetch_subscription_format(
    source: SecretString,
    format: SubscriptionFormat,
) -> Result<Subscription, SubscriptionError> {
    let url = endpoint(source.expose_secret())?;
    let client = client_builder(format)
        .build()
        .map_err(|_| SubscriptionError::Download)?;
    download(client, url, format).await
}

/// Explicit refresh with an optional previously admitted, memory-only response.
/// Validators are reused only for the same canonical URL and format. A 304 needs
/// that exact cached document; otherwise it fails. A 200 replaces it only after full
/// admission. Cancellation/failure discards this owned copy, never mutates the
/// caller's retained catalog, writes storage, retries, applies profiles or activates.
/// Neither URLs nor validators appear in Debug; no validators survive app restart.
pub async fn fetch_subscription_update(
    source: SecretString,
    format: SubscriptionFormat,
    previous: Option<Subscription>,
) -> Result<Subscription, SubscriptionError> {
    let url = endpoint(source.expose_secret())?;
    let client = client_builder(format)
        .build()
        .map_err(|_| SubscriptionError::Download)?;
    download_update(client, url, format, previous).await
}

fn client_builder(format: SubscriptionFormat) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .connect_timeout(Duration::from_secs(10))
        .user_agent(format.user_agent())
}

async fn download(
    client: reqwest::Client,
    url: url::Url,
    format: SubscriptionFormat,
) -> Result<Subscription, SubscriptionError> {
    download_update(client, url, format, None).await
}

async fn download_update(
    client: reqwest::Client,
    url: url::Url,
    format: SubscriptionFormat,
    previous: Option<Subscription>,
) -> Result<Subscription, SubscriptionError> {
    let map_error = |error: reqwest::Error| {
        if error.is_timeout() {
            SubscriptionError::Timeout
        } else {
            SubscriptionError::Download
        }
    };
    let mut previous = previous.filter(|s| {
        s.validators
            .as_ref()
            .is_some_and(|v| v.matches(&url, format))
    });
    let mut request = client
        .get(url.clone())
        .header(reqwest::header::ACCEPT, format.accept());
    if let Some(validators) = previous.as_ref().and_then(|s| s.validators.as_ref()) {
        if let Some(etag) = &validators.etag {
            request = request.header(reqwest::header::IF_NONE_MATCH, etag);
        } else if let Some(modified) = &validators.modified {
            request = request.header(reqwest::header::IF_MODIFIED_SINCE, modified);
        }
    }
    let mut response = request.send().await.map_err(map_error)?;
    if response.status() == reqwest::StatusCode::NOT_MODIFIED {
        let mut subscription = previous.take().ok_or(SubscriptionError::Download)?;
        if let Some(validators) = &mut subscription.validators {
            validators.refresh(response.headers());
        }
        subscription.validators = subscription.validators.filter(|v| v.matches(&url, format));
        cache::refresh_metadata(&mut subscription.metadata, response.headers());
        return Ok(subscription);
    }
    if !response.status().is_success() {
        return Err(SubscriptionError::Download);
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_BYTES as u64)
    {
        return Err(SubscriptionError::TooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(map_error)? {
        if chunk.len() > MAX_BYTES.saturating_sub(body.len()) {
            return Err(SubscriptionError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    let metadata = ProviderMetadata::from_headers(response.headers());
    let mut subscription = match format {
        SubscriptionFormat::Complete => complete::admit(&body),
        SubscriptionFormat::NodesOnly => parse_subscription(&body),
    }?;
    subscription.metadata = metadata;
    subscription.validators = cache::Validators::new(&url, format, response.headers());
    Ok(subscription)
}
