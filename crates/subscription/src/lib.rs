//! Explicit HTTPS subscription loading and bounded share-link lists.
//! Source URLs and node credentials remain in memory and are redacted from Debug.
mod parse;
#[cfg(test)]
mod tests;
pub use parse::{Entry, Subscription, parse_subscription};
use secrecy::{ExposeSecret, SecretString};
use std::time::Duration;

/// Maximum downloaded/decoded payload, including unsupported records.
pub const MAX_BYTES: usize = 2 * 1024 * 1024;
/// Maximum non-comment records per subscription.
pub const MAX_ENTRIES: usize = 512;

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
    /// Input was empty, binary, or neither a URI list nor supported base64.
    #[error(
        "Expected a non-empty URI-list subscription, optionally base64 encoded. YAML, JSON and HTML are not supported."
    )]
    Format,
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
    let url = endpoint(source.expose_secret())?;
    let client = client_builder()
        .build()
        .map_err(|_| SubscriptionError::Download)?;
    download(client, url).await
}

fn client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .connect_timeout(Duration::from_secs(10))
        .user_agent("network-manager-tunnel/0.1")
}

async fn download(
    client: reqwest::Client,
    url: url::Url,
) -> Result<Subscription, SubscriptionError> {
    let map_error = |error: reqwest::Error| {
        if error.is_timeout() {
            SubscriptionError::Timeout
        } else {
            SubscriptionError::Download
        }
    };
    let mut response = client.get(url).send().await.map_err(map_error)?;
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
    parse_subscription(&body)
}
