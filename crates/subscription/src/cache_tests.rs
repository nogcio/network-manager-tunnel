//! Conditional response contracts against bounded private loopback peers, not TLS.
use super::*;
use reqwest::header::{ETAG, HeaderMap, HeaderValue, LAST_MODIFIED};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
const DEADLINE: Duration = Duration::from_secs(5);
const LINK: &str =
    "vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls#Synthetic";

async fn exchange(
    listener: &TcpListener,
    path: &str,
    format: SubscriptionFormat,
    previous: Option<Subscription>,
    response: String,
    conditional: Option<&str>,
) -> Result<Result<Subscription, SubscriptionError>, Box<dyn std::error::Error + Send + Sync>> {
    let url = url::Url::parse(&format!("http://{}{path}", listener.local_addr()?))?;
    let peer = async {
        let (mut stream, _) = listener.accept().await?;
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            if request.len() >= 8192 {
                return Err(std::io::Error::other("oversized test request"));
            }
            request.push(stream.read_u8().await?);
        }
        let request = String::from_utf8_lossy(&request).to_ascii_lowercase();
        let conditionals: Vec<_> = request
            .lines()
            .filter(|s| s.starts_with("if-none-match:") || s.starts_with("if-modified-since:"))
            .collect();
        assert_eq!(conditionals, conditional.into_iter().collect::<Vec<_>>());
        stream.write_all(response.as_bytes()).await?;
        Ok::<_, std::io::Error>(())
    };
    let client = client_builder(format)
        .https_only(false)
        .no_proxy()
        .build()?;
    let (peer, result) = tokio::join!(
        timeout(DEADLINE, peer),
        timeout(DEADLINE, download_update(client, url, format, previous))
    );
    peer??;
    Ok(result?)
}

fn ok(body: &str, headers: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{headers}\r\n{body}",
        body.len()
    )
}

#[tokio::test]
async fn not_modified_requires_the_same_loaded_document_endpoint_and_format() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let first = exchange(
        &listener,
        "/one",
        SubscriptionFormat::NodesOnly,
        None,
        ok(
            LINK,
            "ETag: \"synthetic-etag\"\r\nProfile-Title: Synthetic title\r\n",
        ),
        None,
    )
    .await??;
    let original = first.clone();
    let response = "HTTP/1.1 304 Not Modified\r\nSubscription-Userinfo: total=0\r\n\r\n";
    let cached = exchange(
        &listener,
        "/one",
        SubscriptionFormat::NodesOnly,
        Some(first),
        response.into(),
        Some("if-none-match: \"synthetic-etag\""),
    )
    .await??;
    assert_eq!(cached.entries()[0].name(), "Synthetic");
    assert_eq!(cached.metadata().title, original.metadata().title);
    assert!(matches!(cached.metadata().usage, MetadataValue::Value(_)));
    assert!(matches!(original.metadata().usage, MetadataValue::Absent));
    let invalid_hint = exchange(
        &listener, "/one", SubscriptionFormat::NodesOnly, Some(original.clone()),
        "HTTP/1.1 304 Not Modified\r\nSubscription-Userinfo: total=-1\r\nCache-Control: no-store\r\n\r\n".into(),
        Some("if-none-match: \"synthetic-etag\""),
    ).await??;
    assert_eq!(invalid_hint.metadata().usage, MetadataValue::Invalid);
    assert_eq!(invalid_hint.supported_count(), 1);
    assert!(invalid_hint.validators.is_none());
    for (path, format, previous) in [
        ("/one", SubscriptionFormat::NodesOnly, None),
        (
            "/two",
            SubscriptionFormat::NodesOnly,
            Some(original.clone()),
        ),
        ("/one", SubscriptionFormat::Complete, Some(original.clone())),
        (
            "/one",
            SubscriptionFormat::NodesOnly,
            Some(parse_subscription(LINK.as_bytes())?),
        ),
    ] {
        assert_eq!(
            exchange(&listener, path, format, previous, response.into(), None)
                .await?
                .err(),
            Some(SubscriptionError::Download)
        );
    }
    // A matching request with a rejected 200 does not mutate the retained copy.
    assert!(
        exchange(
            &listener,
            "/one",
            SubscriptionFormat::NodesOnly,
            Some(original.clone()),
            ok("invalid", "Profile-Title: Should not publish\r\n"),
            Some("if-none-match: \"synthetic-etag\"")
        )
        .await?
        .is_err()
    );
    assert_eq!(original.entries()[0].name(), "Synthetic");
    assert_eq!(
        original.metadata().title,
        MetadataValue::Value("Synthetic title".into())
    );
    assert!(!format!("{original:?}").contains("synthetic-etag"));
    Ok(())
}

#[tokio::test]
async fn last_modified_fallback_and_successful_replacement_do_not_preserve_old_hints() -> TestResult
{
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let first = exchange(
        &listener,
        "/one",
        SubscriptionFormat::NodesOnly,
        None,
        ok(
            LINK,
            "Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT\r\nProfile-Title: Old title\r\n",
        ),
        None,
    )
    .await??;
    let replaced = exchange(
        &listener,
        "/one",
        SubscriptionFormat::NodesOnly,
        Some(first),
        ok(LINK, ""),
        Some("if-modified-since: wed, 21 oct 2015 07:28:00 gmt"),
    )
    .await??;
    assert_eq!(replaced.metadata(), &ProviderMetadata::default());
    assert_eq!(
        exchange(
            &listener,
            "/one",
            SubscriptionFormat::NodesOnly,
            Some(replaced),
            "HTTP/1.1 304 Not Modified\r\n\r\n".into(),
            None
        )
        .await?
        .err(),
        Some(SubscriptionError::Download)
    );
    Ok(())
}

#[test]
fn validators_are_bounded_opaque_and_endpoint_bound() -> TestResult {
    let one = url::Url::parse("https://example.invalid/one?synthetic-token=one")?;
    let two = url::Url::parse("https://example.invalid/two?synthetic-token=two")?;
    let mut headers = HeaderMap::new();
    headers.insert(ETAG, HeaderValue::from_static("\"opaque-tag\""));
    headers.insert(
        LAST_MODIFIED,
        HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"),
    );
    let mut validators = cache::Validators::new(&one, SubscriptionFormat::Complete, &headers)
        .ok_or("Synthetic validators missing")?;
    assert!(validators.matches(&one, SubscriptionFormat::Complete));
    assert!(!validators.matches(&two, SubscriptionFormat::Complete));
    assert!(!validators.matches(&one, SubscriptionFormat::NodesOnly));
    assert!(!format!("{validators:?}").contains("synthetic-token"));
    assert!(
        validators
            .etag
            .as_ref()
            .is_some_and(HeaderValue::is_sensitive)
    );
    headers.append(ETAG, HeaderValue::from_static("\"duplicate\""));
    headers.insert(LAST_MODIFIED, HeaderValue::from_str(&"x".repeat(1025))?);
    validators.refresh(&headers);
    assert!(!validators.matches(&one, SubscriptionFormat::Complete));
    Ok(())
}

#[tokio::test]
async fn no_store_disables_conditional_reuse_but_not_explicit_profile_import() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let first = exchange(
        &listener,
        "/one",
        SubscriptionFormat::NodesOnly,
        None,
        ok(
            LINK,
            "ETag: \"synthetic-etag\"\r\nCache-Control: private, no-store\r\n",
        ),
        None,
    )
    .await??;
    assert_eq!(first.supported_count(), 1);
    assert_eq!(
        exchange(
            &listener,
            "/one",
            SubscriptionFormat::NodesOnly,
            Some(first),
            "HTTP/1.1 304 Not Modified\r\n\r\n".into(),
            None
        )
        .await?
        .err(),
        Some(SubscriptionError::Download)
    );
    Ok(())
}
