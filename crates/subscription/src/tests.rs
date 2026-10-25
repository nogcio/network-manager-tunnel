//! Loopback HTTP tests for shared response handling, not TLS acceptance tests.
use super::*;
use std::error::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::timeout,
};

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;
const DEADLINE: Duration = Duration::from_secs(5);
const LINK: &str = "vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=www.example.com#Example";

// The listener is bound before the client starts. Every socket operation and the
// client task have deadlines; dropping the release sender also releases the peer.
async fn response_case(
    response: Vec<u8>,
    request_timeout: Duration,
    expected: Option<SubscriptionError>,
) -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = url::Url::parse(&format!("http://{}/list", listener.local_addr()?))?;
    let (release, released) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (mut stream, _) = timeout(DEADLINE, listener.accept()).await??;
        let mut request = Vec::new();
        timeout(DEADLINE, async {
            while !request.ends_with(b"\r\n\r\n") {
                if request.len() == 8192 {
                    return Err(std::io::Error::other("oversized test request"));
                }
                request.push(stream.read_u8().await?);
            }
            stream.write_all(&response).await
        })
        .await??;
        if response.starts_with(b"HTTP/1.1 302") {
            stream.shutdown().await?;
        }
        // Keep incomplete bodies open until the request has timed out, rather
        // than accidentally testing premature EOF instead of a read deadline.
        timeout(DEADLINE, async {
            tokio::select! {
                _ = released => Ok(()),
                connection = listener.accept() => {
                    connection?;
                    Err(std::io::Error::other("unexpected second request"))
                }
            }
        })
        .await??;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });
    // Only the test permits plaintext and disables environment proxies. All
    // other policy comes from the production builder; no public test hooks exist.
    let client = client_builder()
        .https_only(false)
        .no_proxy()
        .timeout(request_timeout)
        .build()?;
    let result = timeout(DEADLINE, download(client, url)).await;
    let _ = release.send(());
    timeout(DEADLINE, server).await???;
    let result = result?;
    match expected {
        Some(error) => assert_eq!(result.err(), Some(error)),
        None => assert_eq!(result?.supported_count(), 1),
    }
    Ok(())
}

#[tokio::test]
async fn complete_response_imports_and_redirects_and_errors_are_rejected() -> TestResult {
    response_case(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{LINK}",
            LINK.len()
        )
        .into_bytes(),
        DEADLINE,
        None,
    )
    .await?;
    for status in ["302 Found", "503 Service Unavailable"] {
        // The peer rejects a second connection, detecting redirect following
        // independently of the eventual client error.
        response_case(
            format!("HTTP/1.1 {status}\r\nLocation: /unexpected\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                .into_bytes(),
            DEADLINE,
            Some(SubscriptionError::Download),
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn declared_and_chunked_oversize_responses_are_rejected() -> TestResult {
    response_case(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_BYTES + 1
        )
        .into_bytes(),
        DEADLINE,
        Some(SubscriptionError::TooLarge),
    )
    .await?;
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
        MAX_BYTES
    )
    .into_bytes();
    response.extend(std::iter::repeat_n(b'a', MAX_BYTES));
    response.extend_from_slice(b"\r\n1\r\nb\r\n0\r\n\r\n");
    response_case(response, DEADLINE, Some(SubscriptionError::TooLarge)).await
}

#[tokio::test]
async fn stalled_body_obeys_the_request_deadline() -> TestResult {
    response_case(
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n".to_vec(),
        Duration::from_millis(200),
        Some(SubscriptionError::Timeout),
    )
    .await
}
