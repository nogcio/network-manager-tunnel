//! HTTP framing over synthetic owned streams; no certificate or host networking claim.
use nm_tunnel_engine::{Error, exchange_doh};
use std::{io, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn request(peer: &mut tokio::io::DuplexStream) -> io::Result<()> {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        header.push(peer.read_u8().await?);
        if header.len() > 4096 {
            return Err(io::Error::other("Unbounded request header."));
        }
    }
    let header = String::from_utf8(header)
        .map_err(io::Error::other)?
        .to_ascii_lowercase();
    assert!(header.starts_with("post /dns-query http/1.1\r\n"));
    assert!(header.contains("host: resolver.example:443\r\n"));
    assert!(header.contains("content-type: application/dns-message\r\n"));
    let mut body = [0; 3];
    peer.read_exact(&mut body).await?;
    assert_eq!(&body, b"dns");
    Ok(())
}

#[tokio::test]
async fn doh_post_is_bounded_and_http_rejection_never_retries()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(5), async {
        for (response, accepted) in [
            (b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 3\r\n\r\ndns".to_vec(), true),
            (b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n3\r\ndns\r\n0\r\n\r\n".to_vec(), true),
            (b"HTTP/1.1 302 Found\r\nLocation: https://not-contacted.invalid/token\r\nContent-Length: 0\r\n\r\n".to_vec(), false),
            (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 3\r\n\r\ndns".to_vec(), false),
            (b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Encoding: gzip\r\nContent-Length: 3\r\n\r\ndns".to_vec(), false),
            (b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 4097\r\n\r\n".to_vec(), false),
            ([b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n1001\r\n".as_slice(), &vec![0;4097], b"\r\n0\r\n\r\n"].concat(), false),
            (b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 0\r\n\r\n".to_vec(), false),
            (b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 4\r\n\r\ndns".to_vec(), false),
            (b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Type: text/html\r\nContent-Length: 3\r\n\r\ndns".to_vec(), false),
            (b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\nTrailer: X-Private\r\n\r\n3\r\ndns\r\n0\r\nX-Private: private-token\r\n\r\n".to_vec(), false),
        ] {
            let (stream, mut peer) = tokio::io::duplex(32768);
            let client = exchange_doh(stream, "resolver.example", 443, "/dns-query", b"dns");
            let server = async {
                request(&mut peer).await?;
                peer.write_all(&response).await?;
                peer.shutdown().await?;
                let mut extra = Vec::new();
                peer.read_to_end(&mut extra).await?;
                assert!(extra.is_empty(), "No retry or second request after rejection");
                Ok::<_, io::Error>(())
            };
            let (result, server) = tokio::join!(client, server);
            server?;
            assert_eq!(result.is_ok(), accepted);
            if let Err(error) = &result { assert!(!error.to_string().contains("private-token")); }
            if accepted { assert_eq!(result?, b"dns"); }
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    }).await?
}

#[tokio::test]
async fn doh_rejects_invalid_authority_port_and_request_size_before_stream_io()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(5), async {
        for (host, port, payload) in [
            ("resolver.example", 0, b"dns".to_vec()),
            ("https://private-token.invalid", 443, b"dns".to_vec()),
            ("resolver.example", 443, Vec::new()),
            ("resolver.example", 443, vec![0; 4097]),
        ] {
            let (stream, mut peer) = tokio::io::duplex(16384);
            let error = exchange_doh(stream, host, port, "/dns-query", &payload)
                .await
                .err()
                .ok_or("Invalid DoH request accepted")?;
            assert!(matches!(error, Error::Configuration));
            assert!(!error.to_string().contains("private-token"));
            assert_eq!(peer.read(&mut [0]).await?, 0);
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await?
}

#[tokio::test(start_paused = true)]
async fn doh_invalid_input_timeout_and_cancellation_close_owned_stream()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(30), async {
        for path in [
            "https://private-token.invalid",
            "//other.invalid",
            "/dns-query?token=private",
            "/bad\r\nInjected:yes",
        ] {
            let (stream, mut peer) = tokio::io::duplex(16384);
            assert!(matches!(
                exchange_doh(stream, "resolver.example", 443, path, b"dns").await,
                Err(Error::Configuration)
            ));
            assert_eq!(peer.read(&mut [0]).await?, 0);
        }
        for cancel in [true, false] {
            let (stream, mut peer) = tokio::io::duplex(16384);
            let task = tokio::spawn(exchange_doh(
                stream,
                "resolver.example",
                443,
                "/dns-query",
                b"dns",
            ));
            request(&mut peer).await?; // Real request readiness, not a sleep.
            if cancel {
                task.abort();
                assert!(task.await.is_err_and(|e| e.is_cancelled()));
            } else {
                tokio::time::advance(Duration::from_secs(11)).await;
                assert!(matches!(task.await?, Err(Error::Timeout)));
            }
            assert_eq!(peer.read(&mut [0]).await?, 0);
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await?
}
