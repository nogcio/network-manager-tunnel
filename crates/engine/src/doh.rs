//! Bounded RFC 8484 POST over an already approved certificate-verified stream.
use crate::Error;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, body::Body, header};
use std::time::Duration;

const MAX_BYTES: usize = 4096;

/// Exchange one DNS message over an owned, already certificate-verified TLS stream.
/// The source-DNS supervisor supplies the approved stream and checked authority;
/// this function never dials, resolves, redirects, retries or uses environment proxies.
/// HTTP/1.1 POST only; authentication headers and token-bearing paths are unsupported.
/// Drop/cancellation/error or the ten-second deadline closes the driver and stream;
/// no background task or reusable connection survives. DNS identity validation belongs
/// to the shared resolver, not HTTP framing. All diagnostics are static/redacted.
///
/// # Errors
/// Invalid authority/path or an empty/over-4096-byte request is Configuration.
/// Timeout is Timeout. Non-200, encoding/media-type/size or HTTP I/O errors are
/// Handshake, never a signal to fall back to another resolver or route.
pub async fn exchange_doh<S>(
    stream: S,
    host: &str,
    port: u16,
    path: &str,
    request: &[u8],
) -> Result<Vec<u8>, Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    if port == 0
        || request.is_empty()
        || request.len() > MAX_BYTES
        || (nm_tunnel_profile::canonical_domain(host).as_deref() != Some(host)
            && host.parse::<std::net::Ipv4Addr>().is_err())
        || path.len() > 1024
        || !path.starts_with('/')
        || path.starts_with("//")
        || !path
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'?' | b'#' | b'\\'))
    {
        return Err(Error::Configuration);
    }
    let request = Request::post(path)
        .header(header::HOST, format!("{host}:{port}"))
        .header(header::CONTENT_TYPE, "application/dns-message")
        .header(header::ACCEPT, "application/dns-message")
        .body(Full::new(Bytes::copy_from_slice(request)))
        .map_err(|_| Error::Configuration)?;
    tokio::time::timeout(Duration::from_secs(10), async {
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .max_buf_size(16384)
            .handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .map_err(|_| Error::Handshake)?;
        let exchange = async {
            let response = sender
                .send_request(request)
                .await
                .map_err(|_| Error::Handshake)?;
            let headers = response.headers();
            if response.status() != hyper::StatusCode::OK
                || headers.get_all(header::CONTENT_TYPE).iter().count() != 1
                || headers.get(header::CONTENT_TYPE).is_none_or(|v| {
                    !v.as_bytes()
                        .eq_ignore_ascii_case(b"application/dns-message")
                })
                || headers.contains_key(header::CONTENT_ENCODING)
                || response
                    .body()
                    .size_hint()
                    .upper()
                    .is_some_and(|n| n > MAX_BYTES as u64)
            {
                return Err(Error::Handshake);
            }
            let mut body = response.into_body();
            let mut bytes = Vec::new();
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|_| Error::Handshake)?;
                if let Some(data) = frame.data_ref() {
                    if bytes.len() + data.len() > MAX_BYTES {
                        return Err(Error::Handshake);
                    }
                    bytes.extend_from_slice(data);
                } else {
                    return Err(Error::Handshake);
                }
            }
            if bytes.is_empty() {
                return Err(Error::Handshake);
            }
            Ok(bytes)
        };
        tokio::pin!(exchange);
        tokio::pin!(connection);
        tokio::select! {
            biased;
            result = &mut exchange => result,
            _ = &mut connection => {
                // A close-delimited response may finish with the driver in this poll.
                // Poll the ready exchange once; never await a dead connection.
                use std::{future::Future, task::Poll};
                std::future::poll_fn(|cx| Poll::Ready(match exchange.as_mut().poll(cx) {
                    Poll::Ready(result) => result,
                    Poll::Pending => Err(Error::Handshake),
                })).await
            }
        }
    })
    .await
    .map_err(|_| Error::Timeout)?
}
