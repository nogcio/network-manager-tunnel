//! Bounded protocol-library inspection, never a handwritten TLS/HTTP parser.
use std::{io, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt};

const LIMIT: usize = 8192;
const DEADLINE: Duration = Duration::from_millis(300);

/// Owned first bytes and an optional library-observed HTTP Host/TLS SNI.
/// The exact prefix must be replayed once, before relaying further client bytes.
/// It can contain plaintext/authentication data and is always Debug-redacted.
pub struct TcpHostname {
    hostname: Option<String>,
    prefix: Vec<u8>,
}

impl std::fmt::Debug for TcpHostname {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TcpHostname([redacted])")
    }
}

impl TcpHostname {
    /// Canonical observed hostname, not DNS reverse inference or an authenticated
    /// application identity. ECH, unsupported protocols and absent names yield None.
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    /// Bytes already consumed from the client, unchanged and in original order.
    pub fn prefix(&self) -> &[u8] {
        &self.prefix
    }
}

/// Inspect at most 8 KiB within one 300 ms total deadline, without opening any
/// upstream socket. Uses the pinned meow-common HTTP/TLS parsers. Reads are bounded
/// and cancellation-safe; the caller owns the client stream and closes it if this
/// future is cancelled, since an unfinished inspection may have consumed bytes.
/// Unknown/incomplete protocols preserve all read bytes and yield no hostname.
/// An I/O error is sanitized and must close the flow, never trigger direct fallback.
pub async fn inspect_tcp_hostname<R: AsyncRead + Unpin>(stream: &mut R) -> io::Result<TcpHostname> {
    let deadline = tokio::time::Instant::now() + DEADLINE;
    let mut prefix = vec![0; LIMIT];
    let mut size = 0;
    let mut hostname = None;
    while size < LIMIT {
        match tokio::time::timeout_at(deadline, stream.read(&mut prefix[size..])).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Err(error)) => {
                return Err(io::Error::new(
                    error.kind(),
                    "TCP hostname inspection failed.",
                ));
            }
            Ok(Ok(length)) => size += length,
        }
        // The pinned library assumes a complete four-byte handshake header once
        // a TLS record is available. Enforce its minimum input precondition before
        // calling it; all actual TLS/HTTP extraction remains library-owned.
        let tls_minimum = size >= 9 && u16::from_be_bytes([prefix[3], prefix[4]]) >= 4;
        hostname = tls_minimum
            .then(|| meow_common::sniffer::sniff_tls(&prefix[..size]))
            .flatten()
            .or_else(|| meow_common::sniffer::sniff_http(&prefix[..size]))
            .and_then(|name| nm_tunnel_profile::canonical_domain(&name));
        if hostname.is_some() {
            break;
        }
    }
    prefix.truncate(size);
    Ok(TcpHostname { hostname, prefix })
}
