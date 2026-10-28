//! Unprivileged bounded classification. The owner-approved BitTorrent exception
//! is signature detection only; DNS/TLS/HTTP still use the existing libraries.
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Recognize the reviewed fixed TCP signature; this is not a protocol decoder.
pub fn bittorrent_tcp(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x13BitTorrent protocol")
}

/// Recognize the reviewed bounded tracker/uTP signature window.
pub fn bittorrent_udp(bytes: &[u8]) -> bool {
    if bytes.len() >= 16
        && bytes[..8] == [0, 0, 4, 0x17, 0x27, 0x10, 0x19, 0x80]
        && bytes[8..12] == [0; 4]
    {
        return true;
    }
    if bytes.len() < 20 || bytes[0] & 15 != 1 || bytes[0] >> 4 > 4 {
        return false;
    }
    let mut extension = bytes[1];
    let mut cursor = 20;
    while extension != 0 {
        let Some((&next, tail)) = bytes.get(cursor..).and_then(|tail| tail.split_first()) else {
            return false;
        };
        let Some(&length) = tail.first() else {
            return false;
        };
        if next > 4 {
            return false;
        }
        extension = next;
        // Match the source classifier's signature window, not a uTP decoder:
        // after the terminating extension no payload dereference is required.
        cursor += 2 + usize::from(length);
    }
    true
}

/// Recognize a DNS candidate through the library parser, before outbound routing.
pub fn dns_udp(bytes: &[u8]) -> bool {
    hickory_proto::op::Message::from_vec(bytes).is_ok_and(|message| {
        message.message_type == hickory_proto::op::MessageType::Query
            && !message.queries.is_empty()
            && message.answers.is_empty()
            && message.authorities.is_empty()
    })
}

/// Recognize framed DNS, including oversized candidates that must not reach Proxy.
pub fn dns_tcp(prefix: &[u8]) -> bool {
    let Some(length) = prefix.get(..2) else {
        return false;
    };
    let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
    if length > crate::dns::MAX_DNS_BYTES {
        use hickory_proto::serialize::binary::BinDecodable;
        // Recognize an oversized DNS candidate through the library header, then
        // let the bounded DNS framer reject it instead of leaking it to Proxy.
        return prefix.get(2..14).is_some_and(|bytes| {
            hickory_proto::op::Header::from_bytes(bytes).is_ok_and(|header| {
                header.message_type == hickory_proto::op::MessageType::Query
                    && header.counts.queries > 0
                    && header.counts.answers == 0
                    && header.counts.authorities == 0
            })
        });
    }
    prefix.get(2..2 + length).is_some_and(dns_udp)
}

/// Replay an owned inspected prefix exactly once, including multiple DNS frames.
/// No reads/writes are retried on another outbound. Drop owns the client stream.
pub struct Replay<S> {
    prefix: io::Cursor<Vec<u8>>,
    stream: S,
}
impl<S> Replay<S> {
    /// Transfer ownership of the inspected bytes and stream; never replay elsewhere.
    pub fn new(prefix: Vec<u8>, stream: S) -> Self {
        Self {
            prefix: io::Cursor::new(prefix),
            stream,
        }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for Replay<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.prefix.position() < self.prefix.get_ref().len() as u64 {
            Pin::new(&mut self.prefix).poll_read(cx, buf)
        } else {
            Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Replay<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signature_windows_are_bounded_and_do_not_classify_arbitrary_short_data() {
        let tcp = b"\x13BitTorrent protocol";
        for length in 0..tcp.len() {
            assert!(!bittorrent_tcp(&tcp[..length]));
        }
        assert!(bittorrent_tcp(tcp));
        assert!(!bittorrent_tcp(b"\x12BitTorrent protocol"));
        let mut tracker = vec![
            0, 0, 4, 0x17, 0x27, 0x10, 0x19, 0x80, 0, 0, 0, 0, 1, 2, 3, 4,
        ];
        assert!(bittorrent_udp(&tracker));
        tracker[8] = 1;
        assert!(!bittorrent_udp(&tracker));
        let mut utp = vec![0; 20];
        utp[0] = 0x41;
        assert!(bittorrent_udp(&utp));
        utp[1] = 1;
        assert!(!bittorrent_udp(&utp));
        utp.extend([0, 0]);
        assert!(bittorrent_udp(&utp));
        utp[20] = 5;
        assert!(!bittorrent_udp(&utp));
        for length in 0..16 {
            assert!(!bittorrent_udp(&vec![0; length]));
        }
    }
}
