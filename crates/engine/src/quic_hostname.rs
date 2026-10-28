//! QUIC Initial parsing/decryption/reassembly is owned by quic-parser, not this adapter.
use quic_parser::{
    CryptoFrame, decrypt_initial, parse_crypto_frames, parse_initial, reassemble_crypto_stream,
};

/// Bounded, flow-owned QUIC v1/v2 hostname inspection. Holds at most 8 KiB of
/// CRYPTO data from one DCID and four datagrams. No sockets, server handshake,
/// TLS termination or fallback. Drop/cancellation releases all fragments; Debug
/// never exposes connection IDs, hostnames or handshake bytes. Unknown versions,
/// malformed packets, limits and incomplete data produce no hostname.
#[derive(Default)]
pub struct QuicHostname {
    dcid: Option<Vec<u8>>,
    frames: Vec<CryptoFrame>,
    datagrams: usize,
    bytes: usize,
}
impl std::fmt::Debug for QuicHostname {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("QuicHostname([redacted])")
    }
}
impl QuicHostname {
    /// Whether this datagram begins with a supported Initial header. Recognition
    /// alone is not authentication or a domain decision.
    pub fn initial(bytes: &[u8]) -> bool {
        parse_initial(bytes).is_ok_and(|header| matches!(header.version, 1 | 0x6b33_43cf))
    }
    /// Inspect one original datagram without modifying it. Callers retain/replay
    /// every datagram once and bound the collection window externally.
    pub fn inspect(&mut self, mut bytes: &[u8]) -> Option<String> {
        self.datagrams += 1;
        if self.datagrams > 4 || bytes.len() > 65507 {
            return None;
        }
        for _ in 0..8 {
            if bytes.is_empty() {
                break;
            }
            let header = parse_initial(bytes).ok()?;
            if self.dcid.as_deref().is_some_and(|dcid| dcid != header.dcid) {
                return None;
            }
            if self.dcid.is_none() {
                self.dcid = Some(header.dcid.to_vec());
            }
            let length = header
                .header_bytes
                .len()
                .checked_add(header.payload.len())?;
            if length == 0 {
                return None;
            }
            let plaintext = decrypt_initial(&header).ok()?;
            let frames = parse_crypto_frames(&plaintext).ok()?;
            if !self.extend_frames(frames) {
                return None;
            }
            let hello = reassemble_crypto_stream(&self.frames);
            if hello.len() >= 4 {
                // Adapt the library-reassembled TLS handshake to the existing
                // library sniffer's record input; no TLS fields are parsed here.
                let mut record = vec![22, 3, 3];
                record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
                record.extend(hello);
                if let Some(name) = meow_common::sniffer::sniff_tls(&record)
                    .and_then(|name| nm_tunnel_profile::canonical_domain(&name))
                {
                    return Some(name);
                }
            }
            bytes = bytes.get(length..)?;
        }
        None
    }

    // Preflight a whole library-decoded batch: rejection cannot leave a partial
    // new fragment set that a later datagram could turn into a hostname.
    fn extend_frames(&mut self, frames: Vec<CryptoFrame>) -> bool {
        let bytes = frames.iter().try_fold(self.bytes, |sum, frame| {
            if frame.offset.saturating_add(frame.data.len() as u64) > 8192 {
                return None;
            }
            sum.checked_add(frame.data.len())
                .filter(|bytes| *bytes <= 8192)
        });
        let Some(bytes) = bytes else {
            return false;
        };
        if self.frames.len().saturating_add(frames.len()) > 128 {
            return false;
        }
        self.bytes = bytes;
        self.frames.extend(frames);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment_batches_reject_atomically_at_byte_offset_and_count_boundaries() {
        let mut inspection = QuicHostname::default();
        assert!(inspection.extend_frames(vec![CryptoFrame {
            offset: 4,
            data: vec![1; 4]
        }]));
        for rejected in [
            vec![
                CryptoFrame {
                    offset: 0,
                    data: vec![2],
                },
                CryptoFrame {
                    offset: 8192,
                    data: vec![3],
                },
            ],
            vec![CryptoFrame {
                offset: u64::MAX,
                data: vec![3],
            }],
            vec![CryptoFrame {
                offset: 0,
                data: vec![3; 8192],
            }],
            vec![
                CryptoFrame {
                    offset: 0,
                    data: vec![]
                };
                128
            ],
        ] {
            assert!(!inspection.extend_frames(rejected));
            assert_eq!(inspection.bytes, 4);
            assert_eq!(
                inspection.frames,
                [CryptoFrame {
                    offset: 4,
                    data: vec![1; 4]
                }]
            );
        }
        assert!(inspection.extend_frames(vec![CryptoFrame {
            offset: 0,
            data: vec![2; 4]
        }]));
        assert_eq!(
            reassemble_crypto_stream(&inspection.frames),
            [vec![2; 4], vec![1; 4]].concat()
        );
        assert!(inspection.extend_frames(vec![CryptoFrame {
            offset: 8,
            data: vec![3; 8184]
        }]));
        assert_eq!(inspection.bytes, 8192);
        assert!(!inspection.extend_frames(vec![CryptoFrame {
            offset: 0,
            data: vec![0]
        }]));
    }
}
