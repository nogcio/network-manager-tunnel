# ADR 0021: Narrow BitTorrent classification exception

Status: owner explicitly approved the narrow exception; implemented experimentally.

The full source route contains a BitTorrent block before domain/private-IP actions.
The pinned protocol libraries have no equivalent signature classifier. Importing
a torrent client would add an unrelated protocol stack and still not reproduce
the source's short sniff window. The owner authorized only bounded signature
classification, not a handwritten BitTorrent parser/client or network stack.

`crates/nm-service/src/inspection.rs` checks the TCP peer-handshake prefix and UDP
tracker-connect/uTP signature window. Reads are bounds-checked; extension traversal
advances monotonically within the already bounded datagram. Recognized packets are
blocked before any outbound grant. Malformed/short signatures are not classified.
Tests cover truncation, discriminators and extension boundaries, without upstream
client/crypto test duplication. This is heuristic protocol identification, not a
claim to block encrypted/obfuscated BitTorrent or prevent signature false positives.

No upstream implementation was copied. Behavioral references are
[sing-box v1.12.0](https://github.com/SagerNet/sing-box/tree/v1.12.0/common/sniff),
[BEP 3](https://www.bittorrent.org/beps/bep_0003.html),
[BEP 15](https://www.bittorrent.org/beps/bep_0015.html) and
[BEP 29](https://www.bittorrent.org/beps/bep_0029.html).
DNS, JSON, TLS, HTTP, QUIC, VLESS, REALITY and Vision remain library-owned.
Expanding this exception requires another explicit owner decision.
