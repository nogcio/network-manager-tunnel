# REALITY backend feasibility

Source inspection: 2026-10-25. The registry-release incompatibility below motivated
the maintained [meow fork](../decisions/0004-maintained-meow-fork.md), now consumed
by the experimental engine. Inspection identities are historical evidence, not
workspace resolutions; Cargo.lock owns those. Synthetic peer evidence is distinct
from live-provider compatibility and production acceptance.

## Required library boundary

A candidate must authenticate REALITY peers, preserve requested fingerprints,
accept host-controlled upstream sockets, and support Vision's directional raw bypass
without dropping buffered TLS data. A successful handshake alone does not prove
payload forwarding, Vision DIRECT, UDP, cancellation or NetworkManager integration.
Unknown fingerprints and unsupported combinations must fail rather than silently
change the wire protocol. No whole proxy application or external core is adopted.

## Registry incompatibility and selected fix

The isolated registry experiment used `meow-proxy =0.26.1` with `vless,vless-vision`
and `meow-transport =0.26.1` with `tls,ws,reality`, both without defaults.
Against pinned Xray 26.10.21, WebSocket/TLS payloads worked but REALITY authentication
failed. The [server source][server] requires an `X25519MLKEM768` key share before
optional `X25519`. The meow release declares `support_x25519_mlkem768` but does not
use it to generate that share. [Upstream meow][meow] at
`3f485df79add3fc4e6ea03159bb49cc8b51ce2b4` had the same issue. This is a
version-specific incompatibility, not a claim about every deployed REALITY server.

The historical Xray Linux x86-64 fixture archive had SHA-256
`0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978`.
It was used only as an isolated synthetic peer, not a production backend.

The selected fork implements the option with BoringSSL's safe ML-KEM API and enables
`boring/mlkem` through the REALITY feature. Its pinned
`scripts/check_reality_peer.py` regression checks positive payloads, negative
authentication and directional Vision DIRECT against an isolated pinned peer with
synthetic inner TLS. The engine also exercises its supplied-socket profile adapter
independently. These are not host VPN or browser-fingerprint certifications.
The explicit PQ overlay on historical browser tables does not establish exact
contemporary browser fingerprint fidelity.

## Alternative library constraints

The following source snapshots explain why an alternative was not a drop-in
replacement. Reinspect before adoption; protocol names and generic TLS PQ support
do not establish REALITY interoperability.

| Candidate and inspected revision | Finding and library constraint |
| --- | --- |
| [cfal/shoes][shoes], `b0b30617a2b570792f2aef0bedcd91136d3dedcc` | MIT; hybrid ML-KEM and Vision payload feasibility in isolated application probes. REALITY, TCP and crypto modules are private; config exposes no browser-fingerprint selector. The probes did not establish Vision DIRECT or host-controlled socket injection. |
| [ssrlive/reality-rs][ssrlive], `e71b6c20b0860d9fa9589862e81fa8869ed4fa7a` | `Apache-2.0 OR ISC OR MIT`; public client builders and browser profiles. The inspected REALITY provider selects only X25519 and can fall back to ordinary certificate verification; adoption would need strict REALITY authentication and negative tests. |
| [undead-undead/rustls-reality][undead], `cdae8d922a94ef8896df21da1eb13e6461315783` | Inspected modifications are in the server path; no corresponding client implementation established. |
| [Watfaq/rustls][watfaq], `63d10d50f2308478f366f14f9f81e378f5911e3c` | Public REALITY client config, independent of clash-lib, but explicitly constructs a lone X25519 key share. General TLS PQ defaults do not fix that path. |

Shoes pins a [rustls fork][cfal-rustls] at
`d17d0fc304c03fe6e2c96ade6cd39c33b951c3af` and patches BLAKE3, H3, nix and smoltcp.
Cargo does not propagate dependency-root patches into a consuming workspace;
importing its library is not equivalent to adopting a narrow reviewed transport.
The ssrlive fork uses `rustls 0.24.0-dev.2`, a separate AWS-LC provider and
synchronous rustls-util streams. Ordinary tokio-rustls 0.26 compatibility cannot
be assumed. No alternative has passed project-owned library-boundary acceptance.

[server]: https://github.com/XTLS/REALITY/blob/83f621788ca8/tls.go
[meow]: https://github.com/meow-rs/meow-rs/tree/3f485df79add3fc4e6ea03159bb49cc8b51ce2b4/crates/meow-transport/src
[shoes]: https://github.com/cfal/shoes/tree/b0b30617a2b570792f2aef0bedcd91136d3dedcc/src/reality
[ssrlive]: https://github.com/ssrlive/reality-rs/blob/e71b6c20b0860d9fa9589862e81fa8869ed4fa7a/rustls-aws-lc-rs/src/reality.rs
[undead]: https://github.com/undead-undead/rustls-reality/tree/cdae8d922a94ef8896df21da1eb13e6461315783/rustls/src
[watfaq]: https://github.com/Watfaq/rustls/blob/63d10d50f2308478f366f14f9f81e378f5911e3c/rustls/src/client/reality.rs
[cfal-rustls]: https://github.com/cfal/rustls/tree/d17d0fc304c03fe6e2c96ade6cd39c33b951c3af
