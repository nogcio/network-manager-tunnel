# Rust protocol-library research

Inspection date: 2026-10-25. Versions below are observed registry releases, not
workspace resolutions. Moving Git branches are discovery references, not immutable
build inputs. Re-inspect exact releases and their dependency graph before adoption.
This historical inventory informed library selection. The experimental engine now
uses the maintained [meow fork](../decisions/0004-maintained-meow-fork.md).
[REALITY feasibility](reality-feasibility.md) explains the registry-release
incompatibility, fork fix and alternative-library constraints.

## Primary candidate: meow-rs libraries

Upstream: <https://github.com/meow-rs/meow-rs>. Registry metadata for
[`meow-proxy 0.26.1`](https://crates.io/crates/meow-proxy/0.26.1) and
[`meow-transport 0.26.1`](https://crates.io/crates/meow-transport/0.26.1) declares MIT.

| Component | Inspected capability | Adoption caveat |
| --- | --- | --- |
| `meow-proxy` | Public `VlessAdapter`, `VlessFlow`, Trojan, Shadowsocks, VMess, Hysteria2, AnyTLS, Snell, HTTP/SOCKS adapters | Has `meow-common`, `meow-dns` and transport dependencies; not a zero-cost wire-codec-only crate |
| `meow-transport` | TLS, REALITY, WS, gRPC, H2, HTTPUpgrade, XHTTP, ShadowTLS | Ordinary TLS uses BoringSSL; review native build and shipping obligations |
| Vision | Implementation and directional raw passthrough hooks | Keep compatible transport/proxy versions; generic byte-stream abstraction alone is insufficient |
| REALITY | ClientHello builder, authentication and record-layer code | Security-sensitive in-tree TLS logic requires review, not assumed upstream rustls coverage |
| Peer tests | Test source uses official pinned Xray server for VMess, VLESS encryption, Vision and REALITY profiles | Presence of tests is not proof that they pass on our platform/configuration |

Evidence inspected:

- [Workspace manifest](https://github.com/meow-rs/meow-rs/blob/main/Cargo.toml)
- [Proxy features/dependencies](https://github.com/meow-rs/meow-rs/blob/main/crates/meow-proxy/Cargo.toml)
- [Public proxy API](https://github.com/meow-rs/meow-rs/blob/main/crates/meow-proxy/src/lib.rs)
- [Transport features/dependencies](https://github.com/meow-rs/meow-rs/blob/main/crates/meow-transport/Cargo.toml)
- [Transport API and passthrough hooks](https://github.com/meow-rs/meow-rs/blob/main/crates/meow-transport/src/lib.rs)
- [REALITY/Vision peer-test source](https://github.com/meow-rs/meow-rs/blob/main/crates/meow-proxy/tests/xray_server_docker_integration.rs)

The `meow-transport` manifest describes a leaf crate without other `meow-*`
dependencies. `meow-proxy` publicly exposes client adapters. This supports the
library-first approach without launching the meow application. TUIC is not listed
in the inspected meow proxy feature set; do not claim it is covered by this choice.

Upstream has an older draft REALITY design/test document. Its historical scope
must not override the current manifest/source or be treated as current acceptance.

## Other candidates

| Project/crate | Observed version/license | Finding and limitation |
| --- | --- | --- |
| [`shadowsocks`](https://crates.io/crates/shadowsocks/1.25.0) | 1.25.0, MIT | Independent library from shadowsocks-rust; AEAD/2022 support depends on selected features |
| [`hysteria2`](https://crates.io/crates/hysteria2/0.1.6) | 0.1.6, MulanPSL-2.0 | Client library exporting `HysteriaClient`, `connect`, `DuplexStream`; review UDP/extensions and license before admission |
| [`anytls`](https://crates.io/crates/anytls/0.5.3) | 0.5.3, MIT | ssrlive implementation; do not confuse with `anytls-rs` or the meow fork |
| [`Itsusinn/tuic`](https://github.com/Itsusinn/tuic) | Git candidate, not locked | clash-rs uses `tuic-core` tagged v1.8.5; a tag is not our reproducible source pin; license/API review remains open |
| [`shadow-tls`](https://github.com/ihciah/shadow-tls) | Registry release observed: 0.2.20 | Original Rust implementation; registry freshness/API fit need review; meow has a separate transport implementation |
| [`vpn-link-serde`](https://crates.io/crates/vpn-link-serde/0.1.5) | 0.1.5 | Link parser/serializer, not protocol transport; inspect parsing/security limits before reuse |
| [`netstack-smoltcp`](https://github.com/automesh-network/netstack-smoltcp) | Inspected registry release: 0.2.4, MIT OR Apache-2.0 | Rejected after finding an unsound `Send` implementation; see [runtime decision](../decisions/0006-experimental-nm-runtime.md) |

## Broader Rust engines, not automatically production dependencies

- [`clash-rs`](https://github.com/Watfaq/clash-rs): repository metadata reports
  Apache-2.0. The inspected README/source covers VLESS/REALITY/Vision, TUIC,
  Hysteria2, AnyTLS, SS, Trojan, VMess, SSH and more. Has `clash-lib`, DNS and
  netstack components, but `clash-lib` also pulls substantial application policy,
  API/dashboard and configuration infrastructure. Useful reference/alternative;
  not selected as the application's wholesale core.
- [`shoes`](https://github.com/cfal/shoes): manifest declares MIT and library
  outputs; broad protocol support including REALITY/Vision. Current source has
  fork patches for rustls and other dependencies. Library isolation and published
  release parity need review; do not assume a crates.io dependency applies root patches.
- [`Corduit`](https://github.com/blueokanna/Corduit): synchronous library with
  broad protocol claims and in-tree TLS/QUIC logic. Additional license conditions
  and thread-per-relay tradeoffs need review. Not selected.
- [`rustls-reality`](https://github.com/undead-undead/rustls-reality) and
  [`reality-rs`](https://github.com/ssrlive/reality-rs): specialized forks/implementations,
  not proof that official rustls exposes a complete REALITY client API.
- [`leaf`](https://github.com/eycorsican/leaf): Rust proxy framework, not the
  unrelated crates.io `leaf` machine-learning package. Not evaluated deeply enough
  to assert current protocol parity.

## What is and is not established

Established by source/metadata inspection: reusable Rust implementations exist
for the main desired proxy protocols, including client-side REALITY and Vision.
The project should start by validating reuse rather than rewriting protocols.

Not established: parity with every sing-box feature, browser fingerprint fidelity,
complete UDP/XUDP/mux behavior, current peer compatibility, production security,
performance or native packaging suitability. Protocol names alone do not establish
extension/transport compatibility. Current consumers and behavior are documented in
the [engine contract](../../crates/engine/README.md), not this candidate inventory.

Future candidates need a concrete consumer and evaluation of their socket/dialer
boundary, UDP/XUDP behavior, cancellation, half-close and buffering. Use isolated
pinned peers and synthetic credentials; inspect native dependencies, advisories,
licenses and resulting cost. General test and dependency policy lives in
[quality](../quality.md).
