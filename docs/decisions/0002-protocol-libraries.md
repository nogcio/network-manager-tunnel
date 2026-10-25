# ADR 0002: Library-first protocols

Status: accepted strategy; library selection refined by ADR 0004.
Date: 2026-10-25.

[REALITY feasibility](../research/reality-feasibility.md) records the registry-release
incompatibility and alternative API/PQ constraints that motivated the maintained
`nogcio` fork in [ADR 0004](0004-maintained-meow-fork.md). The experimental engine
uses that fork; library selection does not justify silently dropping fingerprint settings.

## Context

Reusable Rust protocol implementations exist, including client VLESS/REALITY/Vision.
Reimplementing security-sensitive TLS/QUIC/proxy behavior before evaluating them
would add unnecessary risk. External proxy-core processes are outside product scope.

## Decision

Evaluate `meow-proxy` and `meow-transport` as the first library candidates. Reuse
their adapters/transports without launching meow's daemon or adopting its entire
configuration, rule engine, UI, REST API or route manager. A Rust application may
use BoringSSL/native dependencies; pure-Rust transitive code is not required.

Keep a narrow project-owned boundary for lifecycle, stream/datagram forwarding,
configuration validation and host-controlled socket bypass. Do not design a generic
dynamic plugin ABI. Add a protocol only with a concrete consumer and acceptance.

Exact versions, features, source identities, licenses, dialer behavior, UDP/XUDP,
native build and interoperability need review before adding production dependencies.
Research versions are not Cargo pins. No complete sing-box feature parity is claimed.

## Alternatives and consequences

`clash-lib` or `shoes` may be alternatives but bring broader machinery or fork
patches. Separate libraries such as `shadowsocks`, `anytls` and a Git `tuic-core`
may fit individual needs. Rewriting protocols is a last resort with documented
evidence that reuse cannot meet a required contract.

Library reuse reduces code ownership, not our responsibility for security and
compatibility. Independent peers are allowed as isolated test fixtures, not runtime
dependencies. Future updates must keep Vision/transport behavior compatible.
