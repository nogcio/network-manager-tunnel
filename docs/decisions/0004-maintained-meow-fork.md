# ADR 0004: Maintained meow library fork

Status: accepted; maintained fork consumed by the experimental engine.
Date: 2026-10-25.

## Context

The registry `meow-transport 0.26.1` REALITY client fails against the pinned current
Xray 26.10.21 fixture because it does not implement its declared hybrid exchange option.
Alternative inspection and isolated shoes feasibility are recorded in
[REALITY research](../research/reality-feasibility.md). Shoes is not a drop-in narrow
library API and does not expose the required fingerprint selector.

## Decision

Maintain [nogcio/meow-rs](https://github.com/nogcio/meow-rs), a fork of
[meow-rs/meow-rs](https://github.com/meow-rs/meow-rs), for the required library fixes.
The initial fork base is `3f485df79add3fc4e6ea03159bb49cc8b51ce2b4` (version 0.26.1).
Keep upstream provenance and license notices. Do not replace its libraries with
an external daemon, adopt its route manager, or copy protocol implementations into
the NM workspace.

The first change implements the existing optional `support_x25519_mlkem768` setting:

- Use BoringSSL's maintained safe ML-KEM API, not a handwritten primitive.
- Preserve X25519 authentication/share ownership, full ClientHello authentication,
  profile selection, SNI, ALPN and fail-closed malformed/unoffered group handling.
- Preserve classical-only wire behavior when the option is disabled. Enabling the
  option is an explicit hybrid overlay on historical profile tables, not a claim of
  an exact contemporary browser fingerprint.
- Verify current-peer payloads and negative authentication plus actual directional
  Vision DIRECT with synthetic inner TLS, inside an isolated network namespace.

Use an explicit full commit SHA from the fork for future Cargo dependencies. All
selected meow packages must resolve to the same reviewed fork revision; check the
actual source/feature graph for registry duplicates. Never substitute a moving
branch, a machine-local path or the known-incompatible fork base as a production pin.
The `nm-tunnel-engine` stream adapter is the concrete workspace consumer. Its API
wraps an explicitly supplied endpoint socket; it does not own socket creation,
resolution, NetworkManager or routes. The engine's synthetic probe exercises the
profile-to-library adapter without launching the meow application.

## Implementation boundary

The experimental engine consumes the fixed fork as libraries. Cargo.lock records
resolved commits; current features and ownership are documented in the
[engine contract](../../crates/engine/README.md). There is no second source-approval
gate. [Dependency review](../dependency-review.md) retains original license evidence
and remaining binary distribution obligations. A passing isolated protocol fixture
does not establish production VPN safety or desktop acceptance; outstanding product
work lives in the [roadmap](../roadmap.md).

## Consequences

We own rebasing, regression tests, dependency updates and reviewing upstream changes
while carrying the patch. Prefer small upstream-compatible fixes and eventual upstream
convergence. Any new incompatibility, broader fork change or replacement dependency
must be presented to the owner before adoption rather than silently changing semantics.
