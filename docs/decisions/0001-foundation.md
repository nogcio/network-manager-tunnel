# ADR 0001: NetworkManager-first foundation

Status: accepted direction. Date: 2026-10-25. Current implementation status is
maintained in the [project README](../../README.md).

## Context

The project needs a Rust multi-protocol client integrated into NetworkManager,
with separate KDE, GTK and COSMIC interfaces and no external proxy-core process.
Kedra provides suitable contributor rules and engineering infrastructure, not a
VPN runtime. Its engine-specific dependencies/deployment must not be inherited.

## Decision

- Adapt Kedra's instructions, xtask checks, DAG/file policy, fail-closed CI,
  license/secret scanning and factual English documentation.
- Preserve source revision/license attribution in `docs/third-party.md`.
- Keep NetworkManager authoritative for profiles/activation/system IP configuration.
- Separate model, engine, NM integration, client and desktop responsibilities.
- Maintain documentation in English only, without translated page trees.
- Forbid unsafe workspace Rust initially. FFI needs an explicit future decision.
- Do not create product stubs or enable release/deploy workflows before real inputs exist.

## Alternatives and consequences

A universal GUI would reduce UI work but not provide the requested desktop-native
integration. A separate always-running controller would duplicate NM ownership.
Copying Kedra wholesale would import Bevy, assets, unrelated exceptions and private
hosting assumptions. Adapting the small relevant mechanisms is more maintainable.

The foundation checks can pass without a VPN. Real peer, NM VM and desktop
acceptance must be added with their respective implementations, not inferred from CI.
