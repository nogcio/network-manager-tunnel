# Documentation map

All project documentation is maintained in English.

## Product direction

- [Architecture and ownership](architecture.md)
- [Rust protocol-library research](research/rust-protocol-libraries.md)
- [REALITY registry incompatibility and alternative-library constraints](research/reality-feasibility.md)
- [NetworkManager and desktop research](research/networkmanager-desktops.md)
- [Roadmap, experiments and acceptance criteria](roadmap.md)
- [ADR 0001: foundation and boundaries](decisions/0001-foundation.md)
- [ADR 0002: library-first protocol implementation](decisions/0002-protocol-libraries.md)
- [ADR 0003: COSMIC-first profile editor](decisions/0003-cosmic-editor.md)
- [ADR 0004: maintained meow library fork](decisions/0004-maintained-meow-fork.md)
- [ADR 0005: NetworkManager Tunnel project name](decisions/0005-project-name.md)
- [ADR 0006: experimental NM runtime and packet adaptation](decisions/0006-experimental-nm-runtime.md)
- [ADR 0007: explicit NM storage and COSMIC connection control](decisions/0007-nm-profile-control.md)
- [ADR 0008: standard Arch/AUR distribution](decisions/0008-local-arch-installer.md)
- [ADR 0009: practical locked dependency checks](decisions/0009-locked-git-source-admission.md)
- [COSMIC subscription UI](../frontends/cosmic/README.md)
- [Experimental end-user workflow](user-guide.md)
- [Arch installation and AUR direction](installation.md)
- [Subscription formats and fetching](../crates/subscription/README.md)
- [Pinned stream engine and ownership contract](../crates/engine/README.md)
- [Experimental NM service, runtime policy and VM acceptance](../crates/nm-service/README.md)

## Engineering

- [Quality and test ownership](quality.md)
- [CI and hosting boundaries](ci.md)
- [Upstream provenance and license review](third-party.md)
- [Dependency status and original license evidence](dependency-review.md)
- [Contributing](../CONTRIBUTING.md) and [AI instructions](../AGENTS.md)

The [project README](../README.md) owns current implementation status.
Research records historical source inspection, not compatibility or security
certification. Source publication is distinct from supported binary distribution
and native desktop acceptance.
