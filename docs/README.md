# Documentation map

All project documentation is maintained in English.

## Product direction

- [Architecture and ownership](architecture.md)
- [Rust protocol-library research](research/rust-protocol-libraries.md)
- [REALITY registry incompatibility and alternative-library constraints](research/reality-feasibility.md)
- [sing-box policy compatibility and isolated route comparison](research/sing-box-compatibility.md)
- [NetworkManager and desktop research](research/networkmanager-desktops.md)
- [Roadmap, experiments and acceptance criteria](roadmap.md)
- [Offline NetworkManager VM acceptance](testing/vm-acceptance.md)
- [ADR 0001: foundation and boundaries](decisions/0001-foundation.md)
- [ADR 0002: library-first protocol implementation](decisions/0002-protocol-libraries.md)
- [ADR 0003: COSMIC-first profile editor](decisions/0003-cosmic-editor.md)
- [ADR 0004: maintained meow library fork](decisions/0004-maintained-meow-fork.md)
- [ADR 0005: NetworkManager Tunnel project name](decisions/0005-project-name.md)
- [ADR 0006: experimental NM runtime and packet adaptation](decisions/0006-experimental-nm-runtime.md)
- [ADR 0007: explicit NM storage and COSMIC connection control](decisions/0007-nm-profile-control.md)
- [ADR 0008: standard Arch/AUR distribution](decisions/0008-local-arch-installer.md)
- [ADR 0009: practical locked dependency checks](decisions/0009-locked-git-source-admission.md)
- [ADR 0010: TCP hostname rules and bounded direct authority](decisions/0010-tcp-domain-routing.md)
- [ADR 0011: per-profile DNS overrides and bounded uplink forwarding](decisions/0011-profile-dns-overrides.md)
- [ADR 0012: connected RFC1918 LAN bypass](decisions/0012-connected-lan-bypass.md)
- [ADR 0013: bounded TUN DNS interception](decisions/0013-tun-dns-interception.md)
- [ADR 0014: LAN relays after DNS interception](decisions/0014-intercepted-lan-relays.md)
- [ADR 0015: root-owned endpoint and Direct relays](decisions/0015-root-owned-endpoint-relays.md)
- [ADR 0016: persistent IPv4 FakeIP identities](decisions/0016-persistent-ipv4-fakeip.md)
- [ADR 0017: IPv4-only first version](decisions/0017-ipv4-only-first-version.md)
- [ADR 0018: checked saved-profile replacement](decisions/0018-checked-profile-replacement.md)
- [ADR 0019: foreign client integration exclusions](decisions/0019-source-client-integration-exclusions.md)
- [ADR 0020: bounded native IPv4 source policy](decisions/0020-native-ipv4-source-policy.md)
- [ADR 0021: narrow BitTorrent signatures](decisions/0021-bittorrent-signature-classifier.md)
- [ADR 0022: automatic session-scoped guards](decisions/0022-session-scoped-guards.md)
- [ADR 0023: FakeIP state under NM confinement](decisions/0023-fakeip-service-state.md)
- [ADR 0024: all-RFC1918 bypass with DNS precedence](decisions/0024-private-ipv4-bypass.md)
- [ADR 0025: shared contracts and runtime ownership](decisions/0025-runtime-contract-ownership.md)
- [ADR 0026: automatic recovery and ordinary-network restoration](decisions/0026-automatic-session-recovery.md)
- [ADR 0027: COSMIC profile editing and session source management](decisions/0027-cosmic-profile-and-source-management.md)
- [ADR 0028: subscription URLs in Secret Service](decisions/0028-subscription-url-secret-service.md)
- [ADR 0029: shared data plane and platform capabilities](decisions/0029-shared-dataplane.md)
- [ADR 0030: session-preserving package updates](decisions/0030-session-preserving-package-updates.md)
- [ADR 0031: offline VM acceptance](decisions/0031-offline-vm-acceptance.md)
- [ADR 0032: destination-free readiness](decisions/0032-destination-free-readiness.md)
- [ADR 0033: persistent network lifetime and NM agents](decisions/0033-persistent-network-lifetime-and-nm-agents.md)
- [ADR 0034: protection until explicit Disconnect](decisions/0034-explicit-disconnect-protection.md)
- [COSMIC subscription UI](../frontends/cosmic/README.md)
- [Experimental end-user workflow](user-guide.md)
- [Arch installation and AUR direction](installation.md)
- [Subscription formats and fetching](../crates/subscription/README.md)
- [Pinned stream engine and ownership contract](../crates/engine/README.md)
- [Shared packet/flow data plane](../crates/dataplane/README.md)
- [Experimental NM service, runtime policy and VM acceptance](../crates/nm-service/README.md)
- [Shared NM settings contract](../crates/nm-schema/README.md)

## Engineering

- [Quality and test ownership](quality.md)
- [Production security review and findings](security-review.md)
- [CI and hosting boundaries](ci.md)
- [Upstream provenance and license review](third-party.md)
- [Dependency status and original license evidence](dependency-review.md)
- [Contributing](../CONTRIBUTING.md) and [AI instructions](../AGENTS.md)

The [project README](../README.md) owns current implementation status.
Research records historical source inspection, not compatibility or security
certification. Source publication is distinct from supported binary distribution
and native desktop acceptance.
