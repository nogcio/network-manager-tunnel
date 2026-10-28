# ADR 0019: Explicit exclusions for foreign client integration

Status: owner-approved import boundary; bounded translation implemented by ADR 0020.
Date: 2026-10-26.

## Decision

The owner explicitly permits excluding a complete source's foreign client
integration, with a warning before saving. NetworkManager supplies tunnel/profile/
activation ownership and COSMIC supplies local control. Do not start source-defined
mixed listeners, Clash API/controllers, downloaded web UI or another tunnel manager.
Do not reuse source cache file paths or fetch its UI/download URLs.

This exception does not authorize dropping DNS/FakeIP behavior, ordered routing,
protocol blocking, endpoint security, leak protection or other networking policy.
The [IPv4-only exception](0017-ipv4-only-first-version.md) remains separate.

The complete importer must validate known source structures before excluding client
settings and disclose the exclusions before Add or replacement confirmation.
Unknown fields or settings with unpreserved networking/security effects still
reject; do not treat an entire arbitrary inbound/experimental object as harmless.
In particular, source tunnel routing, sniffing, MTU and DNS controls must be mapped
to checked native semantics or rejected, not hidden behind a listener warning.

Source persistence may express more than an arbitrary path: required durable
FakeIP ownership is implemented by our root-owned journal, not simply discarded
with the foreign cache configuration. Controller-based selectors must map to
explicit native profile selection; the exception is not permission to silently
choose another outbound or lose selection/routing semantics.

## Current admission and implementation limits

The import page discloses this boundary. The bounded native implementation is in
[ADR 0020](0020-native-ipv4-source-policy.md); no exclusion warning alone makes an
arbitrary source admitted. The owner separately approved only the narrow signature
classifier in [ADR 0021](0021-bittorrent-signature-classifier.md), not a general
handwritten protocol-parser exception. Broader source non-public IP matching and
resolver-policy translation remain separate from legacy connected RFC1918 bypass
and DNS overrides. Native/security acceptance is still required before installation.

No source file/path/URL is executed or persisted by this decision. No installed
package, service, profile, route, DNS or firewall is changed by ordinary checks.
