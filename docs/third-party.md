# Third-party provenance and license policy

## Kedra foundation

Source: <https://github.com/kedra-engine/kedra>, branch `main` inspected at
commit `62ae27a24af048efa0844dd66b3e349726d17d5b` on 2026-10-25.
Immutable reference:
<https://github.com/kedra-engine/kedra/tree/62ae27a24af048efa0844dd66b3e349726d17d5b>.

The root workspace declares MIT OR Apache-2.0 and includes both license texts.
GitHub's repository badge recognizing Apache alone is not the complete license
statement. Kedra's MIT notice says Copyright (c) 2026 Kedra contributors; it is
preserved in our MIT notice alongside attribution of the adapted material.

| Upstream material | Local adaptation |
| --- | --- |
| `AGENTS.md`, `CONTRIBUTING.md`, governance/security/quality docs | NM ownership, Linux privilege/secret boundaries, library-first policy, honest acceptance and owner approval |
| `.editorconfig`, `.gitattributes`, `.gitignore`, Cargo alias/lints | Lean Rust foundation, no engine dependencies or private metadata |
| `xtask/src/{cli,lib,output,architecture}.rs` | Explicit no-prompt checks, live retained logs and workspace dependency boundaries |
| CI workflows | Linux checks, owner-requested major action tags, inline required-result check and optional manual coverage; no publishing |
| `deny.toml`, `about.toml`, Markdown/secret settings | Fresh allowlist, no inherited Kedra exceptions, standard secret detectors |
| Documentation infrastructure | English-only Markdown; no translated page trees or locale-pair checker |
| `LICENSE-APACHE`, MIT permission/warranty text | Canonical license text and retained attribution |

These files are adapted, not an unmodified mirror; this document records the
modifications and origin. Kedra engine/game code, Bevy dependencies, assets,
private infrastructure, Figma identities and release credentials are not imported.
No Kedra affiliation, branding permission or product compatibility is implied.

## Deferred infrastructure

Kedra's static site/landing, object-storage hosting, native asset pipeline, UI
corpus, engine build/test applications and self-update/release/crate-publishing
workflows depend on a different product. They are not installed as misleading
placeholders. Suitable documentation-site, native UI, package and release pipelines
will be added when the [roadmap](roadmap.md) supplies actual consumers and authority.

## Dependencies and distribution

The COSMIC application-template localization API pattern was consulted at commit
`97ff759e658922d7f02e708b10cfda421352b100`:
<https://github.com/pop-os/cosmic-app-template/tree/97ff759e658922d7f02e708b10cfda421352b100>.
`src/i18n.rs`, `src/main.rs` and `i18n.toml` inform standard desktop-language
negotiation, embedded Fluent catalogs and fallback-loader initialization. The local
implementation adds project-specific typed error mapping, checked named arguments,
catalog contracts and independent locale tests; no template assets or translations
are imported. English/Russian application translations are project-owned. The
template uses a generated project-license placeholder, not a different license
grant for this workspace. The actual localization crates and their original license
scopes are recorded in [dependency review](dependency-review.md).

sing-box 1.12.0 was consulted as a behavioral reference for domain metadata,
ordered routing and FakeIP. No sing-box source or dependency is included. Its
GPL-3.0-or-later terms and additional name/association restriction differ from this
workspace's license. Versioned references and the independent implementation's
limits are in [ADR 0010](decisions/0010-tcp-domain-routing.md).
The complete IPv4 behavior and narrow independently written signature-classifier
exception are in [ADR 0020](decisions/0020-native-ipv4-source-policy.md) and
[ADR 0021](decisions/0021-bittorrent-signature-classifier.md). No sing-box source
was copied. The public RFC 9001 QUIC fixture retains its IETF Trust copyright and
Simplified BSD notice in [engine fixtures](../crates/engine/tests/fixtures/README.md).
The optional [isolated route comparison](research/sing-box-compatibility.md) executes
an upstream checksum-pinned v1.12.0 binary only as a disposable test peer. It is
downloaded separately under ignored `target/`, not installed, linked, vendored or
distributed with this project. Its upstream license/restrictions still apply; the
comparison script, fixtures and production correction are independently written.

NetworkManager 1.58.0's GPL-2.0-or-later VPN configuration consumer was consulted
only to verify public D-Bus route layout and never-default semantics. No source
was copied or linked into the workspace; the service independently emits standard
NM messages. References are in [ADR 0012](decisions/0012-connected-lan-bypass.md).

Tooling, shared profile/client dependencies and the libcosmic graph are resolved in
`Cargo.lock`. See [dependency status](dependency-review.md) for maintenance warnings
and remaining shipping notices; toolkit direction is in [ADR 0003](decisions/0003-cosmic-editor.md).
[Protocol research](research/rust-protocol-libraries.md) records candidates and
observed licenses, not a legal/security audit or approval to ship them.

For each adopted dependency, review exact source/version, features, maintenance,
advisories, license and transitive/native cost. Git dependencies use Cargo.lock's
resolved commits and locked builds. `deny.toml` owns repository/license checks;
exceptions need narrow scope and a rationale rather than blanket license allowances.
`about.toml` records accepted notice licenses but does not generate or verify a
release's notices by itself. Preserve native/data licenses as well as Rust notices.

Original license scopes, parent-license clarification hashes and remaining
distribution obligations are recorded in
[dependency review](dependency-review.md). The partial supplementary font/lwIP
texts under `packaging/licenses/` retain their upstream licenses, not the workspace
license. No passing license scan substitutes for complete shipping notices.
