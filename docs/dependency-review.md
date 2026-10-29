# Dependency status and license evidence

## Explicit protection release: system Polkit

The recovery helper's explicit Disconnect requires the existing NetworkManager
`org.freedesktop.NetworkManager.network-control` Polkit permission. The Arch recipe
therefore declares `polkit` as a runtime dependency instead of relying on NM's
optional dependency. Reviewed local package: polkit 128-1, upstream
<https://github.com/polkit-org/polkit>, LGPL-2.0-or-later, about 2 MiB installed.
It is a separately managed system service, not bundled Rust/native code. The
maintained authorization boundary resolves a `system-bus-name` subject; there is no
application-owned password store or caller-supplied numeric PID. No new Rust crate,
feature or lockfile edge is introduced: existing locked zbus handles the D-Bus call.
Polkit absence/refusal fails closed; native prompt acceptance and independent
security review remain required.

The standard audit, `cargo deny --locked check --warn unmaintained`, passes with
maintenance and duplicate-version warnings. Re-run it against Cargo.lock for
authoritative diagnostics; generated output belongs under `target/`.
Cargo.lock is the single resolved version/commit record, not a source-approval gate.
Commands and dependency policy live in [quality](quality.md).

Publishing this project's source does not claim a supported VPN or complete binary
distribution compliance. The AUR recipe generates notices for both executables
with cargo-about and ships supplementary font/lwIP licenses and covered-source
instructions. Review the actual Rust/native/data/asset coverage before distributing
packages. This document retains evidence and limitations, not a second shipping
inventory or a legal certification.

## Maintenance and native cost

The VM-only standard NM agent fixture directly uses the already resolved crates.io
Tokio 1.54.1 `signal` feature as an nm-client dev dependency, to unregister cleanly
on owned SIGTERM. Tokio is MIT and actively maintained; Cargo.lock records its
registry checksum and existing signal-hook-registry 1.4.8 resolution. This exposes
no production API, new crate version or linked native library. Signal delivery
remains process-local and the VM runner externally bounds fixture teardown.

Source DoH directly consumes the already locked crates.io `hyper =1.12.0`
(`client`, `http1`, defaults off), `hyper-util =0.1.21` (`tokio`, defaults off),
`http-body-util =0.1.5` and `bytes =1.12.1` (defaults off). These MIT libraries
are maintained HTTP/body/buffer infrastructure already used by subscription HTTPS;
their concrete new consumer is the engine's single-exchange HTTP adapter over the
supervisor's approved verified TLS stream. Cargo.lock retains their registry archive
checksums and exact resolutions; no new package version or linked native library is
added. Workspace feature unification still includes the existing HTTP/2 graph,
but DoH itself selects HTTP/1.1 and creates no socket, connection pool or background
driver. Existing meow/BoringSSL owns TLS, not a second TLS backend. HTTP parsing now
runs in privileged source DNS, so dependency audits do not replace independent
security review of the bounded response, certificate and cancellation boundaries.
Non-200, compression, unrelated DNS responses and token-bearing settings reject
without retries/fallback. See [ADR 0020](decisions/0020-native-ipv4-source-policy.md).

COSMIC localization directly consumes the already locked crates.io `i18n-embed`
0.16.0 (`fluent-system`, `desktop-requester`, default `rust-embed`), `i18n-embed-fl`
0.10.1 and `rust-embed` 8.13.0, all MIT. The actual consumer is embedded en/ru UI
resources, desktop locale negotiation and compile-time message/argument validation.
These are the pinned libcosmic graph's existing maintained localization families;
no new runtime source package, linked native library, external translation service,
root process or persistent settings store is introduced. Existing `fluent-syntax`
0.12.0 (Apache-2.0 OR MIT) is a direct dev-only consumer for catalog syntax, unique
IDs and named-argument parity, rather than an application-written Fluent parser.
Cargo.lock is authoritative for their exact resolved sources/checksums; the standard
locked advisory/license/source audit remains required.

The COSMIC source persistence consumer uses crates.io `secret-service =5.2.0`,
defaults disabled, with `rt-tokio-crypto-rust` (`rt-tokio` and `crypto-rust`). It is
MIT OR Apache-2.0; the published archive checksum is
`5107b24b91445dd2aa449a258a1807b63240942157292354dc5bfdbeb8bc6db8`.
Versioned upstream source is [secret-service-rs v5.2.0][secret-service-source],
published 2026-08-29. This maintained Secret Service client owns DH/AES session
cryptography and desktop prompts; application code does not implement either.
The real consumer is restoring/saving bounded subscription metadata and secret
URLs under [ADR 0028](decisions/0028-subscription-url-secret-service.md), not VPN
credential migration or a new profile database. Native keyring/prompt acceptance
and the standard vulnerability/license audit remain required; encrypted D-Bus
transport does not isolate secrets from other processes of the same user.
At-rest encryption and locking are supplied by the provider, not certified by
the Secret Service API or this wrapper.

The resolution adds secret-service and its RustCrypto/math families: aes 0.9.3,
cbc 0.2.1, cipher 0.5.2, block-padding 0.4.2, inout 0.2.5, cpubits 0.1.1,
cmov 0.5.4, ctutils 0.4.6, hkdf/hmac 0.13.0 and num 0.4.3 with num-bigint 0.4.8,
num-complex 0.4.6, num-integer 0.1.47, num-iter 0.1.46 and num-rational 0.4.2.
Cargo.lock owns the complete resolved graph. This selection adds no OpenSSL,
libsecret, new linked native library, root service or capability. It requires an
existing desktop Secret Service provider at runtime; unavailable/locked storage
is explicit, never a plaintext fallback. Existing zbus feature unification remains.

Persistence also directly consumes the already locked crates.io serde 1.0.229
(`derive`), serde_json 1.0.154 (`std`), Tokio 1.54.1 (workspace runtime/time),
uuid 1.29.0 (workspace `v4`) and rustix 1.1.5 (`fs`, `process`), all MIT OR Apache-2.0.
They own bounded JSON, async deadlines, independent test IDs/UUID parsing and safe
descriptor-relative no-symlink/single-writer locking. These direct edges add no
new source, native library or privileged operation. Tests use synthetic roots and
never access the owner's keyring.

[secret-service-source]: https://github.com/hwchen/secret-service-rs/tree/v5.2.0

The workspace-local `nm-tunnel-schema` package (MIT OR Apache-2.0) has two production
consumers: the NM client and service. It consolidates existing conversion/admission
code using the existing locked workspace `nm-tunnel-profile`, `secrecy`, `uuid` and
`zbus` dependencies, with unchanged workspace features. It adds no external source,
resolved external package, native library or runtime service. Cargo.lock continues
to own exact resolutions; the existing maintenance/security/license review applies.
The `contract` layer permits model dependencies, not engine, client or service I/O.

The workspace-local `nm-tunnel-dataplane` package (MIT OR Apache-2.0) is a real
consumer of extracted service packet/flow, DNS and FakeIP code, not a speculative
platform framework. Its production consumer is `nm-service`; the existing `engine`
layer admits only model/engine workspace edges. It reuses the existing crates.io
async-trait 0.1.92 (MIT OR Apache-2.0), futures-util 0.3.34 (`sink`, MIT OR Apache-2.0),
hickory-proto 0.26.3 (defaults off, `std`, MIT OR Apache-2.0), tokio-util 0.7.20
(`codec`, MIT), serde_json 1.0.154 (default `std`, MIT OR Apache-2.0), uuid 1.29.0
(workspace `v4`, MIT OR Apache-2.0) and Tokio 1.54.1 (workspace runtime/time plus
`io-util`, `sync`, MIT OR Apache-2.0). These move or share existing direct edges;
the service additionally consumes async-trait for the concrete capability adapters.
The same maintained dependency families and locked advisory/license review apply.

meow-dns and meow-lwip 0.26.1 move from the service into the data plane at the
nogcio revision `b75aa6db6a0f79101abb68ab5bdcff84f03d07b0`;
meow-dns defaults stay disabled, lwIP keeps its existing features. Their exact source,
license evidence and native cost are described below. The data plane also consumes
the workspace protocol engine with unchanged features. No external version/source,
linked native library, capability, FFI exception or daemon is added. The existing
lwIP C/bindgen and protocol-engine BoringSSL build cost now applies to data-plane-only
builds too. This extraction adds no cross-build or platform acceptance claim; see
[ADR 0029](decisions/0029-shared-dataplane.md).

Typed executable profiles reuse the existing locked `secrecy` container and `uuid`/
`base64` parsing in the model. The engine drops its direct dependencies on those
three crates; no external source, feature, native library or resolution is added.
The automatic guard-recovery owner reuses the service binary and existing zbus,
Tokio, serde_json, nftables and systemd runtime dependencies. It adds one D-Bus-activated
root service, bounded to CAP_NET_ADMIN and Unix/netlink sockets, in an independent
cgroup; this is a deliberate lifecycle/privilege addition, not a free abstraction.
There is no new protocol, profile store or external daemon dependency. Its deployed
restart/confinement and packet behavior require review/acceptance under ADR 0026.
Its watchdog additionally consumes the existing rustix 1.1.5 `process` pidfd signaling
and async-io 2.6.0 safe descriptor-readiness APIs (exact versions/sources remain in
Cargo.lock). No external source, feature, resolution, native library or capability
is added. D-Bus must supply `ProcessFD`; unsupported buses reject before guard changes.
Process-pinned termination expands root helper authority and requires owner review,
even with unchanged capability bounding. `GetStatus` adds a narrowly scoped read-only
system-bus permission, not ordinary-user cleanup/control access.

The reviewed graph has maintenance advisories in the UI's build-time localization,
font/rendering and zbus 5 dependency families, including foreign-target entries.
They are not presented as demonstrated exploitable vulnerabilities. The NM client
uses zbus 5 too; updating it alone would not remove the UI's older dependencies.
Assess upgrades for compatibility, maintenance and product benefit rather than
eliminating warning counts. Known vulnerabilities remain audit errors.

The usage client adds a direct consumer of the existing locked crates.io `serde`
with `derive` (MIT OR Apache-2.0), serializing the backend's typed v1 D-Bus response
for the COSMIC traffic view. It reuses the graph's established serialization stack;
there is no new package resolution, native library or runtime service. Source and
resolved versions remain in Cargo.lock; maintenance/security use the standard audit.
The graph uses libcosmic's already-enabled canvas, not a new plotting dependency.

The profile model additionally consumes the existing locked crates.io `serde`
1.0.229 (`std`, `derive`) and `serde_json` 1.0.154 (`std`), both MIT OR Apache-2.0,
for its bounded, versioned TCP policy. Unknown fields/duplicate known fields and
unsupported actions are rejected, and parser diagnostics are sanitized. These
established maintained serialization libraries already serve NM-service IPC; this
adds no resolved package, native library or runtime service. Security/maintenance
remain subject to the normal dependency audit, not inferred from parser tests.
TCP inspection uses the existing pinned `meow-common` HTTP/TLS parsers, not a new
parser dependency or copied sing-box source.

The subscription client also directly consumes these same locked serde/serde_json
versions/features for full-envelope admission and static rejection diagnostics.
This is a real consumer before profile extraction, not a new protocol engine or
foreign configuration executor. JSON syntax/top-level structure is bounded and
checked recursively; only the supported native policy is returned for explicit NM
saves. Foreign listener creation, cache-file access and secondary downloads remain
excluded. This serialization consumer introduces no new package/native cost.

The integration layer directly consumes crates.io `tokio-util` 0.7.20 (`codec`,
empty default feature set), MIT, already in Cargo.lock, for bounded DNS-over-TCP framing.
The existing hickory-proto 0.26.3 (`std`, MIT OR Apache-2.0) parses DNS. This maintained
Tokio utility stack is a real resolver-relay consumer, not a new daemon/protocol
implementation. `codec` adds an edge to the already locked libc 0.2.191; no new
package or native library is resolved. Standard audits still
apply. Endpoint-only readiness reuses the pinned application transport chain with
TLS/REALITY verification, without a new dependency, destination or implicit dialer.

Connected-LAN route planning directly consumes crates.io ipnet 2.12.2 (`std`,
default features disabled), MIT OR Apache-2.0, already locked transitively. Its real
consumer is CIDR aggregation and complement summarization for NM's route report;
it does not install routes. This maintained address utility adds no new package or
native cost. Standard vulnerability/license/maintenance checks still apply; see
[ADR 0012](decisions/0012-connected-lan-bypass.md) for privilege and policy bounds.

The profile model also directly consumes the same crates.io ipnet 2.12.2 with
default features disabled and only `std`: native source-policy v2 validates,
normalizes and matches IPv4 CIDRs using its `Ipv4Net` type rather than a custom
address parser. The MIT OR Apache-2.0 source and maintained utility assessment
above apply. This adds one real-consumer dependency edge, not a new resolved
package, serde feature, native library or network capability. Standard advisory
and license checks remain required; matching is not privileged Direct authority.

Durable FakeIP directly consumes the already locked `meow-dns` 0.26.1 at
`b75aa6db6a0f79101abb68ab5bdcff84f03d07b0`, with default features disabled. Its
workspace license is MIT OR Apache-2.0; the same maintained fork/source evidence
below applies. Pool/MemoryStore are real bounded allocator consumers, not a network
resolver daemon. Existing graph feature unification still applies, but this adds
no new resolved package/native library. The adapter uses opaque IDs to keep private
names out of allocator tracing and supplies strict journal durability rather than
FileStore's best-effort semantics. Normal security/license audits remain required;
see [ADR 0016](decisions/0016-persistent-ipv4-fakeip.md).

The engine uses the maintained [meow fork](decisions/0004-maintained-meow-fork.md)
as libraries, not its application or route manager. REALITY enables `boring/mlkem`;
BoringSSL needs CMake, Clang/libclang and a C/C++ toolchain. The experimental runtime
uses the same fork's `meow-lwip`, requiring bindgen and a native C build. Its wrapper
license does not cover vendored lwIP. The rejected `netstack-smoltcp 0.2.4` is not
a dependency. Runtime ownership and limits live in
[ADR 0006](decisions/0006-experimental-nm-runtime.md) and the
[service contract](../crates/nm-service/README.md).

## Adopted domain XUDP library API

The owner-approved opt-in fork patch is published as
[`b75aa6db6a0f79101abb68ab5bdcff84f03d07b0`][domain-xudp-revision], based on
`fbbb9d23a9fbcba28ac0ed69c18e2aea95e35e21`. It
extends `ProxyPacketConn` with typed IP/domain reads and writes, plus an explicit
VLESS Mux.Cool domain entry point. The production consumer is our supplied-socket
engine, used by the shared data plane for complete-policy FakeIP XUDP Proxy with
inherited DNS. The isolated peer harness builds that production route consumer.
Unsupported adapters reject domain writes by default.
Legacy reads and metadata-based UDP fallback are not automatically opted in.

The patch adds no dependency, crypto, unsafe implementation or native feature.
Existing MIT/provenance and maintenance ownership in ADR 0004 remain applicable.
It reuses the library's Mux.Cool framing and cancellation/stream ownership. Source
metadata remains typed rather than relabeling a different domain as an IP sentinel;
the engine requires the exact original domain/port for domain XUDP responses.
Resolved IPs, unrelated domains/ports and absent sources are rejected without
fallback. IP XUDP uses typed reads too, avoiding legacy lossy domain projection.
Library and isolated peer checks are not independent security review.

Independent review reproduced inherited Mux.Cool transport retention when its
outbound queue is full: dropping an association can leave a detached End-frame
sender awaiting peer progress. The engine contains this at its exclusive per-flow
supplied transport boundary with synchronous revocation and read/write wakeups,
including setup cancellation. The regression uses the real pinned mux queue, not
a packet-connection stand-in. The fork pin/API and other consumers are unchanged;
this does not assert a library-wide fix or deployed security acceptance.

All consumed meow packages now pin the published immutable
`b75aa6db6a0f79101abb68ab5bdcff84f03d07b0`. Relative to the previous pin, only the
reviewed nine-file API/test/documentation patch changes; dependency versions and
features are unchanged. No machine-local production dependency is added.
The fork's selected unit tests and library/probe
Clippy pass; narrow-feature all-target Clippy retains Docker-test helper dead-code
errors reproduced on its unmodified base. Three optional upstream live-peer tests
remain ignored, separately from the explicitly executed pinned Xray checks.

[domain-xudp-revision]: https://github.com/nogcio/meow-rs/commit/b75aa6db6a0f79101abb68ab5bdcff84f03d07b0

## Original Git license evidence

### Complete-policy dependency additions

The QUIC hostname adapter consumes crates.io `quic-parser =0.1.5`, defaults off,
`ring` enabled (MIT), archive SHA-256
`528d91b77f6062ecd2cff9d27b9b39fa3e14447260b076b761358d95ff174a39`.
Reviewed `src/{header,crypto,frame,varint}.rs` own parsing, v1/v2 Initial crypto
and CRYPTO reassembly; our adapter bounds packets/fragments/bytes and passes the
result to the pinned TLS sniffer. This is a small, recent single-maintainer crate,
not a mature full QUIC stack; upstream maintenance and malformed-input behavior
require continued review. It adds no daemon or socket authority. `ring` 0.17.14
already exists in the graph; enabling this engine edge adds native ring compilation
to engine-only builds, using the existing C/assembler toolchain, not another TLS
backend/service. The public fixture's separate BSD notice is retained in
[engine fixtures](../crates/engine/tests/fixtures/README.md).

The pinned meow revision is `b75aa6db6a0f79101abb68ab5bdcff84f03d07b0`;
`meow-proxy` additionally enables `mux` for one-association CommandMux/Mux.Cool
XUDP, not arbitrary source multiplexing or a connection pool. Feature unification
also compiles h2mux/yamux/smux modules. New crates.io resolutions are `h2` 0.4.20
(MIT), `yamux` 0.14.1 (Apache-2.0 OR MIT), and `nohash-hasher` 0.2.0
(Apache-2.0 OR MIT). These Rust-only libraries add compile/runtime surface but no
new native library. Yamux/h2 are established upstream projects; the small stable
hash utility has a lower activity cadence. This feature cost buys the real XUDP
consumer without handwritten VLESS framing or a production external proxy core.
Library source review and the isolated pinned-peer probe cover that adapter path,
not all newly compiled mux protocols. The locked dependency audit passes with
visible maintenance/duplicate warnings; no advisory/license exception was added.
Root source-DNS use expands privileged protocol execution and requires separate
owner review; see [ADR 0020](decisions/0020-native-ipv4-source-policy.md).

These are inspection snapshots, not an independently maintained inventory of
current resolutions or a commit allowlist. Reinspect affected evidence when
updating Cargo.lock. Repository names below are relative to `https://github.com/`.

| Repository | Inspected commit | Inspected requirement | Original license evidence |
| --- | --- | --- | --- |
| iced-rs/cryoglyph | `e429a025df36ab8145708acb309080ae3deec17a` | rev | `LICENSE-MIT`, MIT option |
| jackpot51/rust-atomicwrites | `043ab4859d53ffd3d55334685303d8df39c9f768` | default branch | `LICENSE`, MIT |
| nogcio/meow-rs | `b75aa6db6a0f79101abb68ab5bdcff84f03d07b0` | rev | workspace declarations; lwIP separately below |
| pop-os/cosmic-protocols | `c0cff4db14c37ed954983158e4055aa94c7741d9` | abbreviated rev | `src/LICENSE`, MIT |
| pop-os/dbus-settings-bindings | `eed01dd3609e90e3c8cd043656734c500956c793` | default branch | `LICENSE.md`, MPL-2.0 |
| pop-os/freedesktop-icons | `ab4c57b8e416c6af9297cb04d101889896fd9a92` | default branch | `LICENSE`, MIT |
| pop-os/libcosmic | `430f3d48a97d8779f9c1985473912e594ccca1ae` | rev | `LICENSE` and source SPDX headers, MPL-2.0; nested material differs |
| pop-os/smithay-clipboard | `859b02c88f45c554049a67c6ddeec1692ce0e20b` | tag `sctk-0.20` | `LICENSE`, MIT |
| pop-os/softbuffer | `c2b2c19ddb38ff17495643699f97cb1f2064a1be` | tag `cosmic-4.0` | `LICENSE-MIT`, MIT option |
| pop-os/window_clipboard | `f68595ee0e62fbd6589f4709b5aaa5c3c7ea5f6c` | tag `sctk-0.20` | `LICENSE`, MIT |
| pop-os/winit | `9567503d34130113e36b0167a2b8829c3756e429` | rev | `LICENSE`, Apache-2.0; `dpi/LICENSE-LIBM-MIT` separately |
| wash2/accesskit | `6c20249d3b9fd45e7002efad9f6b6171a9257912` | rev | `LICENSE-MIT` option and `LICENSE.chromium` BSD notice |

Exact original files can be retrieved from
`https://raw.githubusercontent.com/<repository>/<inspected-commit>/<path>`.
Branch/tag/default-branch upstream requirements do not require toolkit forks or
a second commit approval list; see [ADR 0009](decisions/0009-locked-git-source-admission.md).

At that libcosmic revision, gitlinks and `.gitmodules` identify:

- `iced`: `pop-os/iced@229186b5180b6217d93866c912e6373ac378b231`.
  Its own root `LICENSE` is MIT; do not assign libcosmic's MPL wholesale to Iced.
- `cosmic-icons`: `pop-os/cosmic-icons@343c007f37cd71716e68f01c43ecf2764b7f7c47`.
  Source presence alone does not establish which icons enter our distribution;
  asset usage and applicable notices still need review.

## Missing metadata and additional license evidence

`deny.toml` contains package-scoped license admissions and file-hash-backed
clarifications for missing metadata. These do not relabel dependencies as MIT.
MPL is file-level copyleft, not automatically the license of our separate source.

| Resolved package(s) | Evidence and scope |
| --- | --- |
| apply 0.3.0 | Published `License.md` contains the Unlicense despite missing Cargo license metadata. |
| libcosmic, cosmic-config, cosmic-config-derive, cosmic-theme 1.0.0 | Root MPL-2.0 and module SPDX headers; clarification inputs must remain outside the MIT Iced submodule. |
| cosmic-settings-daemon 0.1.0 | dbus-settings-bindings root `LICENSE.md` is MPL-2.0; clarification reads `../LICENSE.md` in that checkout. |
| iced_accessibility 0.1.0 | Located in the MIT Iced submodule, not the MPL parent scope. |
| dnd, mime 0.1.0 | window_clipboard root MIT text names Héctor Ramón and contributors; missing package metadata needs a scoped clarification. |
| option-ext 0.2.0 | Published `LICENSE.txt`, MPL-2.0. |
| almost 0.2.0, notify 8.2.1 | Published `LICENSE-CC0`, CC0-1.0. Preserve actual upstream text, including notify's template-style markers. |
| error-code 3.4.0 | Published `LICENSE`, BSL-1.0. |
| clipboard-win 5.4.3 | Declares BSL-1.0 but excludes LICENSE from its archive. Original `DoumanAsh/clipboard-win@ed27008ae5d1f10cfbb266de039f0fb35fd05a56/LICENSE` supplies the text; archive absence is not a new grant. |
| hexf-parse 0.2.1 | Published `Cargo.toml.orig` declares CC0-1.0. Archive has no license text; the recursive tree and README at `lifthrasiir/hexf@4225763d744183d720f575ae96d04161b4d08ea0` supply no standalone license text. Metadata is evidence of the declaration, not evidence that a license file was shipped. |
| webpki-roots, webpki-root-certs 1.0.11 | Published `LICENSE` is CDLA-Permissive-2.0; section 2.1 requires the agreement text with shared data. |

BSL-1.0 here means **Boost Software License**, not Business Source License.
CC0 and Unlicense are distinct grants and must not be relabeled MIT.

Clarifications read package-relative parent licenses in place. Iced uses its own
`../LICENSE`, not libcosmic's parent license. Hashes are cargo-deny 0.19's normalized
XXH32 values: MPL root `0x3b6981e6`, Iced MIT `0xa244f17c`, clipboard MIT
`0xfd9601dd`, settings-bindings MPL `0x0d4a6b51`, apply Unlicense `0x401a3405`.
The checker matches package name/version and file contents, **not Git revision**.
Resolved source identities are recorded in Cargo.lock;
unchanged package versions/license text do not establish unchanged source code.

Passing license checks does not prove complete distribution compliance.
`about.toml` accepts reviewed texts for collection, including OFL-1.1; unlike
`deny.toml`, collection is not package admission and does not itself ship notices.

## Embedded and native material

At the libcosmic commit above, our `frontends/cosmic/src/main.rs` calls
`cosmic::app::run`. Upstream `src/app/mod.rs:140` calls `iced_settings`, which
unconditionally calls `preload_fonts` at line 36. Lines 891–910 embed and load
five Open Sans TTFs and two Noto Sans Mono TTFs. This is an active application
startup path, not merely unused files in a checkout.

`res/open-sans/LICENSE` and `res/noto/LICENSE` are SIL OFL-1.1. Distribution must
retain their actual copyright notices and license text, respect any reserved font
names when modifying fonts, and not sell fonts by themselves. The application
does not become OFL-licensed merely by bundling fonts. Cargo package-license
metadata alone cannot collect these assets' notices.

The two original font license texts and lwIP COPYING are retained under
`packaging/licenses/`; preserve them in binary packaging. Its README preserves
the additional Noto copyright/trademark/author strings from both font name tables.
These supplementary texts complement the generated Rust/native/certificate-data
notices; they are not the whole shipping notice set.

The fork's `crates/meow-lwip/COPYING` contains the BSD-3-Clause lwIP notice, copyright
2001, 2002 Swedish Institute of Computer Science. Preserve it separately from
the Rust wrapper's MIT/Apache-2.0 declaration. The notice collector includes native
BoringSSL and AccessKit's Chromium notice through `about.toml` clarifications, and
certificate-data licenses from the locked webpki crates. Review generated outputs
and embedded material on source updates; exit success alone does not prove coverage.

Required notices and MPL covered-source availability, including any modifications,
must accompany executable distribution as applicable. A source URL table alone
is not a complete notice/source-compliance mechanism. The recipe ships generated
notices alongside [source instructions](../packaging/licenses/SOURCE-AVAILABILITY.md).
See the
[provenance and notice policy](third-party.md) and [AUR direction](installation.md).
