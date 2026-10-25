# Dependency status and license evidence

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

The engine uses the maintained [meow fork](decisions/0004-maintained-meow-fork.md)
as libraries, not its application or route manager. REALITY enables `boring/mlkem`;
BoringSSL needs CMake, Clang/libclang and a C/C++ toolchain. The experimental runtime
uses the same fork's `meow-lwip`, requiring bindgen and a native C build. Its wrapper
license does not cover vendored lwIP. The rejected `netstack-smoltcp 0.2.4` is not
a dependency. Runtime ownership and limits live in
[ADR 0006](decisions/0006-experimental-nm-runtime.md) and the
[service contract](../crates/nm-service/README.md).

## Original Git license evidence

These are inspection snapshots, not an independently maintained inventory of
current resolutions or a commit allowlist. Reinspect affected evidence when
updating Cargo.lock. Repository names below are relative to `https://github.com/`.

| Repository | Inspected commit | Inspected requirement | Original license evidence |
| --- | --- | --- | --- |
| iced-rs/cryoglyph | `e429a025df36ab8145708acb309080ae3deec17a` | rev | `LICENSE-MIT`, MIT option |
| jackpot51/rust-atomicwrites | `043ab4859d53ffd3d55334685303d8df39c9f768` | default branch | `LICENSE`, MIT |
| nogcio/meow-rs | `fbbb9d23a9fbcba28ac0ed69c18e2aea95e35e21` | rev | workspace declarations; lwIP separately below |
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
