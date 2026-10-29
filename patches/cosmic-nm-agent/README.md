# Local COSMIC VPN agent persistence candidate

Owner-authorized, local-only upstream patch pair. Not installed, published,
upstream-approved or a dependency/backend of Tunnel. The distribution's unpatched
COSMIC applet still fails VPN keyring persistence acceptance.

## Sources and licenses

Apply to sibling checkouts named `cosmic-applets` and `nmrs`:

| Patch | Exact upstream base | License |
| --- | --- | --- |
| `nmrs.patch` | freedesktop-rs/nmrs `ae2166e0658aadde16b133afa20f7285c5ef2d9d` (`nmrs-v3.5.5`) | MIT OR Apache-2.0; original MIT notice retained in `LICENSE-MIT.nmrs` |
| `cosmic-applets.patch` | pop-os/cosmic-applets `406d1b7d627138fdf4078f654268d3d8774e50f1` (`epoch-1.10.0`) | GPL-3.0-or-later; complete text retained in `LICENSE-GPL-3.cosmic-applets` |

The patches include upstream context under those licenses, not the workspace's
blanket license. They keep modifications in the original owners. They do not copy
either project's implementation into Tunnel's runtime. Existing upstream notices
remain authoritative. Neither project's name implies endorsement.

## Contract

- nmrs authenticates Get/Save/Delete/Cancel against the current NM unique bus owner.
  An optional desktop-owned store receives original settings and must complete
  before Save/Delete succeeds. Failures/deadlines return redacted errors. Without
  the option, existing notification-only store behavior remains.
- The existing COSMIC applet, not a second agent, owns VPN Secret Service access.
  Only explicit agent-owned keys (`flags=1`) are saved/read. System, not-saved,
  not-required and combined nonpersistent flags never authorize persistence.
  Invalid flags/payloads reject before keyring work. `REQUEST_NEW` bypasses lookup;
  noninteractive lookup never unlocks a collection or opens a credential dialog.
- Entries bind NM connection UUID, VPN service, setting and key. Writes replace
  matching entries; ambiguous duplicates reject. Profile deletion removes that
  connection's VPN entries, including after its NM object disappears. No complete
  profile document, URL or plaintext fallback is stored.
- The standard provider owns prompts, encryption and locking. Reads/mutations are
  serialized; NM request cancellation interrupts lookup. A dispatched provider
  mutation may complete when its deadline expires, so errors do not prove rollback.
- This candidate covers VPN secrets only, not a Wi-Fi/EAP storage redesign. A small
  unused-`mut` cleanup keeps the touched applet build warning-free on Rust 1.99.1.

The real consumer uses secret-service 5.2.0, defaults off,
`rt-tokio-crypto-rust`, MIT OR Apache-2.0, and async-trait 0.1.92 (already in the
applet graph), MIT OR Apache-2.0. The patch's Cargo.lock includes exact archive
checksums/resolutions. Secret Service crypto is library-owned, not handwritten;
there is no new linked native crypto library. The added RustCrypto/math families
and maintenance/security limitations are the same family reviewed in
[Tunnel's dependency review](../../docs/dependency-review.md#maintenance-and-native-cost).
This is not distribution approval or a complete upstream dependency audit.

## Reproduce without installation

Use clean checkouts of the exact bases; inspect both patches first. For example,
from the directory containing both checkouts, with an absolute `$PATCH_DIR`:

```sh
git -C nmrs apply --check "$PATCH_DIR/nmrs.patch"
git -C cosmic-applets apply --check "$PATCH_DIR/cosmic-applets.patch"
git -C nmrs apply "$PATCH_DIR/nmrs.patch"
git -C cosmic-applets apply "$PATCH_DIR/cosmic-applets.patch"
cargo +1.99.1 build --manifest-path cosmic-applets/Cargo.toml --locked \
  -p cosmic-applet-network --features rust-embed/debug-embed
```

`debug-embed` makes the uninstalled development executable carry its normal
localization resources, just as release builds do. It is not a storage bypass.
Blank patch context lines omit trailing spaces; clean-base `git apply --check`
and byte-for-byte reconstruction of all modified source files are verified.
The exact toolchain is explicit so an upstream rust-toolchain file does not
silently select/download another one. Build inputs may need ordinary source
downloads; VM runtime remains offline.

Pass the executable via `scripts/check_vm.py --suite desktop --desktop-agent PATH`
with the standard checksum-verified image, peer/backend/client/profile arguments
from the [VM contract](../../docs/testing/vm-acceptance.md). The runner hashes the
candidate into its manifest and runs a private copy only in the disposable guest.
Without this flag it tests the packaged applet; there is no hidden substitution.

## Acceptance limits

Verified source checks (from the sibling-checkout directory):

```sh
cargo +1.99.1 test --manifest-path nmrs/Cargo.toml --locked -p nmrs --lib --all-features
cargo +1.99.1 test --manifest-path nmrs/Cargo.toml --locked -p nmrs --doc --all-features
cargo +1.98.1 clippy --manifest-path nmrs/Cargo.toml --locked \
  -p nmrs --all-targets --all-features -- -D warnings
cargo +1.99.1 test --manifest-path cosmic-applets/Cargo.toml --locked \
  -p cosmic-applet-network --lib --features rust-embed/debug-embed
```

Library tests, applet persistence unit tests and both workspaces' format checks
pass. nmrs doctests report 138 passed and 16 upstream-ignored examples; ignored
examples are not environmental acceptance. No host NM integration tests are run.

The bounded desktop scope verifies save, encrypted-keyring evidence, actual
applet/keyring process reopen, NM activation and real TUN traffic, profile deletion,
not-saved policy, no system-keyfile credential, and refusal of non-NM calls without
keyring mutation. It uses a nested guest-root desktop, not a real-user login.
Locked-provider prompt input/cancellation, accessibility, unavailable-provider
native UX, Wi-Fi/EAP regression acceptance, packaging and host deployment remain
unaccepted. This source candidate requires independent security/upstream review.
The original combined full desktop-candidate run failed after S3 during steady
traffic. Platform-only controls under KVM and TCG then localized the reset to
QEMU 11.1.2's ICH9 LPC/PM state loss on wakeup, independently of Tunnel or desktop
processes. The installed emulator still reproduces this failure. The separate
[QEMU patch candidate](../qemu-ich9-s3/README.md) preserves that state without
disabling the watchdog; its regression also verifies expiry without keepalives.
The complementary `desktop-soak` composition passes both the genuine keyring
lifecycle and the complete ten-minute TCP/UDP workload with flow draining,
without a preceding suspend. With both explicit local candidates, `full` passes
40/40 in `target/vm-acceptance/run-vdxk1_vj/`, including post-S3 desktop/keyring,
ten-minute traffic, flow draining and terminal cleanup. This establishes only the
declared offline composition; neither candidate is installed, and passing VM
checks do not certify production safety or the missing native UX above.

nmrs library tests pass with its own locked graph. Strict Clippy passes on Rust
1.98.1; Rust 1.99.1 exposes a pre-existing async-trait 0.1.89 `double_must_use`
finding in `monitoring/transport.rs`. Applet strict Clippy on Rust 1.99.1 finds
pre-existing `app.rs` sort/let-return/collapsible-if/clone-on-copy warnings outside
the persistence implementation. No lint suppression is added to conceal them.
