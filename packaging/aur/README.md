# Planned AUR source package

`PKGBUILD` is a normal VCS source recipe for `network-manager-tunnel-git`.
Upstream source is at <https://github.com/nogcio/network-manager-tunnel>.
The AUR entry is not yet published. Generate `.SRCINFO` from the reviewed recipe
for the AUR submission.
There is no custom installer or artificial acceptance stop in the recipe.

## Build and package

makepkg builds the two executables with `--locked --release --no-default-features`;
preview is never enabled. `Cargo.toml` owns optimization level 3, one codegen unit
and thin LTO. The recipe disables makepkg's independent LTO policy and installs
only release artifacts. Do not override the release profile with debug build flags.
`check()` runs normal Rust release tests, not tests of packaging-file text.

Prerequisites include Rust/Cargo, Git, CMake, Clang/libclang, pkg-config and
cargo-about 0.8.4. Arch's `base-devel` is assumed. cargo-about is build-time only:
its outputs, not its executable or dependencies, enter the package. The two
production manifests are scanned separately with default, development and build
dependencies disabled. Font/lwIP texts are shipped separately; the root
`about.toml` includes parent-license, BoringSSL and Chromium notice clarifications.
Certificate-data CDLA notices are collected from the locked webpki crates.

The `rust` build dependency also accepts Arch's rustup provider. The project's
`rust-toolchain.toml` selects the exact compiler when building through rustup;
check that the compiler meets Cargo.toml's minimum version with a system toolchain.

Validate with an actual unprivileged makepkg build and package-content inspection;
test installation/runtime only under separate authorization. Use the public
upstream source to validate the actual VCS recipe. A local-source build may use
an explicitly reviewed disposable source override, but it does not validate the
public remote. No local override is shipped in this recipe.

## Activation and host integration

NetworkManager directly spawns the executable in `nm-tunnel.name`, as its VPN
plugin API expects. The root supervisor authenticates the current NM D-Bus owner
and drops the protocol worker to the dedicated `nm-tunnel` account. There is no
separate systemd service, unit sandbox or always-on daemon. NM-spawned processes
inherit NM's service environment/confinement; this package does not promise an
additional supervisor sandbox.

The D-Bus activation file is retained because the unprivileged frontend uses
activatable-name discovery to detect the installed backend before first Connect.
Its root-only activation invokes the same executable directly, not another service
manager. Ordinary frontend discovery does not activate it. The service and bus
policy still enforce ownership/control authorization.

Arch's existing sysusers and D-Bus transaction hooks handle installed metadata.
There is no package-specific install script, NM reload, automatic VPN activation,
service restart, guard removal or account/profile deletion.

## Notice tool and verification limits

Selected tool: `EmbarkStudios/cargo-about` 0.8.4, MIT OR Apache-2.0, released
2025-12-04 and available in Arch's extra repository. The crates.io archive SHA-256 is
`9ce2918775e8b4ca29ed86ab17539f88293bdbab953e79af694f7194a3bb35f4`.
The reviewed source/configuration is at
<https://github.com/EmbarkStudios/cargo-about/tree/78444cac825cf0ab678f1bfe4391962591129aa8>.
Its default feature set supplies the executable/template renderer; its build includes
ring and mimalloc native code. It is not linked into the product or added to the
workspace dependency graph. A pinned evaluation installation can use:

```sh
cargo install --locked --version 0.8.4 cargo-about --root /tmp/opencode/nmt-tools/cargo-about-0.8.4
```

This maintained collector has a real consumer in `build()`. It reads dependency
sources, may retrieve missing license files online and renders the minimal
`packaging/licenses/notices.hbs` template. No secret input is required. Its source
review and successful generation are not a security audit or legal certification.
The config disables the external ClearlyDefined metadata service. Upstream has
newer releases; this exact version is selected to use Arch's existing tool package,
not to require another AUR bootstrap package or an implicit Cargo tool installation.
Review generated notices when dependency sources change: the collector may use
canonical license text where upstream packages omit files, and not every embedded
asset is discoverable from Cargo metadata. Covered-source download instructions
are shipped in `SOURCE-AVAILABILITY.md`; keep them aligned with Cargo.lock.
The `mime` 0.1 parent-license clarification does not apply to registry `mime` 0.3;
the tool warns on that mismatch and harvests 0.3 normally. Version 0.8.4 also logs
a deprecated `GPL-2.0` identifier encountered during the UI source scan, without
selecting that identifier or failing generation. Inspect diagnostics and actual
outputs rather than interpreting exit success as proof of complete notice coverage.

The owner reports a working experimental local Arch installation from a reviewed
local-source build. This does not validate a public-source build or a clean Arch
build/install/update/removal/reboot cycle. The installed package can lag source UI
changes; running the source frontend separately does not replace installed files.
Broader packaging/runtime acceptance remains pending. Source publication still
requires owner authorization, independently of these technical limitations.
