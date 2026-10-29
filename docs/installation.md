# Arch Linux and AUR

The distribution direction is a normal source-built AUR package,
`network-manager-tunnel-git`, not a custom installer. Upstream source is at
<https://github.com/nogcio/network-manager-tunnel>. The AUR entry is not yet published.

## Build and install

After the AUR entry is published:

```sh
git clone https://aur.archlinux.org/network-manager-tunnel-git.git
cd network-manager-tunnel-git
less PKGBUILD
makepkg -si
```

Build as a regular user. Only pacman installation requests privileges; never run
Cargo or makepkg under sudo. An AUR helper is optional, not part of the application.
Dependencies are listed in the recipe under `packaging/aur/`.

Installed binaries are built with `cargo build --locked --release`, without the
development `preview` feature. The workspace release profile uses optimization
level 3, one codegen unit and thin LTO. Cargo.lock fixes dependency versions/commits;
the AUR recipe owns its build output directory and installs only that build's artifacts.
The UI enables libcosmic's wgpu renderer with the upstream software fallback.

Pacman owns binaries, desktop entry, NM/D-Bus descriptors, worker account metadata,
notices and documentation. Arch's standard transaction hooks handle registration;
there is no custom install script, broad NM/DNS reload, service enablement or
installation-time VPN activation. NetworkManager launches the VPN plugin directly.
Before changing guards, the backend D-Bus-activates the separate systemd-owned
`nm-tunnel-guard-recovery.service`; its service/policy/unit files are required.
The system message bus must provide connection-credential `ProcessFD` support.
Unsupported buses refuse activation before guard installation, without a numeric-PID
fallback. The helper's lifecycle lease also detects a hung backend retaining its name;
terminal recovery stops that exact process before removing guards. COSMIC observes
progress read-only and never starts recovery itself. Review the process-signaling and
status-policy changes before installing this experimental version.
The optional FakeIP boot guard below is a one-shot reservation, not another VPN
manager or always-on daemon, and is not enabled by package installation.

## Update, remove and recover

The transition to [explicit-Disconnect protection][strict-protection] is
**incompatible** with the old automatic-unblocking helper ABI v1. Before installing
v2, explicitly disconnect the old VPN and confirm both old backend/helper processes
have retired. Do not replace/restart a leased helper under a live VPN. New code
refuses a v1 helper before arming; old running code cannot be made fail-closed by
replacing files. This transition needs separate owner approval.

For compatible upgrades from a version implementing
[ADR 0030](decisions/0030-session-preserving-package-updates.md), install the rebuilt
package normally: registration updates automatically, while an active session
continues on its existing image. After confirmed session teardown the old backend
retires; a later NM connection uses the installed image. The frontend reports a
replacement without forced restart: close/reopen it when convenient to use new UI.
No manual daemon reload, D-Bus reload or VPN reactivation command is required.

The first upgrade from an older version still needs one owner-authorized disconnect
and confirmed retirement: old running code cannot acquire the new retirement logic.
Close the app and disconnect before removal or an incompatible migration.
Use normal AUR rebuilds for updates and `sudo pacman -R network-manager-tunnel-git`
for removal. Existing NM profiles and the worker account are preserved; manage
unwanted profiles through NM. No installer owns a second profile database.

Terminal failure now retains blocking until explicit Disconnect. The independent
helper revokes stale physical exceptions after backend death but does not remove
protection. COSMIC exposes explicit release even when NM has lost its active VPN
object, with the normal Polkit network-control check. An NM-only disconnect from
another applet can leave the latch held; use COSMIC Disconnect to release it.
Package transactions do not themselves alter firewall rules.
Keep both executables/unit files available until disconnect and cleanup complete.
Synthetic legacy IPv4 VM checks passed actual TUN TCP echo, clean disconnect,
backend SIGKILL cleanup and SIGSTOP watchdog cleanup. Broader packet/source-policy
coverage and helper-restart races remain pending; see
[ADR 0026](decisions/0026-automatic-session-recovery.md).

Persistent IPv4 FakeIP retains a root-owned XDG identity journal, but protection
is now session-scoped. Activation automatically installs both required guards;
only explicit Disconnect removes both in one transaction. The compatibility
`--clear-guard` and narrower `--clear-fakeip-guard` remain administrative tools,
not required user recovery steps. Neither command deletes identities. Never reset,
edit or roll back the
journal; names can be sensitive, so do not attach or AI-index it.

No boot service enablement is required. The installed
`nm-tunnel-fakeip-guard.service` still pins the existing root XDG identity namespace
and supports optional explicit restoration, but no longer declares an NM Requires
dependency. If you previously enabled the old unit, explicitly disable its old
symlinks to retire that boot policy; a package update alone does not remove them.
Do not change the identity namespace. Outside a session or after reboot without
restoration, cached FakeIP destinations are not protected; applications may need
to retry or expire their caches. See [ADR 0022](decisions/0022-session-scoped-guards.md).
Native packet/crash acceptance and privileged source-DNS security review remain
incomplete; package/update success does not establish production security.

The current service-state default is `XDG_STATE_HOME=/var/lib`, not root's home:
NM may mount homes read-only. If the former `/root/.local/state` identity directory
already exists, activation rejects instead of silently creating a new epoch.
Plan explicit offline migration preserving every lease; never reset the journal.
See [ADR 0023](decisions/0023-fakeip-service-state.md).

## Current limits

The AUR package is not yet published. An owner-authorized local source snapshot was
built with unprivileged makepkg, including release tests and dependency notices,
and upgraded through pacman after observed Tunnel disconnection and guard cleanup.
The installed executables/desktop entry matched the package checksums; pacman
reported 49 files with no alterations. This is a local snapshot/update observation,
not validation of the public VCS source recipe, clean-system removal, reboot,
desktop prompts or post-update VPN interoperability. No automatic reactivation was
part of that update. The installed snapshot can lag later source changes; launching
the source frontend separately does not update the installed package or backend.

Do not share build directories across independently extracted source snapshots.
Their preserved source timestamps can incorrectly reuse stale Cargo artifacts.
Use the recipe's own fresh source/output tree; retain the verified previous package
for an explicitly authorized offline rollback, without resetting NM profiles or
the FakeIP identity journal.

The recipe generates dependency notices and ships supplementary licenses and
covered-source instructions. Review the actual package outputs before distribution;
see [dependency review](dependency-review.md).
The runtime remains experimental: real desktop/Polkit acceptance, long-running
reliability and live REALITY compatibility are not established by package creation.

[strict-protection]: decisions/0034-explicit-disconnect-protection.md
