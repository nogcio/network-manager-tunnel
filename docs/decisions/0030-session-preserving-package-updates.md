# ADR 0030: Session-preserving package updates

Status: implemented experimentally; privileged live-update and native UI acceptance
remain separate from ordinary checks. Owner-approved local installation is not
production certification.

## Contract

Compatible Arch upgrades replace package-owned files through pacman. Existing Arch
hooks reload systemd and D-Bus metadata and create the worker account; the package
adds no install script, mandatory updater, network-manager restart, disconnect,
activation or subscription refresh. A running VPN retains its immutable profile,
credentials, FakeIP identity epoch and current process image until normal teardown.
No live process is re-executed or killed by the package transaction.

The backend compares its startup executable device/inode with its original installed
path only at an idle boundary. A replaced or missing image retires the backend when
there is no preparation, session or cleanup owner and state is Initial/Stopped.
Completed cleanup may retire immediately; idle heartbeat checks run every two
seconds. Active/preparing/stopping lifetimes are never retired by image observation.
If an activation races idle retirement, it rejects before resources and asks NM to
retry; it never runs a mismatched worker or attempts a fallback activation itself.
NM remains the activation owner and launches the installed backend for a later
connection. No automatic reconnect or on-disk profile migration is introduced.

## Same-image workers

Resolving `current_exe()` to a pathname and reopening it after an atomic package
replacement is not image pinning. Passing `/proc/self/exe` to `setpriv` would instead
execute setpriv's image. Root therefore opens `/proc/self/exe`, maps that owned
read-only file to child stdin using Rust's standard `Stdio` mechanism, and asks
setpriv to execute `/proc/self/fd/0` after its existing UID/capability reduction.
The kernel resolves the child's own descriptor to the pinned ELF image, even if
its former pathname has been replaced/unlinked. There is no unsafe pre-exec hook,
globally inheritable extra descriptor, writable executable copy or retained binary
cache. The worker's fd 0 stays a read-only executable, never a credential channel.

The TUN capability is sent as the first SCM_RIGHTS grant on the existing private
parent/worker Unix stream, before bounded configuration. Receipt has one five-second
deadline and requires exactly one descriptor with the Linux TUN character-device
identity (10:200), without truncation. Invalid/missing/extra descriptors close and
reject; there is no legacy-stdin fallback. Stats/control fd roles and the marked-IP
socket boundary are unchanged. Workers and their parent are the same image, so this
private bootstrap change never relies on cross-version worker compatibility.

## Recovery and frontend

Guard recovery's version-1 GetStatus/Arm/Renew behavior is a stable compatible
interface. Before installing guards a backend checks that version, then arms using
the existing ownership/ProcessFD lease. An incompatible helper refuses activation;
no package hook restarts a leased helper or strips active guards. Breaking cleanup
or profile/storage semantics require a separately reviewed migration/versioned
interface, not an in-place reinterpretation of this contract.

The installed COSMIC process observes its executable identity read-only, coalescing
local filesystem checks off the UI thread. A replacement produces an informational
message using existing UI feedback without overwriting pending action/error feedback.
It never installs packages, reads credentials, restarts itself, controls recovery or
reconnects a VPN. Source runs/previews do not monitor the system-installed image.
Reopening the app uses the new frontend; no forced restart discards unsaved work.

## Transition and limits

Versions predating this mechanism require a one-time owner-authorized disconnect,
confirmed teardown and retirement before installing the first supporting package.
The new source cannot retrofit retirement into an already running old executable.
Removal and incompatible storage/IPC/policy changes still require disconnect first.
FakeIP journals must never be reset/rolled back as part of an upgrade or rollback.

Ordinary tests atomically replace a synthetic executable and verify that setpriv
executes the still-open original without root; test idle retirement gates and
bootstrap descriptor rejection/ownership/deadlines. They do not prove the real UID
transition, TUN transfer, native notice display, old/new privileged session overlap
or arbitrary cross-release compatibility. Pacman hook success and installed file
hashes do not prove these networking/security properties.
