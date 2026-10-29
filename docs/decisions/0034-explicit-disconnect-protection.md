# ADR 0034: Protection remains until explicit Disconnect

Status: owner-approved replacement for automatic terminal unblocking; experimental
implementation with bounded offline VM evidence, not host/native desktop acceptance.
Supersedes ADR 0026's terminal-cleanup
decision and ADR 0033's catastrophic-failure exception. Existing VM v6 evidence is
historical and does not verify this contract.

## Contract and scope

Once a VPN attempt arms protection, loss of the uplink, worker/broker failure,
backend crash/hang, NM owner loss, or exhausted setup cannot authorize ordinary
network access. The independent helper retains the owned nft guard without an
overall timeout. This applies to old nonpersistent profiles too; `vpn.persistent`
still controls NM's physical-network lifetime, not permission to unblock.

A failed worker recovers the same admitted in-memory session using the existing
bounded attempts/backoff and retained TUN. Old flows and resolver authority are
revoked and joined; application bytes are not replayed. A fatal backend or watchdog
failure cannot promise VPN recovery, but must leave physical egress blocked. No
subscription, saved profile, credential or FakeIP identity is migrated or reset.

The helper's v2 ABI is incompatible with the v1 automatic-unblocking helper. A new
backend refuses v1 before installing guards. Do not perform a live mixed-version
upgrade: explicitly disconnect the old session and retire both old processes before
installing/starting v2. Old installed code cannot acquire this behavior from docs
or a saved `vpn.persistent` edit.

This is a current-boot protection latch, not boot activation or a new network
manager. Kernel reboot, privileged firewall administration, and kernel/systemd
failure are outside this guarantee. No boot unit is implicitly enabled. The
original FakeIP journal remains separate and must never be reset or rolled back.

## Independent ownership and release

`Arm` authenticates the current backend's unique D-Bus owner, obtains ProcessFD
from bus credentials and establishes a restrictive baseline guard before returning.
`Renew(cleaning=true)` now retains protection and revokes physical LAN exceptions;
it does not remove tables. Heartbeats cannot revive an expired lease. After owner
loss/expiry the helper terminates the pinned process, confirms exit, removes stale
LAN exceptions and reports `blocked`, never ordinary-network recovery. Helper
restart reconstructs the latch from the existing owned main guard. Unknown nft or
bus observations fail rather than certifying absence or authorizing release.

The sole ordinary release operation is explicit `Recovery.Disconnect(generation)`:

- `GetReleaseToken` is read-only, non-activating and returns a helper-local UUID
  generation plus whether protection is held. It contains no profile/endpoint data.
- The service independently checks Polkit's existing
  `org.freedesktop.NetworkManager.network-control` permission for the actual unique
  bus sender. There is no caller-supplied PID/UID or blanket unprivileged grant.
  Interactive authentication is permitted only when the caller explicitly asks.
- Authorization is bounded; caller disappearance rejects. After authorization the
  release rechecks the generation under the same gate as Arm. Helper restart,
  replacement session and repeated/delayed release cannot clear newer protection.
- The helper confirms process death before the single owned-table removal
  transaction. Failure or unconfirmed exit retains the latch; no automatic release
  retry follows an ambiguous user request. No profile, route, DNS or identity writer
  is introduced. NM remains responsible for normal connection teardown.

The helper has no VPN credentials, profile database or Internet sockets. Polkit is
now an explicit system package dependency, using locked zbus rather than another
Rust authorization library. Its process-signaling/guard authority is unchanged;
the narrow system-bus permission admits the new method only to its independently
authorized implementation.

## Explicit controls and frontend

The existing client `deactivate` pins the protection generation **before** asking
NM to deactivate its observed active object. Only a confirmed accepted NM request
may be followed by release of that pinned generation. A rejected/ambiguous NM call
does not dispatch release; mutations are never automatically retried.

After a crash NM can remove its active object. COSMIC therefore keeps its existing
Disconnect action available on a fresh `blocked`/termination/retry observation even
without NM connectivity. Its explicit fallback `disconnect_protection` pins the
current helper/generation and requests authorized release. Observation, timers,
application exit, HTTP completion and automatic NM plugin Disconnect never invoke
it. Failure/timeout does not claim successful cleanup. Native Polkit prompt/input
acceptance remains pending.

A bare `nmcli connection down` or another desktop's NM-only Disconnect stops the
VPN but does not itself release the latch: NM uses the same plugin method for
automatic teardown, so it cannot certify explicit user intent. Use COSMIC's
Disconnect to release the remaining protection. This limit is deliberate fail-closed
behavior, not silent support for every desktop applet. Root administrative guard
commands remain explicit overrides, not the normal UI path.

## Verification

Owner-local regressions cover authenticated backend admission, unknown ownership,
retention after orphaning, generation/repeated-release refusal, failed guard release,
ProcessFD termination ordering, the Polkit bus-subject/structured-reply contract,
client owner replacement/lost replies without retry, and the disconnected frontend's
explicit action/freshness boundary. These do not establish deployed packet isolation.

Offline VM contract v7 replaces worker/backend crash/hang and uplink-loss cleanup
expectations with retained guards and failed physical probes until explicit release.
The terminal scenario verifies retained full/FakeIP guards after backend SIGKILL,
then ordinary traffic only after explicit Disconnect. Required integration cases
must fail, not skip. The preceding 40/40 v6 run cannot be relabeled as v7 evidence.

The owner-authorized `fail-closed` scope passed eight required cases on the pinned
offline prepared image: baseline/native TCP/UDP/DNS, explicit disconnect, worker
recovery, backend SIGKILL/SIGSTOP, helper restart, and persistent terminal retention.
After NM removed the failed TUN, both IPv4 and IPv6 physical probes were refused;
the unprivileged worker UID could not release protection. A stale token after a
blocked-helper restart was refused without removing guards. Explicit authorized
release then permitted ordinary traffic. Evidence is generated under
`target/vm-acceptance/run-53qxbyfl/`; no host profile or external node was used.

This is a bounded subset, not a new full-suite pass, multi-hour capacity result,
native interactive Polkit/input acceptance or independent security review. Inspect
the incompatible upgrade before separately authorized host deployment. Do not
fault-inject or clear guards on the owner's real VPN as a test.
