# ADR 0022: Automatic, session-scoped VPN and FakeIP protection

Status: owner-approved replacement of ADR 0016's mandatory boot reservation.

Failure retention and manual recovery below are superseded by
[ADR 0026](0026-automatic-session-recovery.md). Session scope and identity ownership
remain; terminal failures now automatically return to ordinary networking.

## Decision

The ordinary profile owns protection automatically: install the main guard and,
for FakeIP, the reserved `198.18.0.0/15` guard before exposing tunnel readiness.
A failed installation refuses activation. On clean NM Disconnect, stop the worker,
broker and relays first, then delete both owned nftables tables in one transaction.
An absent table is harmless; observation/transaction failures report teardown
failure rather than silently opening the network. No unrelated tables are touched.

The original decision retained protection on unexpected failure and required
separate privileged recovery. ADR 0026 supersedes that rule: terminal failure stops
resources and automatically removes both guards, with independent orphan/hang
recovery. No new privileged GUI API is introduced. The compatibility root
`--clear-guard` command removes both session tables but is not ordinary recovery.

FakeIP activation no longer requires enabled/active boot service state or an NM
Requires dependency. The installed unit's single absolute XDG state pin is still
read passively via systemd, even while disabled, preserving the existing identity
namespace independently of caller HOME/XDG variables. No enable/start call occurs.
Unsafe or missing state configuration still rejects before journal/network work.

The optional legacy restoration unit remains available for explicit administration
but no longer declares `RequiredBy=NetworkManager.service`. It is never automatically
enabled; normal profile protection does not depend on it. Existing installations
that previously enabled the old unit must explicitly disable its old symlinks to
retire the old boot policy; installing a new unit file alone does not remove those
symlinks. Do not delete, reset or roll back the identity journal.

## Deliberate tradeoff

After clean disconnect, terminal failure or reboot without optional restoration,
we make no guarantee
against physical egress to cached synthetic addresses. DNS/application caches may
need to expire or applications may need to retry. Flushing the system DNS cache
alone cannot flush every application's cache. This is not protection outside VPN
and must not be advertised as such. Persistent non-reassigning identities remain
useful across reconnects and are retained; persistence does not imply a permanent
firewall or permission to block NetworkManager startup.

Permanent lockdown is not a hidden prerequisite of a profile checkbox. A future
strict mode would require a separate explicit setting and lifecycle/boot tests.

## Evidence and limits

Private-bus tests exercise namespace discovery with no enable/start/status or
RequiredBy APIs and reject malformed pins without creating state. Guard tests
cover exact transaction scope; current lifecycle tests await automatic cleanup and
propagate transaction refusal without claiming success. Ordinary tests do not change
host networking.
Authorized package update/reconnect checks are host evidence, not comprehensive
crash/boot/packet or desktop acceptance.

Behavioral references, not imported code:

- [Amnezia KillSwitch documentation](https://docs.amnezia.org/documentation/instructions/killswitch)
- [Amnezia 5.0.3.0 Linux teardown](https://github.com/amnezia-vpn/amnezia-client/blob/5.0.3.0/service/server/killswitch.cpp)
- [Mullvad kill switch and separate Lockdown](https://mullvad.net/en/help/using-mullvad-vpn-app)
