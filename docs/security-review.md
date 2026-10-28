# Production security review

## Disposition and scope

**Not approved for production use.** This is a first-party, bounded source and
synthetic-reproduction review, not an independent audit, penetration-test
certificate or claim that no other defects exist. The reviewed baseline is
`5948d74b944d713ae11a5f359a5a7311b75d223e` plus the uncommitted implementation.
Generated proof code, resolved proof dependencies and evidence belong under
`target/security-review/`, not in the shipping dependency graph.

The two implementation findings below have local fixes and regression evidence;
their original impact and reproduction remain documented. Production approval
still requires independent review and the release gates below. The
severity is qualitative: neither proof establishes remote code execution, a
privilege escalation or an observed packet leak. No CVSS score is asserted.

## Threat model and boundaries

Assets include NM credentials, subscription URL tokens, endpoint/DNS policy,
session resource ownership and durable non-reassigning FakeIP identities.

- A subscription provider, VPN/DNS peer and network packets are untrusted.
  Explicitly importing a complete configuration grants its admitted routing/DNS
  policy, not permission to execute provider commands or weaken validation.
- The desktop frontend is unprivileged. Its own user/session and the desktop
  Secret Service provider are trusted to handle that user's secrets; encrypted
  transport does not authenticate a compromised desktop or protect against root.
- NM and the system message bus are trusted lifecycle/identity authorities.
  Another user's D-Bus request or a worker request is not root socket authority.
- Treat worker compromise as a relevant containment scenario: the supervisor
  must independently authorize destinations and retain marked IP descriptors.
  The dedicated UID/no-new-privileges boundary is not a complete seccomp or network
  namespace sandbox. Other privileged network services may legitimately coexist;
  a coincident interface name is not evidence of ownership.
- Host root compromise, malicious NM/message-bus implementations and rollback of
  root-owned storage are outside the protection claim. Normal administrative
  errors, conflicting interfaces and failed/delayed teardown remain relevant.

ADR 0026 deliberately restores ordinary networking **without VPN** after terminal
failure. This is not permanent lockdown: a crash or denial of service can end VPN
protection. That owner-approved tradeoff must not be presented as a newly found
kill-switch bypass or silently changed during review.

## Implementation findings and disposition

The defect descriptions in this section refer to the reviewed pre-fix code.
Current implementation and verification limits follow each finding.

### SR-01: Teardown completion does not cover every owned resource

Severity: **Medium — confirmed ordering/assurance defect; packet impact unproven.**

Owners: `crates/nm-service/src/supervisor/session.rs`,
`supervisor/broker.rs`, `lifecycle.rs`, `task.rs` and the TCP/UDP relay owners.

The pre-fix `Session::stop` ignored both `start_kill()` failure and the result of the bounded
child wait. It then aborts/joins the broker task. The broker's relay JoinSets are
dropped during cancellation; Tokio 1.54.1's JoinSet destructor requests aborts but
does not join the child tasks. Preparation cancellation and failed preparation
also use abort-on-drop owners. Consequently, completion of the outer owner alone
does not prove that every nested relay has dropped its socket or that the worker
has exited. The lifecycle can proceed toward guard cleanup without that proof.

The synthetic `relay-lifetime` proof uses the actual production
`stream_relay::run` with loopback TCP/Unix sockets and the broker's JoinSet ownership
shape. After destroying the parent future, the TCP peer still observes an open
connection until relay cancellation is driven; both sockets eventually close.
This confirms the lifetime gap, not the entire Session/TUN path, a
scheduler-independent exploit interval or traffic after an actual nft cleanup transaction. No root,
marks, NM or external peer is used by that proof.

Required remediation:

- Define one shutdown barrier covering the worker, broker, resolver and nested
  TCP/UDP relays on success, failure, retry and cancellation paths.
- Propagate failed/unconfirmed worker termination instead of treating it as
  completed teardown; retain or transfer cleanup ownership without clearing guards
  under an unconfirmed privileged writer.
- Request child cancellation **and await resource release** before allowing guard
  cleanup. A JoinSet abort request or parent-task join is not that barrier.
- Add owner-level regressions for nested live relays, child-wait refusal/deadline,
  cancellation during preparation and retry, using readiness and controlled clocks.
  Verify socket/resource closure before polling cleanup, not only eventual EOF.

Status: **fixed in source; local regressions passed; deployed packet validation pending**.
`supervisor/resources.rs` now owns the child, TUN, telemetry, activation nft writer
and relay sets outside cancellable preparation/broker futures. Stop confirms child
exit, aborts/joins the broker, aborts/joins both relay sets and joins telemetry
before releasing the TUN. Cancellation requests and the 45-second preparation
budget retain this owner through shutdown; retry starts only after confirmed
release. Fatal termination/wait/deadline errors propagate as shutdown failures,
never ordinary activation errors: the lifecycle exits without clearing guards so
the independent helper must confirm backend process exit before recovery.

Regressions cover live production TCP/UDP relays, owned child exit, retained
ownership on refusal, simulated kill/wait/deadline failures, preparation cancellation
with child/nft-writer stand-ins and nested tasks, total-budget expiry, and
cleanup-before-retry. UDP FD closure is observed in the owning process; unrelated
concurrent fork/exec tests can transiently inherit CLOEXEC descriptors. These tests
are not a packet capture of a deployed NM session or proof of complete worker
containment. The original standalone lifetime proof still demonstrates why dropping
a JoinSet alone is insufficient; it is not a test of the new shutdown barrier.

### SR-02: Fixed-name TUN creation can adopt an unrelated interface

Severity: **Medium — reproduced unintended interface adoption/modification.**

Owner: `crates/nm-service/src/supervisor/session.rs` and its pinned `tun-rs` 2.8.13
Linux device-creation consumer.

The activation path invokes the builder with `.name("nmtun0").enable(false)`.
The pinned library uses TUNSETIFF without an exclusive-create flag. A pre-existing
persistent, unattached TUN with that name can therefore be opened as this session's
device. Configuring it disabled alters an interface that the application did not
create. An actively attached non-multiqueue TUN can instead cause a refusal; that
does not make creation exclusive for the persistent/unattached case.

The `tun_collision.py` proof ran the exact builder configuration in a fresh
rootless user/network namespace. It created a synthetic persistent `nmtun0`, set it
up, then observed successful builder attachment to the same interface index and a
transition to down. The fixture was removed inside the namespace. No host link,
route, firewall, NM profile or real VPN was changed. This is not a demonstrated
unprivileged host attack: another administrator/service must have created the
conflicting host interface, or it must remain from an earlier lifecycle.

Required remediation:

- Acquire an exclusively created, session-owned TUN through a reviewed safe library
  API; the pinned builder currently does not expose that guarantee.
- Reject pre-existing interfaces without altering them. A name-existence precheck
  alone is not an atomic exclusive-create guarantee and must not be called a full fix.
- Preserve the workspace unsafe-code prohibition; do not add an unchecked local
  ioctl/FFI workaround or silently change a locked dependency source.
- Add an isolated kernel regression demonstrating unchanged pre-existing interface
  identity, flags and addresses on rejection, including a creation race where feasible.

Status: **fixed in source; isolated kernel collision/race regression passed**.
`supervisor/tun.rs` uses the existing pinned library with no requested name, which
asks Linux to allocate a new nonpersistent TUN, then calls its safe `set_name` API.
The kernel rename atomically refuses an occupied `nmtun0`; only the newly created
device is dropped on refusal. No unsafe code, dependency change or name-existence
precheck was introduced. This reservation occurs before guard installation, so a
collision cannot temporarily authorize another interface through our named rule.

The maintained `check_tun_creation.py` runner invokes the production creator via
the `tun_create` example in a fresh rootless network namespace. It verifies
unchanged identities, flags and addresses for existing persistent `tun0` and
`nmtun0`, no leftover temporary TUN on rejection, and exactly one live winner in a
simultaneous creation race. Dropping owned devices restores the fixture state.
The reviewed kernel contract is the empty-name allocation path in
[Linux v6.12 tun_set_iff](https://github.com/torvalds/linux/blob/v6.12/drivers/net/tun.c)
and RTNL-serialized
[device rename](https://github.com/torvalds/linux/blob/v6.12/net/core/dev.c).
Host-root interference and deployed coexistence acceptance remain outside this
bounded local regression.

## Reviewed controls and remaining risks

Source inspection and existing negative regressions support these bounded claims:

- Control methods verify NM's current unique owner; deployed bus policies restrict
  backend ownership/control and expose only the named read-only observation methods.
- The schema separates credentials from configuration, checks unsupported modes,
  and uses version-pinned NM edits without unconditional fallback or automatic
  retry of unknown writes. NM Delete still has no atomic version/inactivity argument.
- Complete-source admission rejects unknown/duplicate fields and unsupported policy
  rather than extracting a weaker node-only subset. Imports do not execute source
  commands, activate a tunnel or fetch embedded UI/download paths.
- Root independently checks Direct/LAN destinations. IPv6, synthetic and resolver
  restrictions are explicit; upstream IP descriptors stay root-owned and the worker
  receives Unix payload channels. Rejected/ambiguous FD exchanges poison the channel.
- Root source DNS uses a fixed admitted resolver, bounded framing/deadlines and
  checked DNS question/answer membership for public Direct destinations. It expands
  the privileged parser/crypto attack surface; dependency advisory success is not a
  memory-safety review of BoringSSL, protocol libraries or their native code.
- FakeIP publication follows durable append/sync, rejects corrupt/missing journals,
  poisons failed writes and does not evict/reassign identities. Its finite lifetime
  capacity can still be exhausted by many distinct names; this is an availability
  risk to account for, not permission to reset or reuse leases automatically.
- Subscription metadata/URLs use the desktop Secret Service with no plaintext
  fallback, private XDG lock and unknown-write barrier. Credentials still exist in
  process memory; crash-dump, ptrace, descendant-process containment and platform
  keyring-at-rest policies need deployment review, not an unsupported secrecy claim.

These are not independent certifications. Local fixes/regressions for SR-01/SR-02
and passed legacy IPv4 VM echo/crash/hang checks do not cover every source-DNS,
FakeIP, helper-restart, concurrent-control or unrelated-VPN scenario.

## Production release gates

1. Independently inspect the SR-01/SR-02 fixes and repeat their owner-level and
   isolated-kernel regressions; validate deployed teardown ordering in a disposable VM.
2. Independently review privileged source-DNS/Direct execution, worker containment,
   native dependencies and secrets-in-memory/crash behavior under the intended NM
   confinement and Linux capability configuration.
3. Run authorized disposable-VM packet acceptance across DNS/FakeIP/source modes,
   teardown/retry, helper restart, refused nft operations, uplink changes and other
   VPN coexistence. Confirm endpoint/bootstrap and IPv6 leak behavior at boundaries.
4. Complete real desktop keyring/Polkit and native accessibility acceptance. The
   known Wayland capture SIGSEGV remains an unresolved reliability issue; its
   security impact has not been established.
5. Verify public-source packaging, supported platforms, hosted CI, artifact/signing
   and confidential reporting arrangements before promising supported releases.

No production approval follows merely from fixing these two findings or rerunning
the ordinary checks. See [quality](quality.md), [roadmap](roadmap.md),
[ADR 0020](decisions/0020-native-ipv4-source-policy.md) and
[ADR 0026](decisions/0026-automatic-session-recovery.md).
