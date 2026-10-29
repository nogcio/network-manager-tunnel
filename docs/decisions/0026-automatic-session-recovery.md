# ADR 0026: Automatic recovery and return to ordinary networking

Historical decision: terminal unblocking is superseded by
[ADR 0034](0034-explicit-disconnect-protection.md). The descriptions and VM evidence
below document the former v1 policy, not the current protection contract.

Status: owner-approved behavior change; implemented experimentally, bounded legacy
IPv4 VM crash/hang acceptance passed; broader packet/source-policy acceptance pending.
Supersedes failure-retention/manual-recovery behavior in
ADRs 0006, 0007, 0014, 0016, 0020 and 0022, not their in-session authorization rules.

## Decision

The owner explicitly selected automatic return to ordinary networking when VPN
recovery cannot succeed. This is session protection, not permanent lockdown.
During an admitted session and recovery attempt, endpoint bypass, DNS policy,
IPv6 blocking and refusal without outbound substitution remain mandatory. A terminal
failure ends the VPN session and removes its two guards automatically. Traffic can
then use ordinary networking **without VPN**; this is a deliberate privacy tradeoff,
not a claim that the failed VPN recovered.

Preparation can retry the same admitted input once after one second, within one
45-second total budget and before reporting readiness/IP configuration to NM.
Inputs remain memory-only; cancellation owns pending preparation and retries.
Existing health/endpoint recovery handles transient runtime failures without replaying
application streams. Fatal worker/broker failure terminates the session; it does not
secretly recreate NM routes, choose another profile or automatically reactivate NM.

## Cleanup ownership

- Disconnect, preparation exhaustion, fatal worker/broker failure and shutdown stop
  owned resources and start cleanup. The backend reports stopping while cleanup is
  pending and never admits a replacement session over unfinished cleanup.
- Bounded nft observations distinguish confirmed absence from command/parse failure.
  Both owned tables are deleted in one transaction; errors retry once per second.
  No unrelated table, profile, route, resolver or FakeIP journal is modified.
- Preparation/session resources outlive cancellable setup and broker futures.
  Cleanup and retry require confirmed child/activation-writer exit and joined
  broker/TCP/UDP/telemetry tasks; an abort request alone is not completion. The
  45-second setup budget excludes subsequent shutdown. A kill/wait/deadline failure
  ends the backend without clearing guards and transfers recovery to the independent
  process-exit gate. See
  [SR-01](../security-review.md#sr-01-teardown-completion-does-not-cover-every-owned-resource)
  for local evidence and remaining deployed acceptance.
- Before installing a guard, the backend must successfully arm the root-only
  `org.freedesktop.NetworkManager.tunnel.Recovery` service. Missing helper packaging
  refuses activation before new guards, rather than assuming recovery is available.
- The helper is D-Bus-activated in its independent systemd unit/cgroup, with only
  CAP_NET_ADMIN and Unix/netlink sockets. Direct fallback execution without its
  systemd environment refuses startup. Installation never enables a boot unit.
- The helper watches backend name ownership and lifecycle liveness, never
  D-Bus-activates that backend. Arm/Renew accept only its current unique sender;
  system-bus policy additionally restricts control to root. The helper obtains
  `ProcessFD` from D-Bus connection credentials, not a requester-supplied descriptor
  or numeric PID. Missing ProcessFD support refuses activation before guards; no
  PID-based fallback or unsafe-code exception exists.
- The lifecycle loop itself renews a 30-second lease every two seconds after its
  first admitted activation, including after cleanup while awaiting NM. A separate
  heartbeat task must not hide a stuck lifecycle owner. Renewal has a three-second
  total deadline; failure ends that backend lifetime. A late heartbeat cannot revive
  an expired lease. Helper restart reacquires the current bus-supplied process handle
  and a fresh lease without a recovery journal.
- Lost ownership or lease expiry triggers SIGKILL through that process-pinned FD.
  Cleanup is never polled until process-exit readiness is confirmed. Signaling or
  exit-observation failure retains protection and retries, rather than clearing
  under a potentially live privileged writer. Worker parent-death signaling and
  closed broker channels terminate the orphan worker; deployed ordering needs VM
  acceptance. Severe scheduling stalls can also expire the lease: this intentionally
  ends the session and restores ordinary networking without VPN, not hidden redial.
- A shared gate serializes process termination/cleanup with Arm acknowledgement:
  a new backend cannot install protection until preceding cleanup succeeds. Closed
  helper shutdown admission cannot acknowledge a final Arm while exiting.
- systemd restarts a crashed helper without a start-rate cutoff. It retries failed
  cleanup and retains confirmed orphan-cleanup status for 30 seconds before exiting.
  Bus observation failure does
  not prove an orphan; the helper restarts to reconnect rather than unblocking on
  uncertain ownership. The helper stores no credentials, profiles or recovery journal.

The unprivileged frontend never clears firewall rules or retries ambiguous NM
writes. Method completion/NM Disconnected still does not certify completed cleanup;
the backend's terminal telemetry follows confirmed cleanup when it remains alive.
The helper separately exposes read-only `GetStatus` v1: starting, watching,
terminating, cleaning, retrying, cleaned and backend-cleanup. It takes no profile,
endpoint or PID arguments and stays readable while the control/cleanup gate is held.
Only that exact path/interface/member is allowed to ordinary clients. The client
pins/rechecks its owner, disables auto-start and uses a three-second total deadline.
COSMIC observes it independently of NM/HTTP/traffic and ages the result locally;
missing/stale/unavailable status is not confirmed cleanup. `cleaned` is a historical
guard-cleanup result, not restored VPN readiness or proof of NM route removal.

## Verification and limits

Private-bus tests cover current-owner admission, no cleanup while a live leased backend
owns the name, orphan cleanup, transaction refusal, shutdown admission closure,
unknown-bus rejection and the deployed status-only policy. Owned-child pidfd tests
cover termination-before-cleanup, idempotence and refusal without polling cleanup.
Controlled clocks cover lease expiration and late-renewal rejection; client/frontend
tests cover non-activation, owner replacement, malformed status, independent slots
and stale results. Controlled
clock tests cover bounded preparation retries/deadline. Resource tests retain
ordered cancellation; guard tests check transaction scope and tri-state inspection.

These do not establish deployed system-bus activation, systemd cgroup/restart
behavior, SIGKILL recovery, real NM route removal or packet acceptance. Verify those
in an explicitly authorized disposable VM before installation. Kernel/privilege,
systemd or filesystem failure cannot be guaranteed recoverable by application code;
failed operations remain failed and retry, never become fictional success. Manual
administrative commands remain compatible tools, not the ordinary recovery contract.

The watchdog and read-only progress projection are implemented. The bounded VM
evidence below is not full production acceptance. Process termination expands the
helper's authority even though its
CAP_NET_ADMIN bounding set is unchanged (it signals the same root UID through the
bus-supplied pidfd). Owner review of these changes and the narrowly scoped status
policy is required before production installation. Ordinary checks do not install
or enable services; explicit acceptance installation below was confined to the VM.

### Bounded disposable-VM evidence

The owner-authorized KVM acceptance used the official Arch cloud image
`20261015.611680`, verified against the arch-boxes published signing key and SHA-256,
then updated inside its disposable overlay to kernel 7.2.11, NetworkManager 1.58.1,
nftables 1.1.7 and Polkit 128. During this VM check, only the guest received the
current backend and its production D-Bus/systemd/sysusers packaging. The host
VPN/service installation and host routes, DNS and firewall were unchanged by that
check. Test peers and destinations were
synthetic and confined to the guest's network namespace; no provider was contacted.

The real NM client saved and activated the legacy REALITY profile, verified TCP echo
through the actual TUN and exited while NM kept the session alive. A fresh client
disconnected it, and owned guards were observed absent. Subsequent activations
exercised backend SIGKILL and SIGSTOP. In both cases the independent helper removed
the guards and NM ended the VPN; after lease expiry the stopped process was also
observed absent. These final observations do not independently timestamp every
termination/cleanup step. No manual guard-clear command completed
these tests. Generated scripts/logs are under `target/native-acceptance/vm/`;
`tunnel-direct-fixture.log` records the successful bounded run. The VM was shut down.

This evidence is limited to that synthetic legacy IPv4 path. It does not establish
helper-crash/restart races, refused nft transactions, every DNS/FakeIP/source-policy
mode, unrelated-VPN coexistence, long-running reliability or provider compatibility.
Those remain required acceptance categories, not implied by a successful TCP echo.
