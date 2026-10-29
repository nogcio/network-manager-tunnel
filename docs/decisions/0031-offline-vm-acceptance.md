# ADR 0031: Offline, process-owned VM acceptance

Status: implemented for baseline IPv4 REALITY lifecycle and packet acceptance;
broader source-policy, roaming, desktop and performance acceptance remain separate.

## Decision

Maintain a single explicit runner under `scripts/check_vm.py`, with host VM
ownership, guest orchestration, protocol fixtures and lifecycle scenarios in
separate modules. The shared versioned contract declares required cases and result
identity. Missing cases, tools, packet witnesses or cleanup fail the invocation.
Ordinary repository checks never start this privileged guest workload implicitly.

Use a checksum-verified, standalone, pre-provisioned Arch cloud image with a new
disposable overlay per run. Image construction/upgrades and acceptance are separate;
acceptance never downloads packages/peers or uses personal VPN credentials. Input
hashes and exact guest package versions identify the environment. Source archives
can run without Git metadata; the payload manifest remains authoritative for inputs.

QEMU has no network device. A guest NM-managed veth and peer namespace provide
the entire synthetic network. A dedicated virtio-serial result channel carries
bounded structured evidence independent of VPN routing and guest failures. Do not
restore SSH connectivity by adding a management bypass to production guard rules.
Documented systemd boot credentials disable only external-network/time boot waits
that this intentionally offline topology cannot satisfy. Actual NM/device/listener
readiness and positive packet controls remain required.

Production service registration is installed only inside the guest. Fault injection
pins the targeted process with pidfds; production NM/recovery owns teardown, rather
than a test manually deleting protection. An unrelated firewall sentinel verifies
noninterference. Positive unprotected IPv4/IPv6/DNS controls and a zero-drop packet
witness prevent vacuous negative leakage assertions. Reports preserve the narrow
observation windows and do not claim every possible packet/failure ordering.

The host owns and waits exactly its child VM, including timeout/interrupt/failure.
It never installs a host service, changes host networking or accepts guest commands.
Artifacts and the overlay remain private under `target/` for offline diagnosis;
the base image is checked again after the VM exits. There is no mandatory private
service, new Rust dependency, generic scenario plugin system or automatic publication.

## Consequences

Preparing an authenticated image and pinned peer is an explicit prerequisite, not
a hidden network operation. The baseline uses the existing native lab client and
protocol libraries rather than implementing profile/DNS/VLESS wire formats again.
The client observation loop may retry a transient stale read, never an uncertain
save or activation. Repeated full runs use fresh overlays; scenarios fail fast and
declare their ordered lifecycle preconditions.

The [suite contract](../testing/vm-acceptance.md) owns commands, evidence, extension
rules and the remaining acceptance categories. Image replacement validates runtime
generation handoff, not arbitrary cross-version compatibility or pacman semantics.
