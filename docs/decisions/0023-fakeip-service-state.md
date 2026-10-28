# ADR 0023: FakeIP state outside NetworkManager's read-only home mounts

Status: fix for the observed Arch NetworkManager service confinement.

The host's NetworkManager service has `ProtectHome=read-only` and
`ProtectSystem=yes`. Its spawned VPN backend inherits the mount namespace.
The former `XDG_STATE_HOME=/root/.local/state` default cannot create the identity
journal there. A root UID does not override a read-only mount. Enabling the boot
reservation or loosening journal permissions would not fix that ownership mistake.

The installed root-owned unit now pins `XDG_STATE_HOME=/var/lib`, producing
`/var/lib/network-manager-tunnel-fakeip-v1/identities.jsonl`. This is explicit
system-service state, outside the home mount; no NM sandbox, capability, route,
DNS or firewall privilege is widened. Activation creates only its private 0700
directory and 0600 journal under the trusted root-owned state base. The unit
remains disabled by default and is still only passive namespace configuration
for ordinary activation under [ADR 0022](0022-session-scoped-guards.md).

Before using the new default, reject an existing or uninspectable former
`/root/.local/state/network-manager-tunnel-fakeip-v1` namespace. Do not read it into
logs, reset it, copy it automatically or silently allocate a replacement epoch.
An existing journal requires explicit offline migration with no active worker,
preserving the full directory, ownership, permissions and every recorded lease.
Custom absolute pins still select their existing namespace and must be writable
under NM confinement. No real journal is opened by ordinary checks.

On the affected host, metadata-only inspection found no former state directory.
Read-only inspection of NM's mount namespace confirmed `/root` is read-only and
`/var/lib` is writable. This does not prove full FakeIP packet/teardown behavior.
Tests cover read-only state failure without creation, a writable service-state
fixture, and refusal to replace former identities without changing journal bytes.
Activation logs distinguish namespace configuration from journal admission with
static redacted diagnostics; no raw filesystem or source data is logged.
