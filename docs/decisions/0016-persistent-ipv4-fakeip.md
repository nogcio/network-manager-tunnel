# ADR 0016: Durable, non-reassigning IPv4 FakeIP identities

Status: experimental IPv4 implementation; exact-source and native/boot acceptance pending.
Date: 2026-10-26.

The mandatory boot gate and post-disconnect reservation described below are
superseded by [ADR 0022](0022-session-scoped-guards.md). Identity/journal invariants
remain unchanged; ordinary activation needs no enabled boot unit, and clean
disconnect removes both guards. The following boot section records the prior design.

## Scope and admission

`Draft::fake_ip` is default-off and requires explicit DNS interception. NM schema
v2 stores only `dns-fakeip=persistent-ipv4-v1`; unknown modes and v1 downgrade fail.
It allocates from `198.18.0.0/16`, with network/gateway/internal addresses excluded.
The residual/boot physical-output reservation now covers `198.18.0.0/15` for
[bounded source-policy support](0020-native-ipv4-source-policy.md), without expanding
the allocator or identity capacity. This mode is IPv4-only: A gets a synthetic
address, AAAA gets NODATA and
IPv6 remains blocked. Other query types use the selected upstream. It is not
admission of source configurations requiring IPv6 FakeIP or arbitrary pools.
The later [IPv4-only decision](0017-ipv4-only-first-version.md) defers IPv6 FakeIP
instead of requiring it before the first joint test. Complete IPv4 source-policy
translation/disclosure now follows ADR 0020; unsupported required policy still rejects.

The full importer still rejects required unsupported policies without extracting
nodes. COSMIC now exposes a default-off additional opt-in requiring explicit
interception; required source modes cannot be disabled by those switches. Saved
details observe the explicit mode. Checked replacement is in
[ADR 0018](0018-checked-profile-replacement.md). DNS overrides remain separate: CurrentNetwork
uses the selected uplink resolver; default/manual uses VLESS, without fallback.

## Identity and storage ownership

Root exclusively owns the identity journal. The boot unit pins absolute
XDG_STATE_HOME (default `%h/.local/state` for root); append
`network-manager-tunnel-fakeip-v1/identities.jsonl`. Inherited desktop/NM HOME or
XDG variables do not select another identity epoch. Ancestors
must be trusted root/current-user directories, not symlinks or writable by other
users/groups (root-owned sticky directories have their usual ownership protection).
The identity directory is owner-only, the single-link regular journal is owner-only,
and directory flock prevents concurrent allocators. Leaf opens use NOFOLLOW.

The journal contains canonical DNS names in allocation order, not profiles,
credentials, subscription URLs or arbitrary source cache paths. Names can still
be identifying/sensitive: never log, report, index or send this file to an AI service.
The worker cannot choose a path or read the file. Root's XDG location is not the
desktop user's cache. It must agree with the boot guard's environment.

Append and fsync each new identity before publishing its DNS answer. Initial file
and directory creation is synced, including new parent directory entries. Rebuild
the same sequence on reopen. Corrupt, duplicate, noncanonical, truncated, oversized,
unsafe or missing-in-existing-directory journals reject without repair/reset. A
write failure poisons the store; no allocation/reverse lookup is then admitted.
Existing published identities survive reopen. Never delete, roll back or edit the
journal to recover availability: cached addresses may still be in applications.
Privileged external deletion/rollback of the entire trusted state is outside this
integrity boundary; it must not be an automatic application action.

Allocation reuses the pinned `meow-dns::fakeip::Pool` with MemoryStore, but bounds
identities to 16,384, below pool wrap and store eviction. The library sees opaque
lease IDs, not private domain names in its debug tracing. Capacity exhaustion
rejects without reassignment; existing leases remain usable. The journal is at
most 5 MiB. FileStore's debounced best-effort persistence/corruption reset is not
used. No handwritten FakeIP address allocator or DNS parser is introduced.

Blocking filesystem work runs on Tokio's blocking pool. Cancellation may leave a
durable append completing in root, but no reply is published on the cancelled
channel. That task retains the journal lock until completion; a replacement cannot
race a half-finished writer or reset identities. IPC deadlines bound worker waits.

## Runtime and routing

NM receives internal DNS `198.18.0.2`. Intercepted A/AAAA requests use bounded private
FakeIP RPC; messages/replies retain existing DNS validation and 4096-byte bounds.
Reverse RPC accepts only a reserved IPv4 address and returns a checked canonical
name. No requester-provided resolver, interface, path or prefix is accepted.

TCP/UDP synthetic destinations require root-owned reverse identity before outbound
admission. Unknown addresses reject without proxy/direct fallback. A blocked name
rejects before real DNS. Resolve permitted names through the selected upstream,
binding A/CNAME question/answer ownership, then evaluate the known domain rather
than guessing from a shared IP. Explicit domain rules precede connected-LAN
fallback. Synthetic addresses are never sent as destinations to the remote proxy.
Raw non-FakeIP flows retain the prior inspection/dispatch behavior.

The existing checked hostname policy also applies to FakeIP-owned UDP names in this
explicit mode. New UDP Direct grants require root's FakeIP flag, its own Direct
policy and independent DNS/IP verification; legacy TCP-only policies cannot grant
UDP. Root retains each direct UDP IP socket behind the bounded payload relay.
Readiness requires configured-peer secure transport and durable local FakeIP/reverse
identity round trip; a synthetic DNS answer alone cannot certify a working proxy.

## Reserved-range guard and boot gate

Cached synthetic destinations must not fall through to a physical default when
the VPN disconnects. FakeIP activation installs a separate narrow
`nm_tunnel_fakeip` output guard: normal traffic is accepted, but physical egress to
the reserved /16 is blocked, including marked sockets. Clean disconnect removes
the ordinary VPN guard, not this reservation. It creates no route/DNS writer.
Explicit root `--clear-fakeip-guard` is separate from `--clear-guard`; flush all
DNS/application caches first. Clearing the rule never deletes the identity journal.

Runtime nft state alone does not survive reboot. The package supplies optional
`nm-tunnel-fakeip-guard.service`, which restores the narrow guard before NM and
network-pre. It runs once with NET_ADMIN, no network sockets other than netlink/
Unix, a read-only filesystem and no home access. It never opens identities, starts
a VPN, writes routes/DNS or changes profiles. Once explicitly enabled, it reserves
the range on every boot, even when the VPN is off or the journal is unavailable.

Enabling installs a Requires dependency for NetworkManager.service: guard failure
blocks NM startup instead of allowing stale-address egress. This is an important
system-wide opt-in, not an automatic package hook. Activation checks persistent
enablement (not enabled-runtime), that RequiredBy relationship, and exactly one
absolute XDG pin via the manager's read-only GetUnitFileState/LoadUnit/property
interfaces. It does not enable/start anything. Failure occurs before state creation
or network changes. Do not change the pin, disable the unit or remove the package
while relying on cached identities without an explicit migration/retirement plan.

Installation/enabling require owner authorization during the eventual joint test.
Ordinary checks neither install/enable the unit nor create the real journal or rules.
The unit was parser-verified with local systemd 262; private-bus tests cover gate/
namespace rejection without side effects. Real boot/dependency/capability/firewall
acceptance is still missing. Contract references: installed systemd 262 D-Bus XML
and the [versioned manager API][systemd-api].

[systemd-api]: https://www.freedesktop.org/software/systemd/man/258/org.freedesktop.systemd1.html

## Evidence and gaps

Synthetic tests cover stable reopen, exclusive ownership, corruption/torn-write
rejection without mutation, failed writes, exhaustion without reassignment, DNS
identity/reverse pairing, unknown destinations, block-before-real-DNS and rejection
of unrelated A records. Model/schema tests preserve required interception and reject
unknown modes/downgrades. Client observation reads no secrets or live journal.

Power-loss/boot reservation acceptance, packet-level isolation, positive selected
resolver/proxy interoperability, UDP reply attribution, full source policy and
native [saved-profile replacement](0018-checked-profile-replacement.md) still need
authorized acceptance. This
experimental IPv4 layer is not the complete requested FakeIP/LAN/subscription feature.
