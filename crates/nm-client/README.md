# NetworkManager profile client

Unprivileged D-Bus client on `zbus` 5.19. Pure schema-v1/v2 encoding is owned by the
[shared NM contract](../nm-schema/README.md), separate from
explicit async storage/control and read-only NM metadata observation. No direct
route/DNS/firewall changes, secret retrieval, competing credential agent or direct
VPN keyring access.

Service identity is experimental `org.freedesktop.NetworkManager.tunnel`.
The experimental backend owns it when running. Save creates a new NM connection UUID;
it is independent of the authentication UUID. Autoconnect is always false.

## Experimental schema v1

`vpn.data`: `schema-version`, `protocol`, `server`, `port`, `transport`, `security`,
`server-name`, `fingerprint`, `flow`, `alpn`, `uuid-flags`; REALITY additionally uses
`public-key` and `short-id`. `vpn.secrets.uuid` alone contains the VLESS credential.
WebSocket additionally stores `websocket-path` and, when explicitly supplied,
`websocket-host`. `transport=ws` is distinct from TCP, and Host is never substituted
for TLS SNI. The experimental service consumes this schema; its synthetic VM
evidence is separate from serialization tests in this package.
`uuid-flags=0` delegates storage to NM without claiming desktop agent ownership;
`save_profile` always requests persistent storage (AddConnection2 TO_DISK, flag 1)
and returns an NM-issued handle. Callers must explain before explicit Add that NM
saves profiles and credentials on disk. NM owns authorization and backing-file
permissions; the client never writes profile files itself. This is not desktop
secret-agent/keyring storage or encrypted-at-rest storage. A refused disk save
never falls back to memory. There is no session-only save API. Existing in-memory
profiles can still be observed/controlled, but are not automatically migrated.

`save_profile_with_options` adds explicit standard `CredentialStorage::System`,
`Agent` and `Ask` flags plus NM's persistent-session option. The COSMIC save path
uses Agent and persistent lifetime for new profiles, with disclosure before Add.
The existing API keeps its defaults. NM routes credentials to a registered desktop
agent; this client never accesses a VPN keyring. Agent availability/prompt/keyring
acceptance is not proved by a settings-write reply. Failure does not select system
storage. A persistent admitted lifetime survives network loss under its guard until
recovery or explicit Disconnect; it does not enable autoconnect. See
[ADR 0033](../../docs/decisions/0033-persistent-network-lifetime-and-nm-agents.md).

## Observation and explicit control

`runtime.rs` owns the public handles and one total deadline per operation.
`transport.rs` pins the bus ID and unique NM owner and builds uncached proxies;
it contains no profile or write policy. `runtime/observation.rs` owns read-only
metadata admission, version-bracketed settings reads and handle revalidation.
`runtime/mutation.rs` consumes those checks for explicit storage/control requests
and owns refusal versus indeterminate-outcome classification. It never retries or
performs a fallible read after a confirmed write. The private-bus tests exercise
these concrete owners together; no parallel client implementation is used.

Profiles with `Draft::tcp_domain_policy` or an explicit `Draft::dns_override` use
NM schema v2 and checked `vpn.data.tcp-domain-policy`/`dns-override` fields. V1 must
not carry them and v2 requires at least one, so older backends reject the new schema
rather than ignoring routing or resolver selection.
Explicit `Draft::lan_bypass` also selects v2 and stores only
`lan-bypass=connected-rfc1918`, not live prefixes or an interface name. Saved handles
observe that mode; it is distinct from broad private-IP subscription rules. See
[ADR 0012](../../docs/decisions/0012-connected-lan-bypass.md).
The separate `Draft::private_lan_bypass` stores `lan-bypass=private-rfc1918` in v2.
Saved metadata distinguishes the broad physical mode without widening old profiles
or storing live routes. See [ADR 0024](../../docs/decisions/0024-private-ipv4-bypass.md).
`Draft::dns_interception` additionally uses v2 `dns-interception=tun-port53`.
Saved handles expose the observed mode without secrets, query payloads or a live
network probe. It is default-off; combined connected-LAN mode uses TCP/UDP relays
after DNS interception, with other local IP protocols unsupported; see
[ADR 0013](../../docs/decisions/0013-tun-dns-interception.md).
`Draft::fake_ip` stores only `dns-fakeip=persistent-ipv4-v1` and is observed in saved
handles without reading the journal. It requires interception, does not imply IPv6
or complete import support. Protection is session-scoped, with no boot enablement prerequisite;
see [ADR 0016](../../docs/decisions/0016-persistent-ipv4-fakeip.md).
Profile observation accepts both versions without retrieving credentials. Legacy
v1 profiles are unchanged. This backend API does not add a profile editor or full
sing-box subscription importer; policy and limits are in
[ADR 0010](../../docs/decisions/0010-tcp-domain-routing.md).
Saved handles include DNS override metadata without reading secrets or DHCP state.
CurrentNetwork stores no live resolver address. Replacement below can explicitly
change saved DNS policy; it is not a manual DNS editor. See
[ADR 0011](../../docs/decisions/0011-profile-dns-overrides.md).

`snapshot` reads NM GetSettings (not GetSecrets), Unsaved and active metadata.
It filters this service's schema-v1/v2 VLESS profiles and returns NM-issued saved and
active handles. Profiles removed/raced during reads produce unknown/error state,
not an invented Disconnected state. Lists are bounded at 1024 NM objects each.
Backend registration checks D-Bus ownership/activatable names without starting the
service and is not protocol/readiness certification.

`activate` and `deactivate` use standard NM APIs on explicit user action only.
Interactive authorization is permitted for these writes/saves; actual desktop
Polkit presentation still needs native acceptance. Successful replies mean accepted
requests, not tunnel readiness or resource cleanup; observe subsequent NM state.
The GUI may close without affecting NM's connection. Handles are tied to NM's
bus ID (`GetId`), unique NM owner, path and independent UUID and are revalidated
before mutation. Current NM ownership is checked immediately before writes and
before publishing a snapshot, even if the former owner remains connected.
Stale objects/owner replacement must not target a new connection by path reuse.
Ownership may still change between the final check and request dispatch; D-Bus
offers no atomic ownership-check-and-call operation. Calls address the pinned
unique owner, never its replacement. Successful writes do not perform a fallible
post-write ownership read: their returned handles may already be stale.

NM operations have a 20-second deadline. A missing reply, transport loss or timeout
is indeterminate and does not prove rollback: it must not trigger automatic retry.
Cancelling a future can also leave a remotely completed operation. D-Bus serialization creates
transient credential copies; Debug redaction is not zero-copy/zeroization assurance.

Private tests exercise serialization and client-owned lifecycle/identity rules on
a real private bus, not NM's implementation. The explicit `lab_control` example can
exercise the public API in an authorized disposable guest; it is not a complete
VM test harness. Ordinary checks perform no host saves or activations. There is no profile
automatic migration API; later schema support must reject unknown versions.
The VM-only `lab_control storage` mode exercises real persistent save, narrow edits,
stale-version refusal, source override preservation and deletion without activation.
It refuses a pre-existing fixture name. The lifecycle probe optionally accepts a
synthetic peer public key through `NM_TUNNEL_LAB_PUBLIC_KEY`, only after its existing
VM/authorization admission. It is not a subscription credential input or GUI setting.

## Narrow profile edits, source updates and deletion

COSMIC consumes `edit_profile`, `delete_profile` and `update_from_source`; no new
dependency, native library or privileged service API is added. See
[ADR 0027](../../docs/decisions/0027-cosmic-profile-and-source-management.md).

`ProfileChanges` patches name and checked network keys through the shared codec.
Editing preserves all other NM fields and includes no secrets, relying on NM's
documented/inspected retain-existing-secrets behavior. Source refresh instead supplies
the admitted new source credentials, retaining the NM name/UUID/ACL, IP dictionaries
and compatible existing DNS/LAN/protection overrides. Credential storage mode and
persistent lifetime also survive both source updates and checked replacement.
New mandatory-policy conflicts
reject before writes. Both use expected VersionId and Update2 flags `0x61`, never
reconnect and never perform fallible post-write reads or guess the next version.
Confirmed success requires a new snapshot before another checked mutation.

`delete_profile` accepts an observed inactive, versioned handle. It checks identity,
version and inactive NM observation before one Delete; the caller must explicitly
confirm and await observed disconnection for active profiles. NM owns credential
deletion. NM Delete has no atomic version/inactivity precondition, so a concurrent
external activation/edit after local validation cannot be excluded. No teardown,
guard cleanup, cascade deletion or retry is performed by this API.

Each operation has one 20-second deadline. Missing replies, cancellation and transport
loss are unknown write outcomes; do not retry or claim rollback. Multiple source
updates are not a transaction. Private-bus tests validate outgoing fields, identity,
version/refusal/unknown outcomes, inactive deletion and absence of reconnects, not
native NM storage, Polkit or live-session behavior.
A bounded owner-authorized Arch KVM check with NM 1.58.1 passed the above inactive
storage workflow through the real public API. A guest `nobody` client without an
authorization agent was refused; a subsequent root check found no leftover fixture.
This verifies definite refusal, not desktop Polkit prompts or active-session editing.

## Checked saved-profile replacement

`replace_profile` is consumed by the authorized lab-import example; COSMIC uses the
narrow edit and mapped update APIs above. It keeps the NM UUID, name, connection ACL and other
connection-level settings, but **replaces the entire VPN/IPv4/IPv6 sections**,
including old custom overrides, with the selected validated profile. The caller
must disclose replacement and the retained credential storage mode before confirmation.
No GetSecrets,
automatic activation, reconnect, fallback or independent profile storage is added.

Replacement requires a fresh snapshot with nonzero VersionId (NM 1.44+). Reads are
uncached and checked before/after settings; Update2 uses the expected version-id
plus TO_DISK/BLOCK_AUTOCONNECT/NO_REAPPLY. Stale/unsupported targets reject, without
unconditional Update fallback. Newly saved/replaced handles must be refreshed before
another replacement. Success means a confirmed saved update, not live application;
reconnect explicitly later. Cancellation/timeout can leave a completed remote update,
so never automatically retry or roll it back. UI blocks further saves on ambiguity.
The API has one 20-second total deadline and adds no dependencies or native cost.
See [ADR 0018](../../docs/decisions/0018-checked-profile-replacement.md) for contracts/evidence.

## Read-only backend usage

Usage and recovery share `transport::ReadOnly` for pinned unique-owner observation
and final owner revalidation, independently of NM mutation identity.

The COSMIC frontend consumes `usage_snapshot`, separate from NM profile observation.
It reads the service's [telemetry v1 contract](../nm-service/README.md#read-only-usage-telemetry)
with a three-second total deadline and no activation or interactive authorization.
No owner means `Ok(None)`; sanitized `UsageError` distinguishes unavailable from
unsupported/malformed responses. Reads pin/recheck the unique service owner,
disable property caching and set NoAutoStart. Cancellation stops only read-only work.

Public `UsageSnapshot`, `TrafficSample` and `TrafficCounters` mirror the versioned
D-Bus response. Version, bounded history, timestamps and known state/stage values
are validated before publishing. Replace each complete snapshot; never merge charts
across owner changes/generations. Account for local time since receipt when deciding
freshness. Last counts may be historical; worker readiness is not NM activation or
firewall certification. No profile identifiers, endpoints or credentials are fetched.

## Independent recovery observation

Current source adds explicit protection release under
[ADR 0034](../../docs/decisions/0034-explicit-disconnect-protection.md).
`deactivate` pins the helper generation before the standard NM request and only
then requests authorized release. `disconnect_protection` is the explicit fallback
when a crash has removed NM's active object. Both are user actions, never read-side
recovery. The helper checks Polkit NM network-control and process exit; no private
profile database, credential access or client-side nft/route writer is introduced.
Owner/generation changes and failed/ambiguous requests do not retry automatically.
V2 adds `Blocked` status; the remaining read-only observation contract below applies.

COSMIC consumes `recovery_status` without starting the helper or backend. It returns
None for absent ownership, not confirmed cleanup. The three-second total deadline,
NoAutoStart, uncached proxy and owner recheck match usage observation. Typed
`RecoveryStatus` covers the helper's v1 starting/watching/termination/cleanup/retry/
confirmed-cleanup and backend-cleanup states; `RecoveryError` sanitizes unavailable
versus unsupported/malformed results. No control method, process identity, profile
data, secret or normal-route observation is exposed. Age observations locally;
confirmed guard cleanup does not prove VPN recovery or NM route teardown. Cancellation
drops read-only work. The only production consumer is the independent COSMIC status
projection; this adds no external dependency or native cost. See
[ADR 0026](../../docs/decisions/0026-automatic-session-recovery.md).

## Explicit lab import

`lab_import` accepts a subscription URL through private stdin,
without persisting it or putting it in command-line arguments.
It saves supported profiles and credentials persistently in NM, without activation;
the URL itself is never saved. Use only with explicit authorization for disk storage.
The default now requests complete configuration and stops before any NM write on
unsupported policy. `--nodes-only` explicitly selects legacy import without the
source's DNS/routing; it must not be used as an automatic policy-rejection fallback.
Input must reach EOF within 20 seconds and contain at most 4096 bytes. A detached
standard thread bounds the read before starting the async runtime; on timeout the
process can exit even if the pipe remains open. Diagnostics never include input.

In an explicitly authorized lab guest, append
`--replace NM_CONNECTION_UUID --entry NUMBER` (one-based source entry) to update
exactly one observed target instead of adding profiles. `--nodes-only`, if desired,
must still be explicitly specified first and does not preserve source policy.
The target UUID is NM's independent connection ID, never a VLESS authentication UUID.
Unsupported source/entry or missing/ambiguous target rejects without a write. No
activation or automatic retry occurs. Ordinary repository checks do not run it.
