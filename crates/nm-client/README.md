# NetworkManager profile client

Unprivileged D-Bus client on `zbus` 5.19. Pure schema-v1 encoding is separate from
explicit async storage/control and read-only NM metadata observation. No direct
route/DNS/firewall changes, secret retrieval, credential agent or keyring access.

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

## Observation and explicit control

`snapshot` reads NM GetSettings (not GetSecrets), Unsaved and active metadata.
It filters this service's schema-v1 VLESS profiles and returns NM-issued saved and
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
update/delete/migration API; later schema support must reject unknown versions.

## Read-only backend usage

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

`lab_import` accepts a subscription URL through private stdin,
without persisting it or putting it in command-line arguments.
It saves supported profiles and credentials persistently in NM, without activation;
the URL itself is never saved. Use only with explicit authorization for disk storage.
Input must reach EOF within 20 seconds and contain at most 4096 bytes. A detached
standard thread bounds the read before starting the async runtime; on timeout the
process can exit even if the pipe remains open. Diagnostics never include input.
