# Architecture

Current implementation status lives in the [project README](../README.md);
pending product work lives in the [roadmap](roadmap.md).
See [ADR 0001](decisions/0001-foundation.md) for foundational boundaries.

## Objective and non-goals

Build a Linux NetworkManager VPN integration using Rust protocol libraries, with
separate KDE, GTK and COSMIC frontends. The first protocol target is client-side
VLESS + REALITY + Vision. No external sing-box/Xray core is shipped or launched.
Rust application code may depend on native libraries such as BoringSSL; a pure-Rust
transitive graph is not currently a requirement. Native KDE adapters may need C++.

No server implementation, mobile support, generic rule-engine clone, subscription
service, web dashboard or custom dynamic protocol-plugin ABI is in the initial scope.

## Control plane

```text
KDE editor      GTK editor      COSMIC editor      CLI
     \              |                |             /
             shared profile/validation logic
                         |
             NetworkManager settings/activation
                         |
              our NM VPN D-Bus service
                         |
              engine and protocol libraries
```

NetworkManager is the source of truth for connection profiles and activation.
The VPN service owns TUN/runtime resources and reports generic/IP configuration
and lifecycle through the standard VPN API. NM applies normal IP routes and DNS;
the service must not race it with an independent route manager.
Full-tunnel route reports use two IPv4 /1 captures rather than depending on the
relative metrics of physical and VPN defaults. Existing LAN complements and
source-policy connected-prefix captures preserve their checked scope; NM installs
and removes the routes, while the guard denies unapproved physical egress.

The COSMIC editor creates NM profiles and explicitly requests activation through NM.
Saved network edits and explicitly mapped source updates use NM's version check;
a manual protocol editor and other desktop frontends remain planned. Editors are
unprivileged and may close while a connection runs. No mandatory tray app or
parallel persisted profile database is introduced. The service exposes a bounded,
read-only usage snapshot/history over a separate D-Bus telemetry interface; only
that observation method is available to ordinary clients. See the
[telemetry contract](../crates/nm-service/README.md#read-only-usage-telemetry).

## Data plane

```text
application → Linux IP stack → TUN
  → userspace TCP/IP → TCP streams / UDP datagrams
  → protocol adapter → transport/security → remote proxy
```

The [shared data plane](../crates/dataplane/README.md) owns the library netstack,
packet/flow scheduling, DNS, FakeIP identities and routing/execution. Its `PacketIo`,
`Host`, LAN and observation capabilities are implemented by Linux adapters; it does
not depend on NM, Unix IPC, host socket creation or firewall management. The NM
worker is its first production consumer. This is an architectural boundary, not
new platform support; see [ADR 0029](decisions/0029-shared-dataplane.md).

VLESS is a stream/datagram proxy, not arbitrary IP encapsulation. TUN access alone
does not supply userspace TCP termination. The owner-selected pinned `meow-lwip`
provides experimental IPv4 TCP/UDP adaptation in a single-stack worker process;
`netstack-smoltcp 0.2.4` was rejected for an unsound Send implementation.
IPv6 is deferred beyond the first IPv4-only version, not a joint-test prerequisite;
see [ADR 0017](decisions/0017-ipv4-only-first-version.md). Longer-running TCP semantics,
MTU and performance need evidence.
Do not promise arbitrary ICMP forwarding through VLESS.

The selected library candidates are `meow-proxy` and `meow-transport` through the
[maintained nogcio fork](decisions/0004-maintained-meow-fork.md). The experimental
engine pins a fork revision and uses them as
libraries without their application's config loader, web API, listeners or daemon.
See [research](research/rust-protocol-libraries.md). Our adapters must account for
library-owned dialers, DNS, socket options and Vision raw-passthrough semantics.

The current [stream/datagram engine](../crates/engine/README.md) only wraps host-supplied
connected TCP inputs or trusted fixed-peer Unix relays, checks approved peer metadata
and denies implicit redial. The supervisor retains marked IP sockets. It does not
own TUN or the NM lifecycle. REALITY/Vision payloads have passed
an isolated pinned-peer probe through the shared profile adapter, not a host VPN test.

## Configuration and secrets

- The experimental editor uses `org.freedesktop.NetworkManager.tunnel`.
  The experimental backend owns it when running; public namespace and installation
  paths are not reserved. One service type is intended for multiple protocols.
- `vpn.data`: versioned, validated non-secret protocol/transport parameters.
- `vpn.secrets`: credentials, including VLESS UUID as authentication material.
- NM secret flags and secret agents govern persistence/prompting. Do not bypass
  them by writing directly to KWallet, Secret Service or a custom keyring store.
- Use standard NM IP/routing/DNS settings where possible. No opaque copy of a
  foreign engine's entire JSON/YAML profile as the canonical configuration.
- Model protocol, transport, security and flow separately, validating combinations.
  Vision is not an interchangeable wrapper over every transport.
- Unknown or unsupported security/transport options fail validation, never silently
  downgrade to direct access or weaker protection.

The shared model imports VLESS TCP/TLS/REALITY with optional Vision, plus WebSocket
over verified TLS without Vision. WebSocket path/query, HTTP Host and SNI remain
distinct validated fields and survive conversion to NM settings.
The COSMIC UI requests one complete HTTPS configuration by default and rejects
unsupported global policies without extracting nodes or falling back. The bounded
native IPv4 policy is implemented experimentally. Explicit legacy node-only URI-list import remains
available with a visible DNS/routing warning. Downloaded nodes stay in memory;
bounded source metadata/URLs persist in desktop Secret Service under
[ADR 0028](decisions/0028-subscription-url-secret-service.md). There are
no manual protocol fields. The NM client implements experimental
schema v1/v2 with persistent NM profile storage on explicit Add. New COSMIC profiles
delegate credentials to the registered desktop NM agent; the legacy client API
keeps its system-storage default. Storage/lifetime choices are disclosed before
adding. It reads saved/active metadata without
secret lookup and uses standard NM control APIs. See its
[contract](../crates/nm-client/README.md). There is no stable API,
automatic schema migration or competing desktop secret-agent implementation. Standard
NM interactive requests are integrated through SecretsRequired/NewSecrets with
identity-bound admission; see
[ADR 0033](decisions/0033-persistent-network-lifetime-and-nm-agents.md).
Explicit full-replacement remains available to its lab client under
[ADR 0018](decisions/0018-checked-profile-replacement.md); the COSMIC editor and mapped
update contract is [ADR 0027](decisions/0027-cosmic-profile-and-source-management.md).

An optional experimental schema-v2 profile adds checked TCP hostname rules. The
worker uses library HTTP Host/TLS SNI inspection; the supervisor rechecks Direct
authority and independently verifies DNS/IP membership before granting a marked
Unix payload relay while retaining the marked socket. Schema v2 also accepts an explicit DNS
override: CurrentNetwork forwards
bounded plain DNS through supervisor-owned uplink sockets; manual IPv4 uses the
VPN. No DHCP address is stored in the profile, and incompatible manual DNS/Direct
rules are rejected. NM still owns routes/DNS; see
[ADR 0011](decisions/0011-profile-dns-overrides.md). This is not full sing-box subscription,
FakeIP or UDP domain-routing support; see [ADR 0010](decisions/0010-tcp-domain-routing.md).

An explicit connected-RFC1918 LAN option derives bounded prefixes from the selected
NM device before resources. It reports their IPv4 complement as VPN routes to NM,
with interface-scoped guard exceptions only for those connected destinations. It
does not implement broader subscription private-IP rules or IPv6 bypass. See
[ADR 0012](decisions/0012-connected-lan-bypass.md). Bounded offline NM/packet
scenarios exist; they do not establish arbitrary topology or production acceptance.

An optional default-off schema-v2 DNS interception policy handles IPv4 UDP/TCP
port 53 reaching TUN through a bounded profile-selected relay, before hostname
dispatch. It is not FakeIP or full source DNS-hijack semantics. Combined LAN mode
captures connected LAN destinations in TUN and grants bounded Unix TCP/UDP payload
relays only after DNS handling; root retains the new LAN IP sockets and the guard
has no physical LAN exception. See [ADR 0013](decisions/0013-tun-dns-interception.md)
and [ADR 0014](decisions/0014-intercepted-lan-relays.md). Other local IP protocols
are unsupported in that combined mode. The offline VM suite exercises connected
LAN TCP/UDP and DNS; broader topology acceptance remains incomplete.

Experimental IPv4 FakeIP adds a root-owned durable identity journal, not another
profile database. It uses XDG state, bounded library allocation without reuse and
private DNS/reverse RPC. The root XDG namespace remains pinned by installed unit
configuration, but no boot enablement or NM startup dependency is required.
Protection is automatic and session-scoped; clean disconnect removes both guards,
and terminal failure also cleans them automatically, returning ordinary networking
without VPN. The independent systemd-owned recovery helper handles orphan guards;
see [ADR 0026](decisions/0026-automatic-session-recovery.md).
Complete IPv4 source-policy is implemented
experimentally; native boot acceptance remains unfinished, with a hard gate rather
than unprotected fallback.
See [ADR 0016](decisions/0016-persistent-ipv4-fakeip.md).

The checked complete IPv4 contract adds source DNS, DNS recognition/hijack,
BitTorrent signatures, QUIC hostname inspection, ordered domain/private-IP actions
and XUDP. Source DNS also accepts the bounded sing-box v1.12 typed server schema
and RFC 8484 HTTP/1.1 DoH over an approved verified TLS stream, with no independent
HTTP dialer, redirect or fallback. Source DNS/Direct authorization runs protocol
libraries in the root
supervisor, expanding the privileged attack surface beyond the legacy design.
Normal application packet processing remains unprivileged. The exact supported
shape, bounds, exclusions and required owner review are in
[ADR 0020](decisions/0020-native-ipv4-source-policy.md); no arbitrary source-policy
compatibility or native enforcement is implied.

## Responsibility and dependency layers

Each package declares `package.metadata.nm-tunnel.layer`. Production dependencies
(including build/optional/target-specific edges) must follow this table:

| Layer | Allowed workspace dependencies | Intended responsibility |
| --- | --- | --- |
| `model` | `model` | Validated configuration, domain errors, import representation |
| `contract` | `model`, `contract` | Pure integration schemas and non-secret projections; no service/client I/O |
| `engine` | `model`, `engine` | Packet/stream adaptation, protocol sessions, cancellation |
| `integration` | `model`, `contract`, `engine`, `integration` | NM VPN service, Linux resource lifecycle |
| `client` | `model`, `contract`, `client` | Profile editing, NM settings/activation client |
| `frontend` | `model`, `client`, `frontend` | Desktop editors and UI adapters |
| `tooling` | all layers | Repository checks and build/test tools |

The checker covers workspace dependencies; it is not an external-dependency or
privilege sandbox. External toolkit admission still needs review. In particular,
engine code must not acquire GTK/Qt/NM dependencies through third-party features.
Create packages when they have real code/consumers, not to populate this table.

### Code ownership and extension points

The [shared NM contract](../crates/nm-schema/README.md) owns encoding, decoding and
policy metadata admission for both client and service. Configuration without secrets
is not an executable Profile; credential admission is separate. The engine depends
on the model, never the NM contract. See [ADR 0025](decisions/0025-runtime-contract-ownership.md).

Within `crates/nm-service/src/`:

| Owner | Responsibility |
| --- | --- |
| `plugin.rs` | NM caller authorization, request admission validation and NM signal encoding |
| `authentication.rs` | Resource-free interactive credential slot bound to NM connection identity, applied configuration and deadline |
| `lifecycle.rs` | Ordered operation admission and preparation/session ownership |
| `executable.rs` | Same-image worker executable capability and idle upgrade retirement observation |
| `supervisor/plan.rs` | Pure network plan from a checked profile and bounded uplink observation |
| `supervisor/session.rs` | Uplink discovery, privileged resource setup and ordered stop |
| `supervisor/resources.rs` | External preparation/session resource owner and confirmed shutdown barrier |
| `supervisor/roaming.rs` | Persistent-session uplink observation, flow revocation and bounded retry attempts retaining the original NM/TUN lifetime |
| `supervisor/tun.rs` | New kernel TUN allocation and atomic public-name reservation |
| `supervisor/broker.rs` | Independent request authorization, budget and root-owned relays |
| `supervisor/uplink_dns.rs` | Fixed-resolver privileged plain DNS exchange |
| `dns.rs` | Re-export shared data-plane DNS messages, framing and defaults |
| `worker/` | Linux startup, inherited packet device and shared-runtime capability adapters |
| `worker/host.rs` | Linux broker capability adapter for shared flow processing |
| `task.rs` | Abort-on-drop ownership, independent of either process role |
| `guard_recovery.rs` | Root-only independent orphan cleanup and automatic cleanup retries |
| `guard_recovery/watchdog.rs` | Bus-supplied ProcessFD lease, terminal signaling and confirmed process-exit ordering |
| `network/sockets.rs` | Marked IPv4 socket mechanics; unbound variants stay private to `network` |
| `network/bootstrap.rs` | Selected-uplink endpoint A/CNAME resolution |
| `network/authority.rs` | Legacy Direct verification and checked LAN grants, independent of IPC DTOs |
| `network/guard.rs` | Owned nftables observation, programs and transactions; no flow/socket logic |
| `worker/routing.rs` | Linux integration regressions for the shared outbound selector |
| `worker/stream.rs` | Test imports for shared TCP inspection/execution contracts |

`worker/mod.rs` owns Linux startup, inherited descriptors, readiness/health wiring
and the packet-device adapter; shared packet dispatch lives in
`crates/dataplane/src/runtime.rs`. DNS message policy, routing, flow executors,
classification and FakeIP destination processing live in that package too.
`fakeip.rs` retains trusted filesystem/exclusive journal ownership over shared
identity semantics. `source_dns.rs` retains marked transport/socket operations over
the shared activation-local resolver and independent Direct authorization.

TCP and UDP consume the same `Decision` for Proxy, Block, LAN and the two distinct
Direct authorities. A refused grant cannot switch outbound. Classification is not
flattened: complete policy inspects DNS/BitTorrent before destination resolution;
legacy TCP LAN bypass precedes optional hostname sniffing, and legacy UDP ignores
QUIC-supplied names unless a name is recovered from owned FakeIP. Root repeats
authorization against its own policy/snapshot, not this worker decision.

Network authorization accepts destination/name values, not serialized worker requests.
Only a supervisor-checked LAN grant can select unbound marked physical routing for
all-RFC1918 bypass; ordinary endpoint and DNS callers must specify the uplink.
Source-policy Direct verification remains with its selected-resolver authority in
`source_dns.rs`, not the legacy uplink-DNS verification path. Neither path changes
normal routes or DNS, and neither exports IP descriptors to the worker.

Within `crates/nm-client/src/`, `transport.rs` owns pinned D-Bus identity and
uncached proxies; `runtime/observation.rs` owns metadata admission, versioned reads
and stale-handle checks; `runtime/mutation.rs` owns explicit storage/control and
indeterminate write outcomes. `runtime.rs` retains the public API and total
deadlines. Mutation consumes observation rather than duplicating its validation;
confirmed writes have no fallible post-write read and are never retried.

`frontends/cosmic/src/catalog.rs` owns retained/import-admitted nodes; invalidated
catalogs cannot return save candidates. `options.rs` owns pure profile-copy
transformations. `operations.rs` owns explicit NM mutation/control transitions and
the session-long indeterminate-storage barrier. Adding pins the admitted catalog
row; Requesting and Awaiting observation are distinct phases. Only a matching
completion can release a dispatched mutation, while a new explicit action can
supersede accepted control feedback. Widget layout and NM/HTTP effects remain
separate consumers. `download.rs` owns the memory-only subscription URL, format,
pending request ticket and HTTP error. `reads.rs` owns independent NM, usage and
recovery observation slots. Mutation invalidates pending results without releasing
their slots; only the matching unique ticket can complete a read. Late/duplicate
responses cannot finish newer work. `recovery.rs` owns the locally aged helper-status
projection, never guard cleanup. Shared owner-pinned non-activating observation
transport is reused by the client's usage and recovery APIs.

`navigation.rs` owns libcosmic's single-select primary model and pane scroll offsets.
The native Core supplies CSD/NavHandle and condensed navigation. Context is a
side-by-side drawer at sufficient width and a secondary content page when condensed;
neither representation owns NM/HTTP operations or clears storage uncertainty.

`source_store.rs` owns the encrypted source catalog and private XDG single-writer
lock; `source_persistence.rs` owns ticketed restore/save projection. Neither stores
downloaded profiles or VPN credentials. Missing storage stays visibly session-only.
`profile_editor.rs` owns drafts, version-pinned non-secret edits and the bounded
disconnect-observe-delete sequence. `subscriptions.rs` owns session sources, retained
catalogs and explicit source-update review. It does not infer changed server identity
from display names or positions. Applied rows are tracked per target/ticket; later
failure leaves confirmed writes intact and does not trigger rollback or replay.

Extend domain semantics before adding a persisted field or runtime branch. A new
routing action needs worker handling and independent supervisor authorization;
sharing a decision type never makes worker metadata authoritative. New DNS transports
must preserve the approved-socket boundary. Add concrete protocol-library adapters,
not a general plugin system in anticipation of unknown protocols. Schema-v1/v2
compatibility stays at the codec boundary and never silently changes old profiles.

Complete source-policy v2 uses the model's immutable destination predicate tree
for IPv4 CIDR/port and logical route conditions. TCP/UDP preserve unresolved-name
semantics before DNS; root re-evaluates real-destination predicates and retains
independent DNS membership for public named Direct. Legacy source v1 is unchanged;
older backends reject v2. This adds no alternate route writer or worker authority;
see [ADR 0020][destination-predicates].

Source v3 adds immutable ordered real-DNS selection by exact/suffix original query
name, with explicit endpoint Direct/Proxy or NM uplink DNS. These profiles resolve
owned Proxy names locally through that policy instead of delegating DNS to VLESS;
v1/v2 retain remote-domain forwarding. Root derives the resolver from the question,
never a worker-supplied endpoint/index, and independent public Direct DNS membership
uses the same selection. Client FakeIP/bootstrap remain separate; caches are scoped
to immutable activation profiles/uplinks. Failures/cancellation never switch DNS
or outbound. V3 requires DNS rules and exactly one route representation; old
backends reject it. See [the DNS contract][source-dns-selection].

[source-dns-selection]: decisions/0020-native-ipv4-source-policy.md#ordered-real-dns-selection-in-native-source-policy-v3

[destination-predicates]: decisions/0020-native-ipv4-source-policy.md#destination-predicates-in-native-source-policy-v2

## Lifecycle and safety requirements

1. Validate profile and secret requirements without allocating tunnel resources.
2. Resolve the endpoint using an explicit bootstrap policy before DNS changes.
3. Ensure every upstream/reconnect socket bypasses TUN. The experimental supervisor
   marks and binds IPv4 sockets to the selected uplink. Persistent sessions revoke
   old capabilities and rebuild from NM after uplink changes; endpoint rotation
   independent of network changes and IPv6 endpoints remain unsupported.
4. Establish required runtime resources and report configuration in NM API order.
   Design readiness around VLESS's limited authentication acknowledgement semantics;
   opening a TCP socket alone cannot prove the VPN is usable.
5. On cancellation/failure, stop tasks, close sockets/TUN and report state to NM.
   Teardown is idempotent and automatic, including terminal failures; ordinary
   networking resumes without VPN after terminal cleanup. Persistent network loss
   instead retains its admitted guards/TUN until recovery or explicit Disconnect.
   An independent recovery owner must be armed
   before guard changes so backend death does not orphan cleanup.

The experimental [service contract](../crates/nm-service/README.md) implements root
setup/socket brokering, authenticated NM callers and an unprivileged worker.
Synthetic VM probes cover teardown and worker/supervisor crashes; neither these nor
owner-reported local host use establish production hardening. See
[ADR 0006](decisions/0006-experimental-nm-runtime.md).
Workspace Rust still forbids unsafe code; dependency FFI is reviewed separately.

IPv6 must be supported or explicitly prevented from bypassing the tunnel. DNS leak
policy, UDP/XUDP compatibility and kill-switch behavior need distinct acceptance
tests. A default VPN route is not a kill switch. The experimental output guard
drops unmarked physical IPv4 and non-loopback IPv6 during the session/recovery attempt.
Terminal failure ends the session and automatically restores ordinary networking;
this is not permanent lockdown. It also blocks
forwarding from our TUN. Root-owned endpoint/Direct payload relay
authority and remaining acceptance are in [ADR 0015](decisions/0015-root-owned-endpoint-relays.md).

## Desktop-specific integration

- GTK: libnm VPN editor-plugin ABI; verify GTK version/host and authentication UI.
- KDE: plasma-nm's own plugin API, potentially a thin C++/Qt bridge to Rust logic;
  assess the supported Plasma release and its editor transition before implementation.
- COSMIC: native libcosmic editor initially; embedding in settings requires a
  separately reviewed/upstream integration, not an assumed plugin ABI.

The native COSMIC UI uses libcosmic's system theme, grouped rows and context drawer.
Connections is the primary page, with per-profile controls and read-only traffic
rates/history. The Subscriptions import workspace explicitly adds individual subscription nodes
to NM without activation. Saved profiles, explicit Connect/Disconnect and periodic
NM/usage observation are independent of subscription loading and GUI lifetime.
See [ADR 0007](decisions/0007-nm-profile-control.md). Subscription URLs are sensitive,
visible in the input and memory-only;
there is no duplicate persisted connection database or private keyring. Future local
persistence must follow XDG paths and review secret storage independently. Connection switching,
editor availability and credential prompts remain separate native acceptance
categories; compiling and state tests do not establish desktop compatibility.
