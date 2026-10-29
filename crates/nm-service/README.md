# Experimental NetworkManager VPN service

`nm-tunnel-service` implements the standard NM VPN plugin at
`/org/freedesktop/NetworkManager/VPN/Plugin`, using the experimental service type
`org.freedesktop.NetworkManager.tunnel`. It is **experimental software**, not an
accepted production backend. Synthetic VM checks and owner-reported local Arch use
do not establish daily-driver safety; host evaluation requires explicit authorization
and a recovery plan.

## Ownership and lifecycle

Compatible package replacement never restarts an active session. `executable.rs`
observes image identity for idle retirement and opens the running backend image for
worker exec through setpriv's inherited read-only stdin (`/proc/self/fd/0`). TUN is
then a bounded first SCM_RIGHTS grant on the existing control channel, not stdin;
no mixed parent/worker image or legacy bootstrap fallback is allowed. Recovery ABI
v1 is checked before Arm. Only confirmed idle/cleaned lifetimes retire; preparation,
active flow processing and unconfirmed teardown keep their existing ownership.
See [ADR 0030](../../docs/decisions/0030-session-preserving-package-updates.md).

Code ownership is explicit: `plugin.rs` is the NM adapter, `lifecycle.rs` owns
ordered operation admission, and `supervisor/` separates pure planning, resource
setup and broker authorization. The [shared data plane](../dataplane/README.md)
owns packet/flow dispatch, DNS and FakeIP semantics. Private `worker/` modules
provide Linux startup/capabilities and broker integration regressions; `dns.rs`
re-exports shared message policy without sockets. NM serialization is owned by
the [shared schema](../nm-schema/README.md), not a second service-only decoder.
The [architecture guide](../../docs/architecture.md#code-ownership-and-extension-points)
describes extension boundaries and remaining consolidation work.

`network/` separates marked socket mechanics, uplink bootstrap, legacy/LAN authority
and nftables. The authority accepts domain/destination values, not IPC request DTOs;
a checked LAN grant is required to select the broad mode's unbound physical route.
Workers consume shared outbound selection in `dataplane::routing`, with one TCP
executor in `dataplane::stream`. Complete classification still precedes destination resolution;
legacy LAN bypass still precedes TCP sniffing, and legacy UDP does not gain QUIC
hostname routing. Root independently checks every grant. These boundaries do not
introduce a protocol plugin registry, new external dependency versions or expanded permissions.

`guard_recovery.rs` is the independent systemd-owned orphan-cleanup owner. Its
root-only Arm handshake must succeed before guard installation. Preparation retries
the same input once after one second within one 45-second budget; cancellation
stops retries. Disconnect or terminal failure stops owned resources and retries
guard cleanup automatically. Fatal runtime failure ends the session, not a hidden
NM reactivation. Ordinary networking then resumes without VPN. Backend process
death transfers orphan cleanup to the independently restarted helper. This replaces
retained-failure/manual recovery. Bounded synthetic IPv4 VM checks exercise
TUN TCP/UDP/DNS, SIGKILL orphan cleanup, SIGSTOP watchdog cleanup and recovery-helper
restart during traffic; broader failure races and coexistence remain pending.
The helper also detects a lifecycle loop that stops renewing its 30-second lease,
even if it retains its bus name. It pins the backend through D-Bus `ProcessFD`, sends
terminal SIGKILL only through that handle and waits for confirmed process exit before
cleanup. Missing ProcessFD support refuses arming; numeric-PID fallback is forbidden.
Read-only `GetStatus` v1 remains available during termination/cleanup and is consumed
by COSMIC without activating either service or gaining root control. Its last confirmed
cleanup remains visible for 30 seconds after orphan cleanup. Signaling, system-bus
activation/confinement and native packet ordering still require broader review and
acceptance; the VM result does not timestamp every process/packet transition.
See [ADR 0026](../../docs/decisions/0026-automatic-session-recovery.md).

The maintained [offline VM suite](../../docs/testing/vm-acceptance.md) exercises
real NM/TUN TCP/UDP/DNS, bounded physical packet isolation, clean/crash/watchdog
teardown, recovery restart, endpoint refusal, active image replacement and unchanged
TUN-collision rejection. It uses a disposable guest without QEMU networking and
does not change the host VPN. LAN modes, domain actions and persistent FakeIP have
separate native scenarios. These bounded fixtures do not establish every supported
source policy, trusted DoH, roaming, reboot or desktop acceptance.

Preparation and active sessions retain an external resource owner across cancelled
setup and broker futures. Shutdown confirms worker exit, joins the broker and both
relay sets, joins telemetry and confirms activation nft-writer exit before dropping
the TUN and permitting guard cleanup or retry. Unconfirmed kill/wait/deadline results
end the backend without clearing guards; independent process-pinned recovery then
owns cleanup. The 45-second preparation budget excludes subsequent confirmed
resource shutdown, rather than treating a deadline as resource release. A stuck
shutdown does not renew the lifecycle lease. TUN creation uses a new unnamed kernel
device plus atomic rename to `nmtun0` before guard installation; an occupied name
refuses without adopting or configuring that interface. See the
[security review](../../docs/security-review.md) for bounded regression evidence.

Explicit isolated TUN collision/race regression (no host network changes):

```sh
cargo build --locked -p nm-tunnel-service --example tun_create
python3 scripts/check_tun_creation.py --binary target/debug/examples/tun_create
```

Run those commands from the repository root with bubblewrap, iproute2, an available
`/dev/net/tun` and unprivileged user/network namespaces. Missing prerequisites fail;
the ordinary unit suite compiles the driver but does not run this kernel probe.

Only the current unique owner of `org.freedesktop.NetworkManager` may call control
methods. The system-bus policy additionally limits control access to root. A private-bus
test checks rejection, unchanged lifecycle state and NM name-owner replacement.
One activation is allowed at a time; the lifecycle owner acknowledges admission
in queue order with Disconnect, and owns preparation even if its caller goes away.
Profiles and credentials come from NM;
there is no parallel profile store. Interactive secret-agent requests are
owned by the desktop's registered NM agent, not a competing Tunnel process.
System-stored credentials still arrive before Connect. For agent-owned/not-saved
profiles, ConnectInteractive can reserve a bounded credential-request slot and
emit SecretsRequired with the exact `uuid` hint. NewSecrets must match the admitted
NM connection identity and configuration before preparation can allocate resources.
Invalid/late replies cannot mutate that slot. Disconnect, NM cancellation and the
120-second request deadline retire it. An absent agent never selects system-secret
storage. See [ADR 0033](../../docs/decisions/0033-persistent-network-lifetime-and-nm-agents.md).

The root supervisor selects NM's primary uplink and IPv4 nameserver, creates the
TUN and an nftables guard, and retains marked/uplink-bound TCP sockets behind
Unix payload relays. Legacy
profiles permit only the fixed VPN endpoint; optional schema-v2 TCP domain rules
add bounded, independently revalidated Direct grants, described below. DNS
bootstrap uses that nameserver, a marked socket and a bounded A query; no general
system resolver or destination dialer is used. The endpoint address is fixed for
one prepared transport generation. Persistent NM sessions revoke old capabilities
on uplink/address/resolver/gateway changes and rebuild under the existing guards
and TUN until recovery or explicit Disconnect. Normal physical-primary observations
run on the two-second lifecycle heartbeat. Failed observations also revoke stale
authority. Old flows are closed, not replayed. Nonpersistent profiles keep their
previous teardown behavior. Independent endpoint rotation and IPv6 endpoints remain
unsupported.

The child runs as `nm-tunnel`, with no supplementary groups or capabilities,
no-new-privileges and parent-death SIGKILL. TUN and the private control channel
are inherited descriptors. Configuration uses bounded private stdin-style IPC,
not arguments, environment variables or files. Only Unix payload channels, never
upstream IP sockets, are transferred as FDs. Cancelling an ambiguous FD exchange
poisons the channel rather than reusing a potentially stale reply.
The worker's effective, permitted, inheritable and ambient capability sets are
empty. Its inherited bounding ceiling need not be empty: normal NM launch omits
CAP_SETPCAP, and no-new-privileges prevents using that ceiling to regain privileges.
The broker grants at most 64 sockets per one-second window, applying bounded
backpressure rather than terminating the VPN on bursts. Invalid control messages
remain fatal.

One worker process owns one `meow-lwip` core. It translates IPv4 TCP/UDP packets to
library sessions. TCP flows are capped at 512, with a 60-second setup deadline
including broker queueing and no fixed lifetime or inactivity deadline while fully
bidirectional; once either half closes, the root relay allows sixty seconds to drain.
UDP associations at 64 with bounded queues and a 60-second inactivity deadline
covering broker queueing, setup and writes as well as waiting for datagrams.
The TCP task limit leaves headroom below the pinned Linux lwIP pool of 1024 TCP
PCBs for handshakes and closing states. It is an admission bound, not a verified
capacity or throughput guarantee; full admission drops new flows without direct fallback.
The engine independently bounds protocol setup to ten seconds.
Readiness checks only the configured endpoint's TLS/REALITY and optional WebSocket
transport, plus durable local FakeIP/reverse ownership when enabled. No control
domain, upstream DNS test query or destination TLS connection is generated.
VLESS/Vision credential acceptance can remain deferred until actual application
I/O: Connected does not certify credentials, DNS availability or Internet access.
See [ADR 0032](../../docs/decisions/0032-destination-free-readiness.md).
Endpoint health checks normally wait 20 seconds between probes, have a 15-second deadline
including broker queueing and never overlap. Transient probe failures retain the
session, TUN, routes and guards; subsequent probes use fresh upstream connections
after 40 seconds, then at most 60 seconds between attempts. Success restores the
20-second interval. Independent flows continue to be admitted; failed application
streams are not replayed or migrated. A failed endpoint dial refuses only that
request, without terminating the broker or existing relays. No alternate endpoint,
resolver, uplink or unprotected fallback is introduced.

Best-effort private telemetry logs probe failure counts, recovery, numeric runtime
stage, elapsed milliseconds, bounded error class and broker-fatal status; no error
strings, names or addresses are logged. These reports do not change the public
telemetry schema: `running` still does not prove current reachability. A cancelled
in-flight broker exchange remains poisoned and fatal; fatal worker/broker failures
end the session with automatic cleanup. Retrying probes is not process-crash or
uplink-change recovery. Disconnect cancels the worker and pending retries.
Fatal worker reports also include a fixed error class instead of discarding the
error entirely; a runtime stage is not necessarily an activation/setup failure.
Probing does not block TCP admission, UDP dispatch or flow reaping.
NM receives Config, Ip4Config and STARTED
in that order, then owns routes, interface IP/MTU and resolver configuration.
All route plans report `never-default=true` and explicit capture routes; ordinary
full-tunnel profiles use two IPv4 /1s, independent of physical default metrics or
NM connectivity-check penalties. LAN complements and source connected-prefix
capture retain their existing scope. More-specific unrelated physical routes can
still refuse traffic through the guard, never authorize fallback. Marked root-owned
endpoint/Direct sockets keep their existing uplink authority.

## Read-only usage telemetry

The experimental `org.freedesktop.NetworkManager.tunnel.Telemetry.GetSnapshot`
method is on the same service and object path as the NM plugin.
This API is versioned but not stable.
Any system-bus client may call this one method. No control methods, secret lookup,
profile identity, endpoints, subscription URLs or guard recovery are exposed.
Clients should disable D-Bus auto-start when merely observing an absent backend;
no frontend needs to stay running to collect statistics.

For a one-shot read of an already running backend:

```sh
busctl --system --auto-start=no call \
  org.freedesktop.NetworkManager.tunnel \
  /org/freedesktop/NetworkManager/VPN/Plugin \
  org.freedesktop.NetworkManager.tunnel.Telemetry GetSnapshot
```

The returned D-Bus struct has these fields **in order**:

| Field | Type | Meaning |
| --- | --- | --- |
| `version` | `u` | Contract version, currently 1 |
| `generation` | `t` | Activation attempt number within this service process; 0 before any attempt |
| `state` | `s` | `idle`, `connecting`, `running`, `stopping`, `stopped`, or `failed` |
| `setup_stage` | `s` | Last setup step: `idle`, `uplink`, `guard`, `resolve`, `tun`, `worker`, `readiness`, `ready` |
| `worker_stage` | `y` | Last worker observation: 0 unknown; 1 startup; 2 profile; 3 TUN; 4 stack; 7 dispatch; 10 socket; 11 protocol; 12 DNS send; 13 DNS receive; 14 DNS validation |
| `elapsed_ms` | `t` | Monotonic milliseconds since attempt admission (service startup before first attempt) |
| `available` | `b` | At least one worker sample received for this attempt |
| `live` | `b` | Still collecting and last sample is at most 3 seconds old |
| `age_ms` | `t` | Time since last sample; 0 when unavailable |
| `counters` | struct | Last observed cumulative counters, detailed below |
| `upload_bytes_per_second` | `t` | Average over the last sampling interval; 0 before two samples or when not live |
| `download_bytes_per_second` | `t` | Same, download direction |
| `history` | array of structs | Samples in the preceding 60 seconds, oldest first, at most 61 entries |

Each history struct contains `elapsed_ms`, `counters`,
`upload_bytes_per_second`, `download_bytes_per_second`, in that order.
Each counters struct contains the following `t` (unsigned 64-bit) fields in order:

1. `upload_bytes`, `download_bytes`: IP packet bytes read from/written successfully
   to TUN. Includes IP headers and TCP retransmissions; not application payload,
   physical-link usage, encrypted protocol overhead or a provider billing meter.
2. `upload_packets`, `download_packets`: corresponding TUN packet counts.
3. `tcp_active`, `udp_active`: admitted flow tasks, including pending setup.
   UDP counts associations, not connections; readiness/health probes are excluded.
4. `tcp_opened`, `udp_opened`: admitted tasks over this attempt, not successful
   handshakes. Active counts decrease on success, failure and cancellation.
5. `tcp_failed`, `udp_failed`: tasks ending in setup/IO error or deadline. Explicit
   session cancellation does not count as a protocol failure.
6. `dropped_packets`: observed unsupported TUN packets, flow-cap rejections, full
   UDP queues and stack UDP send backpressure. This is not a complete loss meter:
   library/kernel drops are not all observable here.

Counters use atomic operations on the packet path; a multi-field sample is an
approximate observation, not an atomic transaction. A separate inherited private
Unix datagram socket sends a sample about once per second, including setup. It
never shares the serialized socket/FD broker and never waits on telemetry
backpressure. Invalid reports are ignored; missed reports increase sample age.
The collector belongs to preparation/session ownership and is aborted on teardown.

Totals and the last setup stage survive failure/stop until the next admitted
attempt resets them. Terminal states mark the last counters inactive (`live=false`);
flow counts remain the **last observed** values, not claims of live resources.
The final sub-second traffic before termination can be absent. History expires
even while stopped, but totals remain. No disk history or cross-restart accounting
is kept. Clients must reset their charts when the D-Bus unique owner or generation
changes, and must show unavailable/stale data distinctly from zero traffic.
`running` means the plugin reported readiness to NM, not proof of NM route setup,
application reachability or current guard presence; use NM for connection state.

## Network policy and limitations

- Full-tunnel IPv4 only: legacy `nmtun0`, `198.18.0.1/32`, point-to-point
  `198.18.0.2`, MTU 1400; complete policy reports its checked private TUN address/MTU.
- Legacy default DNS is `1.1.1.1`. Explicit resolver overrides are described below.
  NM priority -100 and `~.` remain required. Non-exclusive DNS, split routes,
  generic NM DNS overrides, custom addresses/gateways/tables/metrics and enabled
  IPv6 are rejected before setup.
- Legacy VLESS bound UDP is carried over the selected TCP security/transport, not
  native QUIC. Complete-policy profiles use XUDP. Legacy wire format has no
  per-packet source address. The pinned
  library's absent-source sentinel is accepted only for this bound association.
- ICMP and other IP protocols are not forwarded. IPv6 output is explicitly
  dropped by the guard, even if another interface has a working IPv6 route.
- The guard allows loopback, marked IPv4 upstream sockets and IPv4 TUN output;
  other output is dropped. It does not preserve SSH management traffic.
- Disconnect and terminal failure automatically remove both session guards after
  resource teardown. Cleanup errors retry; they are not reported as absent protection.
  The independent helper handles orphan guards after supervisor death. Ordinary
  networking returns without VPN; this is not permanent lockdown.
- Compatibility `--clear-guard` remains an administrative tool, not a required
  user recovery step. Recovery is not owned by the GUI or package transactions.
- D-Bus serialization and Rust strings can contain transient secret copies;
  redacted diagnostics are not a zeroization guarantee.

### Experimental TCP hostname rules

NM schema v2 permits `vpn.data.tcp-domain-policy`, the versioned checked format
documented by the [profile model](../profile/README.md#optional-tcp-hostname-policy).
V1 refuses policy keys; v2 requires an explicit TCP/DNS/LAN policy. Existing
profiles remain v1 unless explicitly recreated through the model/client API. The
complete importer uses a separate checked `source-policy`, not this legacy overlay.

### Experimental complete IPv4 policy

`vpn.data.source-policy` requires schema v2, persistent FakeIP and interception;
legacy LAN/TCP overlays reject. Source DNS/Direct authority runs selected-resolver
VLESS/XUDP/TLS and bounded DoH HTTP libraries in root, unlike the legacy worker protocol path. Root
revalidates Direct requests and retains all IP sockets. Capture prefixes do not
grant sockets or physical firewall exceptions. Source defaults never silently
replace unsupported policy. The supported shape, resource limits, privacy,
privilege expansion and pending native/boot/security acceptance are specified in
[ADR 0020](../../docs/decisions/0020-native-ipv4-source-policy.md).

DoH uses one approved selected-route TCP stream, mandatory certificate verification
and the engine's bounded HTTP/1.1 POST adapter. HTTP authority and optional TLS name
remain distinct; hostname bootstrap still uses the declared local role. No URL
client, environment proxy, redirect, implicit socket or resolver fallback is added.
The shared resolver validates DNS replies before cache/Direct authorization. These
synthetic contracts do not establish live DoH, privileged VM or packet acceptance.

HTTP Host/TLS SNI is inspected with the library before socket admission (8 KiB,
300 ms), preserving and replaying consumed bytes once. First matching rule wins:
`block` closes before any socket, `proxy` uses the existing endpoint path, `direct`
requests a supervisor grant. Unknown names stay proxied. This is TCP-only: no
FakeIP, DNS reverse inference, UDP/QUIC metadata or domain-based LAN exceptions.

The supervisor rechecks Direct rules and rejects protected/non-unicast destinations
before DNS/socket work. It resolves the allowed name through the NM uplink resolver
and binds the question and A/CNAME answer chain to the requested IP. This exposes
that Direct name to the uplink DNS, and CDN/resolver differences may refuse a valid
flow; neither case triggers fallback. The grant uses a marked/uplink-bound TCP
socket retained by root, never a broad route/firewall exception. The worker gets
only a validated Unix payload channel. Direct requests have 512-byte frames and a five-second
frame deadline. Cancellation/malformed replies poison the serialized FD channel;
explicit refusal leaves it usable. No hostname/payload is logged.

These rules are not full sing-box compatibility or an application-identity security
boundary. Synthetic tests cover admission/ownership and DNS answer binding, not live
NM/direct routing or leakage. Design, behavioral references, remaining full-policy
work and VM acceptance limits are in [ADR 0010](../../docs/decisions/0010-tcp-domain-routing.md).

### Per-profile upstream DNS overrides

Schema v2 `vpn.data.dns-override` selects `current-network` or
`proxy-ipv4:ADDRESS`; absent means source/default (legacy URI profiles use
`1.1.1.1`). Manual public IPv4 resolvers go through VPN and are used for proxied
DNS readiness too. Invalid/private/IPv6/encrypted manual choices fail before
resources. Manual DNS plus Direct hostname rules is also rejected rather than
leaking independent Direct verification queries to uplink DNS.

CurrentNetwork rereads the first usable IPv4 resolver from the primary NM uplink
at every activation; no DHCP address is stored. NM receives tunnel DNS
`198.18.0.2`. Queries there are forwarded by a bounded private broker RPC to the
fixed upstream on marked/uplink-bound sockets. No broad DNS exception, global
hijack, OS-stub/DoT/IPv6 policy import or public-resolver fallback. Plain UDP/TCP
port 53 outside VPN is explicitly disclosed by the UI.

The supervisor checks the mode before sockets; the requester cannot supply server
IP/port/URL/interface. hickory-proto validates one IN-class QUERY and matching
ID/questions in replies; tokio-util owns TCP framing. Negative answers/truncation
are preserved. Messages are at most 4096 bytes, upstream/frame/write operations
have five-second deadlines, worker exchanges have ten seconds, and 32 extra UDP
DNS tasks share the broker budget. Uncertain cancellation poisons the FD channel;
explicit refusal does not. Invalid input creates no privileged socket.

CurrentNetwork readiness verifies only the configured VPN endpoint, without a DNS
test query or application destination. Real requests independently exercise the
selected uplink resolver; its failure never selects a public fallback. See
[ADR 0032](../../docs/decisions/0032-destination-free-readiness.md) and the override
bounds in [ADR 0011](../../docs/decisions/0011-profile-dns-overrides.md).
Overrides do not bypass complete-configuration admission; only checked source-policy
combinations can execute with persistent FakeIP.

### Connected RFC1918 LAN bypass

The separate explicit `lan-bypass=private-rfc1918` mode keeps all RFC1918 traffic
on existing physical routes and uses their complement for NM VPN routes, without
connected-subnet capture. Enabled DNS interception uses kernel output DNAT for
private port 53, including gateway host routes, plus final-egress validation.
FakeIP names resolving to private IPs use bounded root-owned TCP/UDP relays.
Public, IPv6 and synthetic physical egress remain protected. Existing connected
profiles retain the narrower semantics below. See
[ADR 0024](../../docs/decisions/0024-private-ipv4-bypass.md) for invariants and
explicit isolated kernel-adapter verification.

Explicit schema-v2 `lan-bypass=connected-rfc1918` derives at most sixteen connected
private IPv4 prefixes from the selected NM device on activation. Invalid/broad
prefixes or no eligible subnet reject before resources. The guard permits only
these destinations on that uplink; IPv6/public physical output remains blocked.
NM receives `never-default=true` and a disjoint CIDR cover of all remaining IPv4
destinations via `Ip4Config.routes`. Only NM installs/removes routes. Generic NM
route overrides are still rejected. No arbitrary LAN prefixes or Direct dialer.

This explicit exception bypasses hostname policy for connected LAN destinations,
not every special/private address. It cannot admit a full subscription's broader
`ip_is_private` rule. It is off by default; reconnect is required after uplink
changes. Native route/packet/teardown acceptance remains pending; see
[ADR 0012](../../docs/decisions/0012-connected-lan-bypass.md).

### Explicit TUN DNS interception

Schema-v2 `dns-interception=tun-port53` redirects IPv4 UDP/TCP port 53 reaching TUN
to the profile-selected DNS before hostname/general proxy dispatch. It is off by
default. CurrentNetwork still uses the fixed broker RPC; default/manual resolvers
use VLESS UDP for UDP queries or framed VLESS TCP for TCP queries, without fallback.
Queries are parsed before broker work and replies checked for ID/question binding;
each exchange has a ten-second bound including setup and I/O. Existing task limits
and TCP client deadlines apply. No listener, global rewrite or privilege expansion.

COSMIC exposes this as an explicit creation/replacement opt-in, not complete subscription
translation. Interception alone is not FakeIP, DoH/DoT, IPv6 or DNS sniffing on other ports. It
uses a separate combined-LAN path rather than letting LAN DNS skip TUN. Saved
details observe the mode; existing
profiles are unchanged. Synthetic contracts and outstanding interoperability,
netstack and VM acceptance are in
[ADR 0013](../../docs/decisions/0013-tun-dns-interception.md).

With both LAN bypass and DNS interception, NM receives two /1s plus more-specific
halves of each original connected prefix. The guard allows no unmarked physical
LAN traffic. DNS runs first; local unicast TCP/UDP is authorized against the root's
own NM snapshot, then relayed over private Unix payload channels. Root retains
all new LAN IP sockets; the worker cannot retarget a grant. Port 53, network/
broadcast boundaries, IPv6, public and non-connected targets cannot get LAN grants.
Other LAN IP protocols and /31-/32 point-to-point prefixes are unsupported here.
Standalone LAN bypass is unchanged. Resource bounds, tests and pending acceptance
are in [ADR 0014](../../docs/decisions/0014-intercepted-lan-relays.md).

Endpoint and hostname-Direct grants now use the same root-owned stream boundary,
not exported marked IP descriptors. A shared 609-slot root set covers TCP, proxied
UDP, DNS and health streams. The guard also drops forwarding from `nmtun0` without
changing unrelated forwarding policy. Positive relay interoperability and packet
acceptance remain pending; see [ADR 0015](../../docs/decisions/0015-root-owned-endpoint-relays.md).

### Experimental persistent IPv4 FakeIP

Schema-v2 `dns-fakeip=persistent-ipv4-v1` requires interception and one trusted
absolute XDG namespace pin, read passively from installed unit configuration.
Boot enablement, service startup and an NM Requires dependency are not prerequisites.
Root owns a locked, bounded, append-only XDG
identity journal; records are fsynced before DNS publication and never evicted or
reset automatically. Missing/corrupt/unsafe state or failed writes reject. Names
are identifying data: never log or index the journal. The allocator library sees
only opaque lease IDs. No source cache path or subscription URL is persisted.

Known synthetic TCP/UDP destinations resolve through the selected upstream and
use domain rules before LAN fallback; unknown ownership closes before outbound
work. Root independently verifies UDP Direct grants, and retains IP descriptors.
The reserved /15 has a narrow physical-egress guard during the session, separate
from the main guard. Clean disconnect stops workers/relays and deletes both owned
tables in one nft transaction. Terminal failure also ends protection through automatic
cleanup. Neither the backend nor recovery helper changes the identity journal.

This is IPv4-only, not full source compatibility: AAAA is empty and IPv6 remains
blocked. The optional legacy boot restoration unit is never automatically enabled
and no longer declares an NM Requires dependency. Existing old enablement symlinks
need explicit retirement. Cached FakeIP destinations are not protected outside a
session or after reboot without restoration; this limitation is disclosed before
saving. COSMIC exposes the opt-in requiring interception. No journal migration/reset
is implied. See [ADR 0022](../../docs/decisions/0022-session-scoped-guards.md).
Contracts, resource/privacy limits and
remaining live acceptance are in [ADR 0016](../../docs/decisions/0016-persistent-ipv4-fakeip.md).

## Build, packaging and acceptance

Build without privileges:

```sh
cargo build --locked -p nm-tunnel-service
cargo test --locked -p nm-tunnel-service -p nm-tunnel-engine -p nm-tunnel-client --all-targets
```

Packaging templates are under `packaging/`. A disposable VM needs NetworkManager,
nftables, D-Bus, systemd, util-linux/setpriv, and a dedicated `nm-tunnel` system
account. Templates are not installed by ordinary build/check commands.

The repository does not provide an automated NM VM or live-node test harness.
Ordinary checks cover component contracts, not end-to-end tunnel acceptance.
The Rust `lab_control` and `lab_import` examples are explicit client tools, not
complete integration suites or isolation safeguards.

Runtime acceptance requires an explicitly authorized disposable VM with recovery
access and external process deadlines. Verify real NM activation, TCP/UDP and DNS,
worker privilege drop, invalid credentials, independent recovery/cgroup crash handling
and resource cleanup. NM command completion can precede plugin cleanup; use bounded
readiness checks rather than assuming synchronous teardown. The guard blocks ordinary
SSH, and tests must not discard a pre-existing guard or unrelated connections.

Live REALITY compatibility and broader reliability remain unresolved. Local runtime
evidence does not certify every protocol/provider or native COSMIC input, Polkit,
accessibility and reboot behavior. A timeout does not justify a security downgrade.
Real-node tests require separate authorization; subscription URLs, credentials and
endpoint identities must not enter arguments, fixtures or captured logs.
