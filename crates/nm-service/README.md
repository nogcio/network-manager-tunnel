# Experimental NetworkManager VPN service

`nm-tunnel-service` implements the standard NM VPN plugin at
`/org/freedesktop/NetworkManager/VPN/Plugin`, using the experimental service type
`org.freedesktop.NetworkManager.tunnel`. It is **experimental software**, not an
accepted production backend. Synthetic VM checks and owner-reported local Arch use
do not establish daily-driver safety; host evaluation requires explicit authorization
and a recovery plan.

## Ownership and lifecycle

Only the current unique owner of `org.freedesktop.NetworkManager` may call control
methods. The system-bus policy additionally limits control access to root. A private-bus
test checks rejection, unchanged lifecycle state and NM name-owner replacement.
One activation is allowed at a time; the lifecycle owner acknowledges admission
in queue order with Disconnect, and owns preparation even if its caller goes away.
Profiles and credentials come from NM;
there is no parallel profile store. Interactive secret-agent requests are not
implemented; NM must supply `vpn.secrets.uuid` before Connect.

The root supervisor selects NM's primary uplink and IPv4 nameserver, creates the
TUN and an nftables guard, and supplies marked/uplink-bound TCP sockets. DNS
bootstrap uses that nameserver, a marked socket and a bounded A query; no general
system resolver or destination dialer is used. The endpoint address is fixed for
one activation. Uplink changes, endpoint rotation and IPv6 endpoints are not
supported; connections must be explicitly reactivated.

The child runs as `nm-tunnel`, with no supplementary groups or capabilities,
no-new-privileges and parent-death SIGKILL. TUN and the private control channel
are inherited descriptors. Configuration uses bounded private stdin-style IPC,
not arguments, environment variables or files. Further upstream sockets are
transferred as owned FDs over this channel. Cancelling an ambiguous FD exchange
poisons the channel rather than reusing a potentially stale reply.
The worker's effective, permitted, inheritable and ambient capability sets are
empty. Its inherited bounding ceiling need not be empty: normal NM launch omits
CAP_SETPCAP, and no-new-privileges prevents using that ceiling to regain privileges.
The broker grants at most 64 sockets per one-second window, applying bounded
backpressure rather than terminating the VPN on bursts. Invalid control messages
remain fatal.

One worker process owns one `meow-lwip` core. It translates IPv4 TCP/UDP packets to
library sessions. TCP flows are capped at 512, with a 60-second setup deadline
including broker queueing and no fixed lifetime or inactivity deadline after setup;
UDP associations at 64 with bounded queues and a 60-second inactivity deadline
covering broker queueing, setup and writes as well as waiting for datagrams.
The TCP task limit leaves headroom below the pinned Linux lwIP pool of 1024 TCP
PCBs for handshakes and closing states. It is an admission bound, not a verified
capacity or throughput guarantee; full admission drops new flows without direct fallback.
The engine independently bounds protocol setup to ten seconds.
Readiness requires a real proxied DNS exchange; socket setup alone is not success.
Health checks wait 20 seconds between probes, have a 15-second deadline and never
overlap; probing does not block TCP admission, UDP dispatch or flow reaping.
NM receives Config, Ip4Config and STARTED
in that order, then owns routes, interface IP/MTU and resolver configuration.

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

- Full-tunnel IPv4 only: `nmtun0`, `198.18.0.1/32`, point-to-point `198.18.0.2`, MTU 1400.
- VPN DNS is currently fixed at `1.1.1.1`; the importer sets NM DNS priority -100
  and the routing domain `~.`. The service rejects non-exclusive DNS, split routes,
  custom addresses/DNS/gateways/tables/metrics and enabled IPv6 before setup.
- VLESS bound UDP is carried over the selected TCP security/transport, not native
  QUIC or XUDP. Its wire format has no per-packet source address. The pinned
  library's absent-source sentinel is accepted only for this bound association.
- ICMP and other IP protocols are not forwarded. IPv6 output is explicitly
  dropped by the guard, even if another interface has a working IPv6 route.
- The guard allows loopback, marked IPv4 upstream sockets and IPv4 TUN output;
  other output is dropped. It does not preserve SSH management traffic.
- Clean NM Disconnect removes the guard. Failed activation or worker/supervisor
  failure retains it, including when NM activates a replacement plugin just to
  send Disconnect. A successful retry restores normal teardown ownership.
- `nm-tunnel-service --clear-guard` is an explicit privileged lab recovery command.
  It is not automatically invoked on service failure or restart.
- D-Bus serialization and Rust strings can contain transient secret copies;
  redacted diagnostics are not a zeroization guarantee.

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
worker privilege drop, invalid credentials, crash handling, retained guard ownership
and resource cleanup. NM command completion can precede plugin cleanup; use bounded
readiness checks rather than assuming synchronous teardown. The guard blocks ordinary
SSH, and tests must not discard a pre-existing guard or unrelated connections.

Live REALITY compatibility and broader reliability remain unresolved. Local runtime
evidence does not certify every protocol/provider or native COSMIC input, Polkit,
accessibility and reboot behavior. A timeout does not justify a security downgrade.
Real-node tests require separate authorization; subscription URLs, credentials and
endpoint identities must not enter arguments, fixtures or captured logs.
