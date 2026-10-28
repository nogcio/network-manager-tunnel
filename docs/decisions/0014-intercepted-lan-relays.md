# ADR 0014: Connected LAN relays after DNS interception

Status: experimental backend implementation; native/VM acceptance pending.
Date: 2026-10-26.

## Decision and scope

Permit the existing `lan_bypass` and `dns_interception` policies together without
letting connected-LAN DNS escape the TUN. This replaces ADR 0013's temporary
combination rejection. Neither policy is silently disabled. Legacy standalone LAN
bypass retains ADR 0012's physical-route/guard-exception behavior.

In the combined mode, DNS interception runs first, then connected RFC1918 unicast
TCP/UDP uses a supervisor-authorized direct relay. Other LAN IP protocols, including
ICMP, are unsupported in this mode; IPv6 remains blocked. Local-host/kernel-local
destinations and traffic not reaching TUN remain outside the interception contract.
This is not broader subscription `ip_is_private` matching, arbitrary-port DNS
sniffing, BitTorrent classification or full ordered subscription admission.

## NetworkManager and guard ownership

Read the same bounded selected-device address snapshot as ADR 0012. The supervisor
retains original private connected prefixes as well as their aggregated cover.
Original boundaries must not become authorized unicast merely because aggregation
merged adjacent prefixes. Combined mode rejects original /31 and /32 prefixes
before privileged resources; their point-to-point semantics are not implemented.

NM receives two IPv4 /1 VPN routes and two more-specific halves of **each original
connected prefix**. This captures LAN traffic ahead of the physical connected
routes, including overlapping address prefixes. It avoids a custom routing table,
port-based kernel rewrites, netlink route writer or independent route manager.
`never-default=true` suppresses the ordinary /0; explicit routes still cover all
IPv4. NM applies and removes every normal route.

The combined-mode guard creates **no unmarked physical LAN exception**. Existing
loopback, marked upstream, TUN and IPv6 rules remain. An unrelated more-specific
physical route therefore cannot produce an unmarked DNS/LAN escape; it can make a
flow unusable instead. NM route application, DNS and such conflicts still need
packet-level acceptance. No host networking changes occur in ordinary tests.

## Supervisor authority and private IPC

The worker receives a bounded activation-local snapshot over the private config
channel, never in persisted `vpn.data`. It validates the mode/prefixes before
readiness, but its snapshot is not authority for the supervisor. The supervisor
checks its own NM-derived plan for every new `L` grant. Only a destination and
TCP/UDP selector can be requested: no interface, prefix, mark, URL or DNS name.

Public/non-connected/IPv6 destinations, every original network/broadcast boundary,
port zero and port 53 reject **before socket creation**. DNS must use the selected
resolver path, even when a compromised worker requests a raw LAN grant. Refusal
never falls through to proxy or hostname Direct. Frames are at most 128 bytes and
have five-second read deadlines; grants share the existing 64-request/s budget.

The new LAN path transfers **only Unix payload channels**, never marked IP sockets:

- TCP: root retains the connected, marked, uplink-bound IP socket and bridges it
  to a private Unix stream. Tokio owns backpressure and half-close. The worker
  gets a Unix stream, with no IP destination API or IP socket option capability.
- UDP: root retains a connected IP socket for one destination and bridges payloads
  over a private Unix datagram pair. A connected UDP IP descriptor must not be
  handed out as a destination-confined capability: a recipient could retarget it.
  Datagrams are at most 65,507 bytes, writes have five-second deadlines and the
  relay expires after sixty seconds without traffic. Empty UDP payloads are valid.

The worker verifies descriptor family, type and connected Unix peer while owning
the serialized exchange. Wrong descriptors close and poison the channel before a
queued grant can proceed. Uncertain cancellation poisons it; explicit refusal and
dropping an already-admitted payload channel do not. No destinations/payloads are
included in diagnostics. [ADR 0015](0015-root-owned-endpoint-relays.md) extends root
ownership to endpoint and hostname-Direct paths too; grant-time IP peer checking
alone is not claimed as post-grant confinement.

## Lifecycle and resource bounds

The original LAN-only limits were 512 TCP and 64 UDP grants. ADR 0015 replaces the
TCP set with a shared 609-slot endpoint/Direct/LAN set; UDP remains bounded at 64.
Completed results are reaped before new LAN admission. Worker limits remain 512
TCP tasks and 64 UDP associations, plus the existing 32 DNS tasks; full queues and
refusals never trigger another outbound. UDP flow tuples remain worker-owned, so
replies are attributed to the original application destination, not the Unix peer.

The broker future owns both relay task sets. Session cancellation/drop aborts the
broker and its bridges, releasing root IP sockets and local payload channels.
Individual TCP I/O completion/error closes that bridge; UDP also has its idle bound.
Idle UDP channels can remain until that bound after a worker closes its end.
Unexpected session failure retains the strict guard; clean teardown remains NM's
normal route removal plus existing explicit guard lifecycle.

No profile migration, native creation switch, new dependency or persistent cache
is introduced. Saved details distinguish the combined TCP/UDP relay mode from
standalone LAN bypass. Full configuration execution and FakeIP remain unimplemented.

## Evidence and remaining acceptance

Pure tests cover route specificity, original subnet boundary retention, strict
guard output, mode/snapshot checks and unchanged plans on rejection. Root socket
admission tests reject protected/DNS/public targets before privileged work. Private
FD tests exercise Unix-only payload grants, wrong IP-descriptor closure/poisoning,
refusal and cancellation. Loopback relay tests cover TCP bytes/cancellation, UDP
payloads including empty messages, oversize rejection, idle cleanup and channel
closure. Worker tests show local DNS precedes LAN dispatch and local TCP/UDP grants
do not fall through on refusal. No root privileges or real LAN/node is required.

These checks do not prove real NM route precedence, marks/interface binding,
IPv6/public packet isolation, UDP netstack attribution or crash teardown on a host.
Those remain authorized VM/native acceptance gates, alongside full-policy/FakeIP
work and positive endpoint/Direct relay interoperability. Installation stays
deferred; component checks are not a complete VPN security assessment.
