# ADR 0013: Bounded IPv4 TUN DNS interception

Status: experimental model/backend implementation; live acceptance pending.
Date: 2026-10-26.

## Decision

Introduce explicit `Draft::dns_interception`, default-off, encoded as schema-v2
`vpn.data.dns-interception=tun-port53`. V1 refuses it; unknown values fail, and v2
requires at least one admitted policy. This is a bounded prerequisite for FakeIP,
not allocation of synthetic addresses or full subscription execution. It uses the
existing DNS parser, framing and protocol libraries; no new dependency is added.

When enabled, IPv4 UDP/TCP port 53 reaching the worker's netstack is handled by the
selected profile resolver before TCP hostname inspection and general proxy flow
dispatch. The original application destination is not an upstream DNS authority.
UDP responses retain the original source/destination association in the netstack.
There is no kernel DNS listener, route/firewall change, packet rewrite engine,
protocol sniffing on other ports, IPv6, DoH or DoT interception. Loopback/local
listeners and traffic outside TUN are outside this contract.

The model/client/backend API supplies this explicit policy. The subscription
adapter still rejects complete configurations. COSMIC now exposes an explicit
default-off creation/replacement opt-in; it must not silently enable this mode for
existing or node-only profiles. Required source modes are not disabled by an
unchecked additional opt-in. Saved details observe the mode without secrets.

## Resolver and ownership

One worker relay handles intercepted UDP and TCP, plus the existing CurrentNetwork
internal DNS address. The fixed resolver comes only from the checked profile:

- CurrentNetwork uses the existing private `Q` RPC, whose supervisor-selected
  upstream and plain UDP/TCP disclosure are unchanged (ADR 0011).
- Inherit uses legacy `1.1.1.1` through VLESS until a complete source DNS policy is
  admitted. ProxyIpv4 uses the explicit public IPv4 resolver through VLESS.
- A TCP request uses bounded library DNS-over-TCP framing over VLESS TCP; UDP uses
  the existing bound VLESS datagram adapter. Neither falls back to the other
  transport or to a direct socket. The worker opens only a broker-approved proxy
  endpoint socket, never the application's purported DNS destination.

Parsing happens before any broker request: one bounded IN-class QUERY, without
answer/authority/signature material. Replies must match opcode/type/ID/question.
Negative responses and UDP truncation are returned unchanged; no retry. Each
exchange has a ten-second deadline covering queueing, setup, writes and response.
Messages remain limited to 4096 bytes. TCP client idle/write limits and the 32 UDP
relay-task/512 TCP-flow limits remain unchanged. The shared supervisor budget also
bounds new proxied sockets; no pool or extra unbounded queue is added.

Cancellation owns and closes each tunnel/stream. Uncertain broker cancellation
poisons the serialized channel; cancellation after completed FD admission closes
only the owned tunnel, not a valid channel. Explicit grant refusal does not poison
or trigger fallback. Diagnostics contain no query names or third-party parser text.

## LAN interaction and admission

Standalone connected-LAN bypass (ADR 0012) removes LAN destinations from TUN. The
initial interception implementation rejected that combination to prevent LAN DNS
from escaping interception. [ADR 0014](0014-intercepted-lan-relays.md) supersedes
that temporary rejection with NM-owned capture routes, a strict physical guard
and bounded root-owned LAN TCP/UDP relays after DNS dispatch. Other LAN IP protocols
are unsupported in the combined mode. This still is not full ordered source policy.

This mode cannot substitute for a source rule matching DNS by protocol at arbitrary
ports. Full subscription admission still rejects broader DNS actions, FakeIP,
unsupported IPv6/routing and client integration rather than extracting partial
profiles. Existing profiles and active host networking remain unchanged.

## FakeIP constraints found during library review

The pinned meow-rs revision `fbbb9d23a9fbcba28ac0ed69c18e2aea95e35e21` supplies
`meow-dns::fakeip::Pool`, but its cursor wraps and evicts prior allocations.
MemoryStore also evicts. FileStore debounces best-effort persistence and can treat
corruption as empty state. Those semantics alone cannot prove that an old cached
FakeIP will never be reassigned to another domain after eviction/restart.

Do not enable FakeIP by simply adding these defaults to the runtime. The owning
implementation must establish durable address identity or safe non-reuse before
publishing replies, fail closed on persistence/corruption/exhaustion, and cover
stale addresses and active-flow ownership. Persistent cache settings in a full
subscription remain unadmitted. This review adds no cache files or persistence.

## Evidence and missing acceptance

Synthetic tests cover dispatch boundaries, default-off behavior, v2 admission,
policy admission without mutation, selected-network UDP/TCP forwarding
over the private broker, malformed input without broker work, negative replies,
deadlines/refusal without fallback, and cancellation after socket admission.
A worker TCP test proves interception precedes hostname/proxy dispatch. Client
tests observe the saved mode without activation. No upstream parser test is copied.

Positive tunneled DNS interoperability, UDP netstack reply attribution, real NM
routing, packet capture and teardown still need authorized isolated peers/VMs.
No ordinary check changes host DNS/routes/firewall, contacts real nodes or proves
the complete FakeIP/LAN/subscription target. Installation remains deferred.
