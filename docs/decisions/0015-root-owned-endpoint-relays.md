# ADR 0015: Root-owned endpoint and Direct TCP relays

Status: experimental implementation; interoperability/packet acceptance pending.
Date: 2026-10-26.

## Decision and trust

Extend ADR 0014's Unix payload-channel boundary to every brokered TCP flow: proxy
endpoints, hostname Direct and LAN. A grant-time peer check on an exported marked
IP socket is not durable confinement: a recipient must not get an IP descriptor
that could be disconnected/reconnected or reconfigured. Root now retains every
marked IP socket; the worker gets only connected Unix payload channels.

Root authorization is unchanged: endpoint grants use the selected fixed endpoint;
hostname Direct requires policy and independent DNS/IP verification; LAN requires
the root's NM snapshot. Descriptor family/type/connected-peer validation stays
inside the serialized exchange. IP descriptors reject even if their type/peer
looks correct. Uncertain cancellation/malformed replies poison the channel;
explicit refusal and cancellation after completed admission do not. No fallback.

The engine's consumed `EndpointStream` has a real service consumer. Existing TCP
callers derive peer metadata from `peer_addr`. `EndpointStream::relayed` accepts
an owned Unix channel and a trusted host's fixed-peer attestation; it cannot
discover/authenticate a relay's IP peer. Authenticating the supervisor/control
channel belongs to the host. Approved endpoint/profile port/literal profile IP are
still checked before protocol I/O. TCP and UDP-over-VLESS consume the same input,
without implicit DNS, socket creation, redial or a new dependency/toolkit coupling.

## Lifecycle and bounds

The broker owns a shared 609-slot TCP relay set: 512 worker TCP flows, 64 proxied
UDP associations, 32 DNS tasks and one health probe. Reap completed tasks before
admission, check capacity before privileged socket creation and again before
payload transfer. Refusal cannot grant another destination or trigger retry.

Established bidirectional traffic has no lifetime deadline. After either half
closes, the other gets sixty seconds to drain, then the bridge closes. Abandoned
half-closed worker channels therefore cannot pin root slots forever. Session
cancellation owns/aborts the set and closes IP and Unix ends. Direct UDP retains
the separate 64-relay limit and existing idle/write deadlines.

The guard also drops forwarding from `nmtun0` for both IP families, leaving unrelated
interface forwarding unchanged. OUTPUT filtering alone would not cover malicious
TUN injection when host forwarding is enabled. Normal local-application replies
use INPUT, not FORWARD. VPN routing for other machines is outside this contract.

## Evidence and gaps

Engine tests cover raw/relayed metadata rejection before handshake, TCP/UDP setup
cancellation, channel ownership and no redial. Broker tests reject IP descriptors
and preserve poisoning/refusal semantics. Ordinary loopback bridge tests cover
bytes, half-close deadlines and session cancellation. Guard-program tests cover
the TUN-specific rule, not privileged nft application.

These checks do not establish positive TLS/REALITY/Vision relay interoperability,
NM routes, marks, nft evaluation or a complete sandbox against local IPC/application
threats. Authorized packet-level VM/native checks remain necessary. FakeIP, full
source policy admission and native
[saved-profile replacement](0018-checked-profile-replacement.md) acceptance remain
unfinished; installation
is still deferred.
