# ADR 0020: Bounded native IPv4 source policy

Status: implemented experimentally; production security review and full native
source-policy acceptance remain incomplete. Owner-authorized experimental
installation does not certify these properties or arbitrary sing-box input.

## Contract

The complete importer translates one checked source shape into native profiles:
one selector of VLESS TCP TLS/REALITY/Vision or WebSocket TLS nodes, one Direct
and one Block outbound, legacy FakeIP DNS roles, and an ordered route pipeline.
Every node must validate before any result is returned. Recursive duplicate and
unknown keys reject. Unsupported settings never cause node extraction, retries,
an alternate outbound, or a node-only request.

The fixed order is sniff, DNS hijack (port 53 or recognized DNS), BitTorrent block,
ordered exact/suffix domain actions, non-public IPv4 Direct, selected proxy.
Non-public means RFC1918, loopback, link-local, multicast and unspecified, matching
the source reference; it does not additionally include CGNAT or documentation IPs.
TCP inspection is bounded to 8 KiB/300 ms; QUIC v1/v2 uses at most four datagrams,
eight coalesced packets per datagram, 128 CRYPTO fragments and 8 KiB of fragment
data. Inspected bytes are replayed once. Missing/ECH/unrecognized names are not
authenticated identities and do not match domain actions. No full traffic-analysis
or encrypted BitTorrent detection is claimed. The narrow classifier exception is
[ADR 0021](0021-bittorrent-signature-classifier.md).

For complete policy, a successfully sniffed canonical HTTP Host/TLS SNI or QUIC
name selects domain rules before the original FakeIP name, matching the pinned
sing-box v1.12.0 reference. Without an observed name the owned FakeIP name remains
the rule input. These are separate identities: sniffing does not rewrite the
original destination, replace durable ownership or authorize Direct. Legacy
profiles retain their original identity-first behavior. A Block decision using
the effective rule name rejects before real destination DNS or outbound admission.
Unknown FakeIP identities and invalid observed metadata still reject.
Complete FakeIP TCP Proxy with inherited DNS retains the owned original FQDN inside VLESS without
pre-resolving it. Only an explicit Direct domain rule resolves it locally through
the selected DNS, followed by independent Direct authorization. An unresolved FQDN
does not match IP-only rules. Explicit resolver overrides retain pre-resolution
to preserve the user's DNS selection. Legacy and UDP paths retain pre-resolution; the
pinned Mux.Cool per-packet API cannot yet preserve XUDP domain destinations.

Source DNS supports one selected UDP, TCP or certificate-verified TLS resolver,
through the selected proxy or explicitly Direct. Resolver hostnames require the
declared local bootstrap role, mapped to NM's selected-uplink plain IPv4 DNS.
Bootstrap A answers are bound to the question/CNAME chain. There is no resolver
fallback. The response cache is bounded to 256 entries, question/transport-bound,
activation-local and TTL-aged; it is not the durable FakeIP identity store.
Explicit per-profile DNS overrides remain independent of the imported resolver.

Client A/AAAA FakeIP uses the durable non-reassigning `/16` allocator, with empty
IPv6 answers. Source `/15` reservations are accepted but never allocate extra
leases: the persistent physical-output guard reserves all `198.18.0.0/15`.
Unknown synthetic identities reject. The 16,384-identity lifetime limit and
identity invariants in [ADR 0016](0016-persistent-ipv4-fakeip.md) remain.
[ADR 0022](0022-session-scoped-guards.md) replaces the boot prerequisite with
automatic session-scoped guards. [ADR 0026](0026-automatic-session-recovery.md)
supersedes failure retention: clean disconnect and terminal failure remove guards
after resource teardown, restoring ordinary networking without VPN.

## Privileged authority and lifecycle

Unlike the legacy worker-only protocol path, source DNS executes protocol libraries
in the root supervisor. It owns selected-resolver TCP/UDP sockets, VLESS/XUDP and
verified TLS sessions. This expands the privileged parsing/crypto attack surface;
the original blanket claim that all protocol processing is unprivileged no longer
applies. DNS requests are bounded and validated, resolver/detour choices come only
from the validated profile, and each exchange has an external deadline. Cancellation
or session teardown drops resolver, cache, bridges and owned sockets.

Worker `P` requests are not authority. Root independently rejects IPv6, port 0/53,
synthetic ranges and non-Direct policy decisions before socket creation. Public
Direct destinations additionally require membership in a fresh/cached answer from
the selected real resolver, not an unrelated uplink verification query. Non-public
IP Direct requires no DNS membership. Root retains IP descriptors and exports only
Unix payload channels, with bounded relay slots and no fallback on refusal.
Selecting a Direct rule through sniffed metadata does not remove the independent
selected-resolver membership requirement; mismatching original-destination and
sniffed-name DNS answers may still refuse a flow that sing-box allows. This
deliberate authority boundary remains a compatibility limitation.

NM still installs normal routes/DNS. Selected-uplink connected/static prefixes are
captured with more-specific VPN routes; `/31` and `/32` capture rejects. Capture
prefixes never grant Direct authority or physical firewall exceptions. Source TUN
and FakeIP namespace conflicts reject before TUN/firewall setup. Legacy LAN/TCP
overlays cannot combine with this policy. Uplink changes require reconnect.

UDP uses the pinned protocol library's VLESS CommandMux/Mux.Cool XUDP path,
one supplied endpoint stream and one logical datagram flow per association.
Empty and over-8,192-byte datagrams reject before writing. No ordinary VLESS UDP
substitution or implicit redial is allowed. Drop releases the library association
and host relay. Isolated pinned-peer tests cover REALITY/Vision echo, bounds,
invalid authentication and bridge cleanup, not NM enforcement or real providers.

## Exclusions and acceptance

[ADR 0017](0017-ipv4-only-first-version.md) defers IPv6 while retaining blocking;
[ADR 0019](0019-source-client-integration-exclusions.md) excludes foreign listeners,
platform proxy controls, controller/web UI and file paths. These exclusions are
disclosed before saving, not permission to ignore networking policy. Source
selector entries become explicit per-node profiles without automatic switching.

Native NM/Polkit replacement, route packets, root DNS, boot restoration, crash
teardown and the exact private subscription remain acceptance gates. Repository
tests and isolated XUDP do not establish deployment readiness or production safety.
The [name-precedence comparison](../research/sing-box-compatibility.md) checks one
bounded route-decision matrix, not wire or deployed equivalence.

## References

- [sing-box v1.12.0 sniff reference](https://github.com/SagerNet/sing-box/tree/v1.12.0/common/sniff)
- [sing v0.7.0-beta.2 address classification](https://github.com/SagerNet/sing/blob/v0.7.0-beta.2/common/network/addr.go)
- [Dependency review](../dependency-review.md)
