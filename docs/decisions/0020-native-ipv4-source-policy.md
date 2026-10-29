# ADR 0020: Bounded native IPv4 source policy

Status: implemented experimentally; production security review and full native
source-policy acceptance remain incomplete. Owner-authorized experimental
installation does not certify these properties or arbitrary sing-box input.

## Contract

The complete importer translates one checked source shape into native profiles:
one selector of VLESS TCP TLS/REALITY/Vision or WebSocket TLS nodes, one Direct
and an optional legacy Block outbound, checked legacy or typed FakeIP DNS roles,
and an ordered route pipeline. Modern post-sniff reject rules do not need a Block
outbound.
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
Source-v1/v2 FakeIP TCP Proxy with inherited DNS retains the owned original FQDN
inside VLESS without pre-resolving it. Only an explicit Direct domain rule resolves
it locally through the selected DNS, followed by independent Direct authorization.
An unresolved FQDN does not match IP-only rules. Explicit resolver overrides retain pre-resolution
to preserve the user's DNS selection. Complete-policy XUDP now uses the same owned
original-name preparation as TCP, through the pinned library's typed domain API.
Each packet retains the domain; responses must carry exactly that name and port.
IP/absent domain responses reject without fallback. Legacy bound UDP retains
pre-resolution. This introduces no persisted profile or FakeIP identity migration.

Source-v1/v2 DNS supports one selected UDP, TCP, certificate-verified TLS or HTTPS resolver,
through the selected proxy or explicitly Direct. Resolver hostnames require the
declared local bootstrap role, mapped to NM's selected-uplink plain IPv4 DNS.
Bootstrap A answers are bound to the question/CNAME chain. There is no resolver
fallback. The response cache is bounded to 256 entries, question/transport-bound,
activation-local and TTL-aged; it is not the durable FakeIP identity store.
Explicit per-profile DNS overrides remain independent of the imported resolver.

The typed DNS subset follows sing-box v1.12.0: `udp`, `tcp`, `tls`, `https`,
`local` and `fakeip` servers with checked tags and explicit local hostname bootstrap.
Unlike legacy DNS, typed servers default to Direct without `detour`. A checked
`route.default_domain_resolver` naming local may replace the deprecated outbound
DNS rule; client A/AAAA still uses FakeIP. Other DNS actions, resolver graphs,
active per-query modifiers, custom TLS roots/verification bypass and nonempty HTTP
headers reject atomically. Checked typed TLS verification-name overrides are retained.
String shorthand and object forms of `domain_resolver` are admitted for typed DNS
servers, VLESS endpoint bootstrap and the route default only when they select the
same declared local role. Object `strategy` is omitted or `ipv4_only`; cache/TTL/ECS
fields are absent or their neutral false/null values. DNS `action:route` uses the
same checked options. Non-neutral options and conflicting legacy `domain_strategy`
plus explicit endpoint `domain_resolver` reject, rather than weakening authority.

After the mandatory sniff/hijack prefix, modern route rules may use explicit
`action:route` or `action:reject`. Reject without an outbound translates to native
Block for BitTorrent or ordered domain rules. Omitted/default/drop reject methods
close these established/post-sniff flows as in the sing-box reference; this is not
general pre-sniff TUN rejection with TCP RST/ICMP responses. `no_drop:true` and
reject+outbound ambiguity reject. The fixed order and final private-IP Direct
rule remain mandatory, and route destination overrides, extra resolve actions,
timeout/fragment modifiers and unsupported rule-set conditions are not discarded
or approximated.

The legacy domain-only inline path compiles into the existing ordered domain-policy
without a new runtime matcher, resolver, storage format or Direct capability.
Declarations use `type:inline` (or omit type), a unique tag and nonempty headless
rules. Exact/suffix alternatives, set entries, referenced tag lists and logical OR
nodes form a union under the referring route's action. Source route order and
first-match behavior remain unchanged. Rules combining a set reference with an
explicit group use the source-v2 compilation described below, not legacy flattening.
All declarations validate, even unused ones. Limits are 32 sets, 128 headless nodes,
depth 8, 128 declared names and 16 KiB serialized declarations; the native 64-rule,
128-expanded-name and 16-KiB policy budgets remain unchanged. Repeated references
consume the expanded budget. The source-v2 path below supports destination CIDR,
ports, logical AND/OR and inversion. Recursive references, regex, source-address
and other unsupported conditions, local/remote/binary sets and DNS sets reject.
No referenced file is read and no URL is fetched. Native names, not source tags or
containers, survive compilation. This adds format compatibility, not independent
packet/security acceptance or authorization beyond the existing selected-resolver
Direct check.

### Destination predicates in native source-policy v2

The complete importer additionally admits bounded destination conditions in the
middle ordered route rules: `domain`, `domain_suffix`, IPv4 `ip_cidr`, destination
`port`/`port_range`, logical AND/OR and `invert`. IPv4 literals without a slash
become /32; CIDRs normalize to their network using the existing ipnet library.
Port ranges are inclusive, including `:N` and `N:` within 1..65535; port zero,
IPv6, malformed/reversed ranges and empty conditions reject. No process/source-IP,
regex, network-type, extra action or destination override is silently discarded.

This follows the destination group in sing-box 1.14.4's default rule: exact names,
suffixes and IP CIDRs within one default condition are ORed, then ANDed with its
port alternatives. Logical nodes explicitly combine complete conditions. Invert
negates the complete node, including its missing-name/IP alternatives. The first
explicit match wins. The mandatory sniff/DNS/BitTorrent prefix and final non-public
Direct/default Proxy behavior do not change.

The native source envelope uses `version:2` and `route_policy` containing native
predicate schema v1. V1 source profiles still contain only `domain_policy` and keep
their representation and behavior. Ambiguous envelopes with both policies reject;
older backends reject v2 instead of discarding its constraints. No saved profile or
active session is migrated. Domain-only legacy imports still compile to source v1.

Native predicates have at most 64 terminal rules, 128 condition nodes, depth 8,
256 total name/CIDR/port-interval values and the existing 16-KiB encoded-policy
budget (also applied to the complete source envelope). Limits are checked both
during import and by the independent profile model. Public `RoutePolicy` is
immutable, redacted in Debug, and has no I/O or capability to create sockets.

TCP and UDP both evaluate owned unresolved names with the actual destination port
before DNS or outbound admission. An unresolved FQDN has no real IP: CIDR
alternatives do not match it and a FakeIP address is never substituted. No new DNS
lookup is performed merely to satisfy an IP condition. This is a bounded matcher,
not full sing-box domain-resolution semantics; general resolve actions are absent.
With inherited DNS, explicit Direct resolves the original name and evaluates policy again
against the real destination. An inconsistent final decision refuses the flow,
never switches it to another outbound. Root repeats the same predicate evaluation;
public Direct still requires a canonical name and independent selected-resolver
DNS membership. A CIDR match alone cannot grant unnamed public Direct access.

Inline sets can declare the same bounded destination predicates, including CIDRs,
ports and nested AND/OR/inversion, without actions or recursive set references.
All declarations validate even when unused: at most 32 sets, 128 headless nodes,
depth 8, 128 names, 256 total match values and 16 KiB serialized declarations.
Only referenced predicates are expanded into the native route tree; unused valid
destination sets do not change an otherwise legacy source-v1 representation.

Composition preserves the sing-box 1.14.4 set-shape boundary:

- A set with exactly one non-inverted default entry merges its address alternatives
  with the outer default address group, and its port alternatives with the outer
  port group. Alternatives within each group are ORed; different groups are ANDed.
- Multi-entry, logical and inverted sets are self-contained. Their entries are ORed
  and the set result is ANDed with the complete outer default condition.
- Referenced tags are separate OR branches. Groups are never pooled across tags;
  outer inversion applies after the complete reference composition.

Compilation uses the existing native predicate schema, not new worker rules or a
parallel matcher. Expansion is model-validated incrementally, including repeated
references, against native tree/value/byte limits before another branch or terminal
rule is added. Source tags and set containers do not survive in NM data. Recursive,
remote/local/binary, regex, source-IP remapping and DNS sets remain unsupported.

Verification covers pure import/model semantics, schema/version/budget rejection,
TCP/UDP dispatch and independent Direct authorization without external traffic.
The earlier 40-case VM result describes the preceding implementation, not deployed
acceptance of these new predicates; no new VM run is implied.

Reference: [sing-box v1.14.4 route conditions][destination-rules].
The [versioned set composition implementation][set-composition] establishes the
single-default-entry merge boundary; this source was consulted, not copied.

[destination-rules]: https://github.com/SagerNet/sing-box/blob/v1.14.4/docs/configuration/route/rule.md
[set-composition]: https://github.com/SagerNet/sing-box/blob/v1.14.4/route/rule/rule_item_rule_set.go

## Ordered real-DNS selection in native source-policy v3

Source v3 adds an explicit `dns_policy` (predicate schema v1) and retains exactly
one of `domain_policy` or `route_policy`. V1/v2 reject nonempty DNS policies; v3
requires one. Existing profiles keep their encoding and remote-domain behavior;
old backends reject v3, never silently use only its default resolver. NM remains
the profile/route/DNS owner. There is no new service, dependency or persistent cache.

The complete importer admits up to 64 ordered exact/suffix real-resolution rules,
128 total names and eight declared DNS servers including the local/FakeIP roles.
Names in one rule are ORed with strict label boundaries; the first matching rule
wins, otherwise the existing `dns.final` real endpoint applies. Each rule selects
an explicitly checked Direct/Proxy UDP/TCP/DoT/DoH endpoint or `local` (the NM
uplink's plain IPv4 DNS, always Direct). TLS identity and DoH path belong to each
endpoint, including a non-default endpoint. Source tags compile to bounded resolver
indices; they are not runtime authority or stored source identifiers. Native DNS
policy has at most eight resolver entries and shares the 16-KiB source envelope.

Domain rules must follow both the bootstrap rule and the mandatory client A/AAAA
FakeIP rule. Modern sources may supply the bootstrap role through
`route.default_domain_resolver` instead of the legacy `outbound:any` rule. Rules
before FakeIP, per-domain FakeIP suppression, query-type conditions, DNS logical
trees/inversion/rule-sets, response actions and non-neutral cache/TTL/ECS modifiers
reject. This preserves client FakeIP instead of pretending that an earlier real-DNS
rule has no effect. For real resolution FakeIP is skipped, matching the reference's
[real-resolution/FakeIP boundary][dns-walk]; no foreign implementation was copied.

With v3, owned FakeIP TCP/UDP destinations resolve their **original** name through
the selected real resolver even for Proxy; VLESS receives the real IP rather than
delegating DNS to the peer. Otherwise the explicit resolver choice would be lost.
Observed names still govern routing independently. Block precedes destination DNS;
unknown FakeIP never reaches it. Real-IP predicates can match after this required
query; the generic route `resolve` action is still unsupported. Provisional Direct
is rechecked after DNS and refuses on disagreement. A DNS failure never retries
the default resolver, another route, remote-domain VLESS or host DNS.

The privileged transport derives selection again from the validated question and
immutable activation profile; no worker-supplied resolver index is accepted. Public
named Direct still requires independent membership in the selected resolver's
answer for the authorization name. Different original/observed names may therefore
select different DNS rules and refuse a flow; this does not relax authority.
Explicit user DNS overrides replace source selection for all real queries, not
FakeIP/bootstrap. No DHCP DNS address is persisted in the policy.

Cache ownership remains activation-local and question/transport-bound. Since
selection is deterministic from the immutable profile and question, an identical
cache key cannot change resolver within that cache. Uplink/profile replacement
creates a fresh authority/cache. Responses require the original question/answer
chain; errors, cancellation and timeouts publish no entry or application socket.

Local evidence covers import/version/budget rejection, canonical selection,
NM writer/observer/executable-admission round trips without policy/secret loss,
original-name TCP/UDP pre-resolution, override precedence, Direct DNS membership,
cache separation and failure/timeout/cancellation without fallback. It does not
extend the earlier VM result to v3 or establish positive encrypted-DNS peer/native
desktop interoperability. No new VM campaign or host-network activation is required.

[dns-walk]: https://github.com/SagerNet/sing-box/blob/v1.14.4/dns/router.go

### Source DNS exchanges

DoH uses RFC 8484 POST over certificate-verified HTTP/1.1, one approved socket,
no redirect/retry/environment proxy and no fallback. Default port/path is 443 and
`/dns-query`; only bounded origin paths without query/fragment tokens are stored.
An optional TLS identity remains separate from HTTP authority and socket address.
Only status 200, `application/dns-message`, no content encoding/trailers, and a
1..=4096-byte DNS response is accepted. Hyper owns HTTP framing, including chunking;
the shared resolver still binds DNS replies to the question/ID before cache admission.
The ten-second total exchange budget includes bootstrap, transport, TLS and HTTP.
Cancellation drops both driver and socket without detached work. HTTP parsing now
runs in the root source-DNS path, expanding privileged surface; synthetic contracts
are not independent security or live DoH acceptance. Old profiles omit the optional
native `http_path` field unchanged; an older backend rejects new HTTPS transports,
not downgrades them. Existing NM profiles and active sessions are never migrated.

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
overlays cannot combine with this policy. Persistent NM sessions rebuild these
plans and revoke all old sockets/caches on uplink changes under
[ADR 0033](0033-persistent-network-lifetime-and-nm-agents.md); nonpersistent profiles
still require an explicit reconnect.

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
- [sing-box v1.12 typed DoH](https://github.com/SagerNet/sing-box/blob/v1.12.0/docs/configuration/dns/server/https.md)
- [sing-box v1.12 typed DoT](https://github.com/SagerNet/sing-box/blob/v1.12.0/docs/configuration/dns/server/tls.md)
- [sing-box v1.12 dial fields](https://github.com/SagerNet/sing-box/blob/v1.12.0/docs/configuration/shared/dial.md)
- [sing-box v1.12 DNS route actions](https://github.com/SagerNet/sing-box/blob/v1.12.0/docs/configuration/dns/rule_action.md)
- [sing-box v1.12 route actions](https://github.com/SagerNet/sing-box/blob/v1.12.0/docs/configuration/route/rule_action.md)
- [sing-box v1.12 inline sets](https://github.com/SagerNet/sing-box/blob/v1.12.0/docs/configuration/rule-set/index.md)
- [sing-box v1.12 headless rules](https://github.com/SagerNet/sing-box/blob/v1.12.0/docs/configuration/rule-set/headless-rule.md)
- [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484)
