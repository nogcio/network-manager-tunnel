# Shared profile model

Desktop- and NetworkManager-independent editable `Draft`, typed executable `Profile`,
static field errors and single-link VLESS import. No I/O, DNS, subscription fetch or engine.

`Draft::private_lan_bypass` explicitly selects all-RFC1918 physical bypass,
including routed private networks. It cannot combine with legacy connected-only
`lan_bypass` or complete source policy. It does not discard DNS interception or
FakeIP ownership; see [ADR 0024](../../docs/decisions/0024-private-ipv4-bypass.md).

Supported subset: TCP (`tcp`/`raw` import) with TLS/REALITY and optional Vision,
or WebSocket (`ws`) with verified TLS and no Vision. WebSocket request path/query
and optional HTTP Host override are preserved separately from the server and SNI.
Missing WS path means `/`; missing Host means no explicit override, not SNI.
VLESS uses `encryption=none`, six browser profile labels and optional h2/http/1.1 ALPN.
WebSocket uses HTTP/1.1 Upgrade: ALPN must be absent or offer only `http/1.1`;
explicit `h2` offers are rejected, not rewritten. Hostnames and SNI must be ASCII
(punycode for IDNs), with no URL percent encoding. Validation preserves their spelling
and permits case differences, but rejects names needing decoding or IDNA conversion.
Unknown/duplicate link parameters and incompatible security fields are rejected,
not silently dropped. REALITY keys must be 32-byte nonzero unpadded base64url;
short IDs use zero to eight complete hex bytes. Links are bounded to 8 KiB.

This version is IPv4-only. IPv6 literal endpoints, including IPv4-mapped IPv6,
reject during URI import and draft validation without conversion or mutation.
Hostnames remain valid but require an IPv4 A record at activation. The runtime
keeps IPv6 leak blocking; see [ADR 0017](../../docs/decisions/0017-ipv4-only-first-version.md).

Credentials use `SecretString`; Draft/Profile Debug is redacted. URL parsing uses
`url`, UUID parsing uses `uuid`, and key decoding uses `base64`. The import module
only applies our supported-subset policy; it is not another general URL parser.
The broader `vpn-link-serde` schema is not adopted because accepting its broader
formats without representing their settings would silently lose configuration.

The [experimental engine](../engine/README.md) applies fingerprint settings, but
rejects REALITY Android rather than substituting Chrome. The experimental
[NM backend](../nm-service/README.md) consumes these profiles; production admission is pending.
Validation tests do not establish REALITY key security, fingerprint fidelity, wire
compatibility or tunnel readiness. See [research](../../docs/research/rust-protocol-libraries.md).

## Optional TCP hostname policy

`TcpDomainPolicy::from_json` validates a bounded internal policy before it can be
attached to `Draft::tcp_domain_policy`. This is not a sing-box config parser:

```json
{
  "version": 1,
  "rules": [
    {"domain": ["blocked.example"], "action": "block"},
    {"domain_suffix": ["direct.example"], "action": "direct"}
  ]
}
```

The first matching rule wins; exact/suffix alternatives in one rule are ORed.
`example.test` as a suffix matches the apex and subdomains; `.example.test` matches
only subdomains. Unknown/absent names stay proxied. Names are ASCII-normalized with
strict label boundaries, not substring, wildcard, regex or IP reverse matching.
The bounds are 16 KiB, 64 rules and 128 names total; unknown fields, actions and
versions fail atomically. Debug/errors are redacted; `as_json` contains potentially
identifying domains and must not be logged. There is no I/O or mutable global state.

The [shared NM codec](../nm-schema/README.md) encodes these profiles as schema v2,
and the worker consumes the
policy for library-observed HTTP Host/TLS SNI only. Direct routing has additional
supervisor DNS/IP authorization and can be refused; it does not authorize LAN
access. With explicit FakeIP, owned names can also govern UDP; the separate complete
policy adds QUIC metadata and ordered source actions. Those extensions do not widen
legacy sniffing-only rules. See [ADR 0010](../../docs/decisions/0010-tcp-domain-routing.md)
and [ADR 0020](../../docs/decisions/0020-native-ipv4-source-policy.md).

## Per-profile DNS override

`Draft::dns_override` is independent of TCP rules. Inherit keeps admitted/default
policy (URI-only legacy default `1.1.1.1`); CurrentNetwork selects the primary NM
uplink's first usable IPv4 DNS at each activation; ProxyIpv4 selects one public
IPv4 resolver through the VPN. CurrentNetwork permits plain UDP/TCP DNS outside
the VPN, not importing OS DoT/IPv6 resolver policy. Only its mode is stored, not a
DHCP address. Manual private/IPv6/encrypted resolvers fail validation.

Overrides never remove routing rules. Manual through-VPN DNS plus Direct hostname
rules is currently rejected rather than leaking Direct verification queries through
another resolver. Canonical `from_nm`/`to_nm` values use schema v2; unknown modes and
bad combinations return static errors without I/O or source mutation. There is no
manual protocol editor. COSMIC's narrow saved network editor is defined by
[ADR 0027](../../docs/decisions/0027-cosmic-profile-and-source-management.md).
Bounded complete IPv4 execution is experimental, not arbitrary
foreign-policy compatibility. Explicit saved-profile
replacement is now defined by [ADR 0018](../../docs/decisions/0018-checked-profile-replacement.md).
Runtime ownership and
remaining FakeIP/LAN work are in [ADR 0011](../../docs/decisions/0011-profile-dns-overrides.md).

`Draft::lan_bypass` is an explicit default-off exception for connected RFC1918
subnets on the selected NM uplink, not arbitrary/private-address matching. It
bypasses hostname policy for those destinations; IPv6 remains blocked. NM resolves
subnets at activation, not profile save. See
[ADR 0012](../../docs/decisions/0012-connected-lan-bypass.md) for ownership and limits.

`Draft::dns_interception` explicitly routes IPv4 UDP/TCP port 53 reaching TUN to
the selected resolver. It defaults off, does not allocate FakeIP, and does not
intercept DoH/DoT, IPv6 or DNS at other ports. Combined LAN/interception mode handles
DNS first, then connected unicast TCP/UDP through bounded supervisor-owned relays,
without an unmarked physical LAN exception. Other local IP protocols are unsupported;
point-to-point LAN prefixes reject at activation. No policy is silently disabled.
See [ADR 0013](../../docs/decisions/0013-tun-dns-interception.md) and
[ADR 0014](../../docs/decisions/0014-intercepted-lan-relays.md) for lifecycle/limits.

`Draft::fake_ip` additionally requires interception and encodes the default-off
`persistent-ipv4-v1` mode. It preserves durable /16 domain identities without reuse;
IPv6 is still blocked and AAAA is empty. The first-version IPv4-only source subset
requires explicit disclosure, not silent IPv6 compatibility. Known FakeIP names
apply the checked policy to TCP and UDP;
explicit domain decisions precede connected-LAN fallback. Missing ownership fails
without a network fallback. Boot support, storage privacy/durability and remaining
acceptance are in [ADR 0016](../../docs/decisions/0016-persistent-ipv4-fakeip.md).

## Execution-facing views

Complete source-policy v2 adds native `RoutePolicy` destination predicates: exact/
suffix domains, IPv4 CIDRs, destination ports/ranges and logical AND/OR/inversion.
Address alternatives within a default rule are ORed, then ANDed with its port
alternatives; the first matching terminal rule wins. The public matcher has no I/O
or socket authority. Root independently repeats policy and selected-resolver DNS
membership checks before public named Direct. CIDR matches alone do not authorize
unnamed public Direct.

Unresolved names have no real IP; FakeIP is never used for CIDR matching. Inherited
DNS does not resolve solely for an IP predicate. A provisional named Direct route
is checked again after resolving its original name; disagreement refuses the flow
without another outbound. The native envelope uses `route_policy` only with source
version 2 (or DNS version 3); v1 retains `domain_policy`, and both together reject.
Existing profiles are not migrated; old backends reject v2/v3. Full limits and
unsupported combinations are in [ADR 0020][destination-predicates].

Complete import also compiles bounded inline sets into this same tree. A single
non-inverted default set entry merges like groups with its outer rule; multi-entry,
logical and inverted sets remain independent AND constraints. Different referenced
tags remain OR branches, not pooled groups. No source set tag, local path, remote
fetch or binary-set parser is added to this model or its runtime consumers.

[destination-predicates]: ../../docs/decisions/0020-native-ipv4-source-policy.md#destination-predicates-in-native-source-policy-v2

`SourceDns` separates socket IP/optional bootstrap hostname, TLS verification name,
selected Direct/proxy route and wire transport. `SourceDns::validated` is shared by
native profile admission and import of every declared resolver, including unused
ones, so selection cannot hide an invalid endpoint. It performs no I/O.
HTTPS adds a bounded `http_path`
(default `/dns-query`) without query/fragment tokens, controls or authority syntax;
it is omitted from older non-HTTPS JSON so legacy profile encoding stays unchanged.
Non-HTTPS policies reject nonempty HTTP paths. Debug redacts these identifying
settings. Validation has no I/O and never upgrades/migrates active or stored profiles;
the older backend rejects the unknown HTTPS transport instead of downgrading it.

Source v3 additionally stores bounded ordered exact/suffix DNS rules. `dns_for`
returns the first matching `SourceDnsSelection` (a checked endpoint or the NM
current-network role), otherwise `dns()` supplies the default real endpoint.
`has_dns_rules()` requires TCP/UDP Proxy destinations to pre-resolve their original
owned name instead of bypassing this selection with remote VLESS DNS. The rule tree
and DNS policy remain immutable; selection has no I/O or socket authority. Runtime
overrides explicitly replace real-DNS selection; bootstrap and client FakeIP remain
separate. See [ADR 0020][dns-selection]
for bounds, ordering, cache/Direct authority and unsupported DNS behavior.

[dns-selection]: ../../docs/decisions/0020-native-ipv4-source-policy.md#ordered-real-dns-selection-in-native-source-policy-v3

`Profile::routing` exposes checked `RoutingPolicy` semantics rather than a source
format or NM schema version. `Profile::lan_bypass` returns one mutually exclusive
`LanBypass` mode, even though editable/imported Drafts retain raw compatibility
fields. Neither view grants sockets, performs DNS nor owns live network resources.
Profile stores no Draft: `node()` borrows typed endpoint/peer security/ALPN/framing,
`credential()` owns parsed UUID bytes in a redacted secrecy container, and `network()`
borrows immutable policy. FakeIP/interception and complete/legacy exclusivity are
represented by enums rather than runtime boolean combinations. The engine no longer
parses ports, UUIDs or REALITY material on each flow. `to_draft()` explicitly creates
an editable copy, canonicalizing numeric/hex/UUID spelling without I/O or automatic
profile migration. Exposed/copied authentication bytes and serialized secret text
can still have transient copies; zeroization of the owned container is not a
guarantee about every library, stack or D-Bus buffer.
`Draft::validate_policy` validates non-secret policy combinations for metadata
observation; `validate_configuration` additionally checks public transport fields.
Only full `validate`, including credentials, constructs an executable Profile.
