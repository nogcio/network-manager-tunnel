# Subscription loading

Shared client library for explicit HTTPS format negotiation, fail-closed complete
configuration admission and bounded legacy URI-list decoding.
It has no UI toolkit, NM activation, background scheduler or disk storage.

## Fetch policy

- Only an explicitly supplied HTTPS URL, at most 8 KiB; no userinfo or fragments.
  Query/path tokens are accepted but sensitive: no raw URLs in diagnostics.
- Certificate verification is mandatory. Redirects are not followed, including
  HTTPS-to-HTTPS, so tokens cannot silently be sent to a different destination.
- No retry, provider discovery, nested URL fetch, cookies or persistent cache.
  Explicit updates may reuse bounded memory-only HTTP validators, as described below.
- 10-second connect and 20-second total timeout, at most 2 MiB of response bytes,
  with both Content-Length and incremental chunk enforcement. Automatic compressed
  response decoding is not enabled.
- No body, credential or third-party error text is emitted through our errors/Debug.
  Transient HTTP/URL/decoding buffers are not guaranteed to be zeroized.
- `fetch_subscription` requests Complete by default; `fetch_subscription_format`
  additionally permits an explicit NodesOnly choice. Complete sends
  `User-Agent: SFA/1.12.0 network-manager-tunnel/0.1 (configuration-import-only)` and
  `Accept: application/json`; NodesOnly sends our own user agent and `text/plain`.
  The platform-client prefix is a provider format-selection compatibility request,
  not a claim that we implement sing-box or Android integration. There is exactly
  one request, with no automatic format discovery, retry or node-only fallback.

This sends one direct application HTTPS request through the user's configured
network/proxy environment, before any VPN engine exists. Tests do not contact a
real provider; provider compatibility remains separate acceptance. HTTP-only or
redirecting subscription endpoints are currently rejected rather than downgraded.

## Formats and atomicity

### Complete configurations

Complete mode requires a bounded JSON object with nonempty typed outbounds. A URI
list/base64/HTML response fails with `FullConfigurationRequired`, not success with
missing policy. JSON is decoded using serde/serde_json with a recursion bound and
recursive unknown/duplicate fields rejected. It is untrusted data, never commands.

The experimental supported subset is one selector of validated VLESS nodes,
legacy or sing-box 1.12 typed FakeIP/local/selected-real DNS roles and the exact
ordered route pipeline
in [ADR 0020](../../docs/decisions/0020-native-ipv4-source-policy.md). Every node
gets an owned native policy; any unsupported required setting rejects the whole
document with a static `UnsupportedPolicy` category. No partial nodes are extracted.
Resolver hostnames require an explicit local address resolver. Source listeners,
controller/web UI downloads and file paths are excluded with a mandatory notice;
their values are never executed/fetched/persisted. Required native policy names are
stored in NM, not logs, and credentials remain separate NM secrets. Per-profile DNS
overrides do not disable required FakeIP/interception. IPv6 is explicitly deferred.
The actual private provider and native runtime/boot acceptance remain unverified.

Typed DNS servers support `udp`, `tcp`, `tls`, `https`, `local` and `fakeip` only.
The same single-real-upstream/local-bootstrap/FakeIP role contract still applies;
this is not general DNS-rule or contemporary full-configuration compatibility.
Typed servers default to Direct when `detour` is absent, unlike legacy servers.
Resolver hostnames require a `domain_resolver` naming local bootstrap, as a string
or checked object. The same forms are accepted for `route.default_domain_resolver`
and VLESS endpoint bootstrap; all must name the same local role. Object `strategy`
may be omitted or `ipv4_only`; `disable_cache:false`, `rewrite_ttl:null` and
`client_subnet:null` are accepted without changing the existing native contract.
Active cache/TTL/ECS modifiers and other strategy preferences reject rather than
silently applying to a different query or resolver.
`route.default_domain_resolver` may replace the deprecated `outbound:any` DNS rule
only when it names that same local role. Client A/AAAA must still route to FakeIP;
`action:route` accepts the same checked query options. Other DNS actions reject.
Independent caching
must remain explicitly enabled. Mixed typed/legacy server lists or dual FakeIP
declarations reject atomically. IPv6 resolver endpoints remain unsupported.

DoH accepts typed `https` or legacy `https://` upstreams. The default port/path is
443 and `/dns-query`; an explicit origin path and verified `tls.server_name` are
preserved. Only optional `tls.enabled:true` and `tls.server_name` are supported:
custom TLS roots, insecure TLS, client certificates and other TLS options reject.
Custom nonempty headers, query/fragment tokens, credentials and redirects are not
supported. Execution uses one bounded RFC 8484 POST over verified HTTP/1.1 through
the selected route, never application environment proxies or resolver fallback.

Routing still requires the fixed sniff → DNS hijack → BitTorrent block → ordered
domain rules → private-IP Direct pipeline. Modern `action:route` and post-sniff
`action:reject` can replace legacy route/block rules without requiring a `block`
outbound. Reject methods omitted/`default`/`drop` map to closing these already
established/post-sniff flows, not a new pre-sniff TCP RST/ICMP implementation.
`no_drop:true`, reject+outbound ambiguity, destination overrides, timeout/fragment
route options, arbitrary resolve actions and reordered pipelines reject atomically.

Route `rule_set` supports domain-only inline declarations (`type:inline` or omitted)
and string/list references in the ordered domain-rule portion of that pipeline.
Headless exact/suffix alternatives, set entries, multiple referenced sets and nested
logical `or` are ORed into one native rule with the referring route's action. The
route order, first-match behavior and leading-dot subdomains-only suffix semantics
are preserved. Tags/source containers are discarded after compilation; only checked
native domain matchers persist. The shared worker and independent Direct authorizer
consume that same existing policy; a set never grants a socket or bypasses FakeIP.

Admission limits are 32 declarations, 128 total headless nodes, depth 8, 128 declared
names and 16 KiB of serialized declarations. The existing native limits still apply:
64 domain rules, 128 names after expansion (including repeated references), and a
16 KiB encoded policy. Every declaration validates, including unused sets. Empty
sets/leaves, duplicate tags, unknown references/fields and any exceeded bound reject
the whole import. Logical `and`, inversion, set-to-set references, mixed route
`rule_set`+domain match groups, IP/CIDR, regex and other headless conditions reject
rather than broadening a match. DNS rule-set matching is not implemented. Local
paths, remote URLs, binary sets and refresh/download settings are never opened,
fetched, persisted or silently ignored; they remain unsupported.

### Explicit legacy node-only mode

Plain UTF-8 newline-separated share links, or standard/URL-safe base64 with or
without padding. Blank/comment lines are ignored. Maximum 512 records; an empty,
malformed, non-URI-list, JSON/YAML/HTML or oversized document fails atomically.
A caller keeps its previous list on failure.
`parse_subscription` is this node-only decoder, not proof that a provider has no
global policies. Its caller must obtain explicit node-only consent; the GUI warns
that legacy profiles default to VPN DNS `1.1.1.1` without imported domain/LAN rules.
The separate per-profile DNS selection can override the resolver, not recover
policies missing from a URI-list response.
Each record must start with its actual URI scheme followed immediately by `://`;
an opaque YAML value containing an embedded URL is not a share link.

VLESS TCP TLS/REALITY and WebSocket TLS nodes use the shared model's strict validation. Unsupported
protocols and unsupported VLESS settings remain named records with static reasons.
They are not silently dropped or selectable as supported. Raw links are not
retained; source order is preserved. Display labels are bounded/control-free,
and unnamed nodes receive stable positional labels matching the prepared NM name.

Changing source/format or failing any load disables additions from retained nodes
until a successful explicit reload. Retention preserves read-only list/search state,
not authority to save an older configuration after policy rejection. Mode changes
are blocked while downloading or mutating NM. Existing NM profiles are not edited.

The COSMIC consumer owns multiple sources and Secret Service persistence; this library
does not own a source catalog, storage, scheduling or NM mutations. Other protocols
and broader transports remain unsupported. Add them only with their actual profile
semantics and acceptance tests, not by ignoring unknown fields.

## Advisory provider headers

Successfully admitted downloads expose `Subscription::metadata()`. Offline parsing
has absent metadata. The supported header contract is deliberately bounded:

- `subscription-userinfo`: at most 1024 bytes; semicolon-separated `upload`, `download`,
  `total`, `expire`, case-insensitive names and unsigned decimal integers. Counters
  are bytes; expiry is Unix seconds through year 9999. Missing fields remain unknown.
  Explicit zero total/expiry mean unlimited/no expiry. Duplicate/unknown fields,
  negative/floating/overflowing numbers and overflowing combined usage invalidate the
  entire usage header, not the independently admitted configuration.
- `profile-title`: at most 512 encoded bytes, plain UTF-8 or `base64:` plus standard
  padded base64; decoded display label is at most 128 bytes, without controls or
  bidi direction controls. It is only a suggested name, never a rename instruction.
- `profile-update-interval`: decimal integer hours, 1 through 720; advisory only.
  It cannot start a timer or change any source setting.

Absent, invalid and checked values are distinct. Duplicate header lines invalidate
that header rather than selecting an arbitrary value. Debug redacts all metadata;
raw rejected values are discarded. These optional hints cannot weaken required
policy validation or make a failed body acceptable. No header opens a URL or writes
storage. Metadata lives with the in-memory response, not in Secret Service or NM.

The usage field names follow the de facto
[Mihomo v1.19.0 implementation][userinfo-reference], not a standardized billing API.
Unlike that implementation, this consumer does not coerce floats or default missing
fields to zero. Provider compatibility and accuracy are not independently established.
COSMIC labels these snapshots separately from local tunnel counters; expiry never
disconnects a running VPN. Relative expiry uses the local wall clock, not a trusted
provider time source.

## Conditional explicit refresh

`fetch_subscription_update` accepts an owned optional previous `Subscription`.
Downloaded responses retain a redacted canonical URL, request format and at most
1024 bytes each of ETag/Last-Modified in memory. Raw source links are still discarded.
The same URL (including path/query) and format are required before sending a
validator. ETag takes precedence over Last-Modified; duplicate, empty, control-bearing
or oversized validators are not reused. Nothing is written to disk.
`Cache-Control: no-store` disables validator retention/reuse, without preventing
the explicit import of the admitted configuration into application memory/NM.

A 304 succeeds only when that request had a matching validator and its fully admitted
document is still present. It reuses the document and refreshes only metadata and
validators actually supplied in the 304; omitted fields retain the previous snapshot,
while malformed supplied metadata becomes explicitly invalid. An unsolicited 304,
offline parse, changed URL/format or app restart cannot authorize cached reuse.
A successful 200 replaces metadata/validators rather than merging stale hints, and
must pass all ordinary body/policy admission checks first. Failure/cancellation never
mutates the caller's retained copy or applies anything to NM. Even an unchanged
response enters COSMIC's explicit review/Apply flow; no automatic writes occur.

[userinfo-reference]: https://github.com/MetaCubeX/mihomo/blob/v1.19.0/adapter/provider/subscription_info.go

## Automated verification limits

Parser contracts use synthetic links. Private loopback HTTP tests exercise the shared
download path's redirect/status rejection, declared and chunked body limits, and a
stalled-body deadline. They use the production client policy with plaintext enabled
only in tests, environment proxies disabled, and bounded peer/client operations.
They do not verify HTTPS handshakes, certificate rejection, the connect timeout, or
the production timeout durations. No real provider is contacted.
Additional loopback contracts check metadata publication, validator-bound 304 reuse,
changed source/format refusal, Last-Modified fallback and rejection without mutating
the retained catalog. They do not establish live-provider HTTP/TLS compatibility.
Format tests additionally verify actual User-Agent/Accept headers, complete-response
rejection, refusal of node-only replies to complete requests and absence of a second
fallback request. Synthetic JSON admission tests verify no partial extraction,
bounded/duplicate/unknown rejection and sanitized errors without source mutations.

## Explicit live verification

`cargo run --locked -p nm-tunnel-subscription --example inspect` reads a source URL
from stdin until EOF (8 KiB, 20 seconds) and invokes the app's HTTPS loader/parser.
A stalled pipe cannot keep the process alive through Tokio blocking-input shutdown.
It prints progress, aggregate import counts and static rejection reasons, never source
URLs, node names, endpoints, credentials or downloaded bodies. It creates no NM
profiles and does not contact proxy endpoints. Feed sensitive input through a private
stdin channel, never argv, shell history, checked-in fixtures or shared logs.
This command is opt-in, not part of CI, and tests importing rather than connectivity.
The default requests complete configuration and rejects unsupported required
policy. Add `-- --nodes-only` only for an explicit legacy node-only inspection;
there is no automatic retry. Never pass the source URL as an argument.
