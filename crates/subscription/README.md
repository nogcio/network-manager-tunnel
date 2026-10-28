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
legacy FakeIP/local/selected-real DNS roles and the exact ordered route pipeline
in [ADR 0020](../../docs/decisions/0020-native-ipv4-source-policy.md). Every node
gets an owned native policy; any unsupported required setting rejects the whole
document with a static `UnsupportedPolicy` category. No partial nodes are extracted.
Resolver hostnames require an explicit local address resolver. Source listeners,
controller/web UI downloads and file paths are excluded with a mandatory notice;
their values are never executed/fetched/persisted. Required native policy names are
stored in NM, not logs, and credentials remain separate NM secrets. Per-profile DNS
overrides do not disable required FakeIP/interception. IPv6 is explicitly deferred.
The actual private provider and native runtime/boot acceptance remain unverified.

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

Persistent subscriptions, multiple sources, provider metadata, subscription-userinfo,
other protocols and broader transports are not implemented. Add them only with
their actual profile semantics and acceptance tests, not by ignoring unknown fields.

## Automated verification limits

Parser contracts use synthetic links. Private loopback HTTP tests exercise the shared
download path's redirect/status rejection, declared and chunked body limits, and a
stalled-body deadline. They use the production client policy with plaintext enabled
only in tests, environment proxies disabled, and bounded peer/client operations.
They do not verify HTTPS handshakes, certificate rejection, the connect timeout, or
the production timeout durations. No real provider is contacted.
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
