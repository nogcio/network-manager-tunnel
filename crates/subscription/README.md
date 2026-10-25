# Subscription loading

Shared client library for explicit HTTPS fetching and bounded URI-list decoding.
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

This sends one direct application HTTPS request through the user's configured
network/proxy environment, before any VPN engine exists. Tests do not contact a
real provider; provider compatibility remains separate acceptance. HTTP-only or
redirecting subscription endpoints are currently rejected rather than downgraded.

## Formats and atomicity

Plain UTF-8 newline-separated share links, or standard/URL-safe base64 with or
without padding. Blank/comment lines are ignored. Maximum 512 records; an empty,
malformed, non-URI-list, JSON/YAML/HTML or oversized document fails atomically.
A caller keeps its previous list on failure.
Each record must start with its actual URI scheme followed immediately by `://`;
an opaque YAML value containing an embedded URL is not a share link.

VLESS TCP TLS/REALITY and WebSocket TLS nodes use the shared model's strict validation. Unsupported
protocols and unsupported VLESS settings remain named records with static reasons.
They are not silently dropped or selectable as supported. Raw links are not
retained; source order is preserved. Display labels are bounded/control-free,
and unnamed nodes receive stable positional labels matching the prepared NM name.

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

## Explicit live verification

`cargo run --locked -p nm-tunnel-subscription --example inspect` reads a source URL
from stdin until EOF and invokes the same HTTPS loader/parser as the app. It prints
only aggregate import counts and static rejection reasons; it never prints source
URLs, node names, endpoints, credentials or downloaded bodies. It creates no NM
profiles and does not contact proxy endpoints. Feed sensitive input through a private
stdin channel, never argv, shell history, checked-in fixtures or shared logs.
This command is opt-in, not part of CI, and tests importing rather than connectivity.
