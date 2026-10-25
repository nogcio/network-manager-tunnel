# Shared profile model

Desktop- and NetworkManager-independent editable `Draft`, validated `Profile`, static
field errors and single-link VLESS import. No I/O, DNS, subscription fetch or engine.

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
