# Engine stream and datagram adapters

The engine consumes a validated shared profile and one host-supplied connected TCP
input or a fixed-peer Unix payload relay. It uses the pinned meow-rs revision for VLESS,
TLS/REALITY, WebSocket and Vision. It does not launch a core or own NetworkManager,
TUN, DNS, routes, firewall policy, endpoint resolution or socket creation.

The [shared data plane](../dataplane/README.md) consumes this package for packet/flow
dispatch, DNS and FakeIP semantics over explicit platform capabilities. Linux/NM
resource management remains in the service, not either engine-layer package.

`connect_tcp` checks the approved peer address, profile port and literal profile IP,
then wraps that owned input. The integration must resolve hostname endpoints and establish
their bypass policy before calling it. Every flow/reconnect must get a new explicitly
approved socket; an injected deny-only dialer prevents implicit direct fallback.
Destinations travel in VLESS, never through a local destination dialer.
`connect_tcp_domain` carries a checked canonical original DNS name and port instead
of an IP, with identical endpoint/ownership/deadline checks and no local resolver.
The complete-policy data plane consumes it for owned FakeIP TCP Proxy flows with
inherited DNS; explicit resolver overrides retain pre-resolution. Sniffed
HTTP Host/TLS SNI selects rules but never replaces that original wire destination.

`EndpointStream` derives peer metadata from ordinary TCP inputs. The service uses
`EndpointStream::relayed` after validating a private Unix grant: its trusted host
attests the fixed IP endpoint. That constructor cannot authenticate the remote
peer itself. Root retains marked IP sockets rather than transferring retargetable
capabilities; see [ADR 0015](../../docs/decisions/0015-root-owned-endpoint-relays.md).

Configuration preserves distinct SNI/HTTP Host/path, fingerprint, ALPN and flow fields.
The shared model rejects WebSocket ALPN offers containing `h2` before socket use;
the selected WebSocket transport implements only HTTP/1.1 Upgrade.
REALITY enables the reviewed hybrid option. The REALITY Android profile is explicitly
rejected because the fork maps it to Chrome; no silent fingerprint substitution is
allowed. Historical profiles plus the PQ overlay do not establish exact contemporary
browser fingerprint fidelity. `connect_udp` uses a destination-bound VLESS
UDP-over-TCP association over the same selected security/transport, with an injected
single-use supplied-socket dialer. Complete-policy profiles instead select the
library's CommandMux/Mux.Cool XUDP path: one stream/connection per association,
1–8,192-byte payloads, no implicit redial or ordinary-UDP fallback. There is no
native UDP dialer or packet/TUN adapter in this package. Legacy bound UDP carries
no per-datagram source; the pinned
library's absent-source sentinel is normalized without accepting unrelated sources.
`connect_udp_domain` uses the pinned library's explicit domain XUDP API and typed
packet reads/writes, preserving the original name in every Keep frame without DNS.
Domain responses require exactly the bound canonical name and port; absent sources,
IP substitutions and other domains/ports fail closed, without fallback. Peers that
return resolved IPs instead of domains are intentionally unsupported on this path.
IP XUDP accepts only the bound IP/port or absent source metadata, never a domain
projected to a sentinel. Explicit DNS overrides retain checked pre-resolution.

Each XUDP association retains an exclusive transport owner before protocol setup.
Its drop synchronously destroys the supplied underlying channel and wakes pending
read/write operations, before dropping the library association. This prevents the
pinned mux library's detached End-frame sender from retaining a stalled transport
when its outbound queue is full. Setup cancellation/failure also revokes ownership;
invalid-size rejection alone leaves a live association usable. There is no shared
session/pool revocation, new socket, timeout-based cleanup task or dependency change.
The library-wide queue behavior remains upstream; this is containment at our
exclusive-supplied-transport boundary, not a claim of fixing all mux consumers.
An in-memory regression fills the actual pinned Mux.Cool outbound queue for IP and
domain associations, cancels the pending send and requires synchronous transport
destruction without peer progress. Separate tests require both pending I/O directions
to wake/fail and release shared state. No live peer or privileged test is implied.

The setup deadline is ten seconds. Ownership transfers on entry, including errors and
cancellation. Errors/Debug are redacted and stream I/O diagnostics are normalized.
Dropping the tunnel closes the library stream. VLESS may defer its request/response;
successful setup alone is not authentication acknowledgement or VPN readiness.

The `probe` example accepts only synthetic REALITY/Vision fixtures in an explicitly
isolated loopback environment; it accepts no personal node or imported credential.
It is not a VPN executable. Public contracts cover rejection/cancellation socket
ownership; private tests cover model-to-library settings and implicit-redial denial.

Cargo.lock owns dependency resolutions; source/features, licensing and advisories
need review on updates and before supported release. Passing these tests cannot
establish NM activation,
leak prevention, fail-closed routing, DNS policy or native desktop acceptance.

`verify_peer_transport` checks the host-approved endpoint and applies the same
TLS/REALITY/WebSocket transport chain as application flows, then closes it. It
creates no socket, resolver query, VLESS destination or application health request.
Rejection, cancellation and its ten-second deadline release the owned input.
The NM worker consumes it for endpoint-only readiness/health. Success verifies the
secure peer, not VLESS UUID acceptance, DNS, forwarding or Internet reachability;
VLESS/Vision may defer authentication until real application I/O. See
[ADR 0032](../../docs/decisions/0032-destination-free-readiness.md).

## TCP hostname inspection

`inspect_tcp_hostname` uses the pinned `meow-common` HTTP/TLS parsers, with at most
8 KiB and one 300 ms deadline. It returns a canonical HTTP Host/TLS SNI plus the
exact consumed prefix. The integration must replay that prefix once before further
relay, or close the flow on rejection/cancellation. Prefixes can contain sensitive
plaintext; their Debug is redacted. Missing/unsupported names remain absent, never
inferred from a shared destination IP. The engine opens no socket for inspection.

The NM worker consumes this API for optional schema-v2 TCP rules. The supervisor,
not the engine, authorizes explicit Direct sockets. This does not add FakeIP, DNS
interception or full sing-box policy import. See
[ADR 0010](../../docs/decisions/0010-tcp-domain-routing.md).

`QuicHostname` adds bounded library-owned v1/v2 Initial decryption/reassembly for
the complete-policy consumer. Its four-datagram/8-KiB budget never modifies replay
bytes; malformed/unsupported input yields no name. It authenticates no endpoint.
Public RFC 9001 fixtures test our adapter, not upstream cryptography.
`wrap_verified_tls` wraps an owned approved transport for source DNS-over-TLS,
with mandatory verification and a ten-second deadline; it never dials.
See [ADR 0020](../../docs/decisions/0020-native-ipv4-source-policy.md).

`exchange_doh` supplies RFC 8484 HTTP/1.1 POST framing over an owned, already
certificate-verified TLS stream. Its source-DNS supervisor consumer retains socket,
bootstrap, route and certificate authority. The adapter cannot dial or resolve.
One ten-second deadline owns both Hyper's connection driver and exchange; no
detached driver, pool, redirects, retry or environment proxy exists. Only HTTP 200
with one `application/dns-message` content type, no content encoding/trailers and
1..=4096 response bytes is accepted. Incremental chunk limits apply independently
of Content-Length; errors and cancellation close the stream. The shared resolver
then validates DNS question/ID and caches only admitted answers. Synthetic HTTP
contracts do not establish a live DoH/TLS, full packet or deployed NM acceptance.

Explicit isolated interoperability check (not part of ordinary host checks):

```sh
python3 scripts/check_source_peer.py --peer target/research/xray-26.10.21/xray
```

The script verifies the pinned Xray binary checksum, uses a loopback-only bwrap
namespace and synthetic credentials, and fails on unavailable tools/peers. It
checks REALITY/Vision XUDP echo, oversized rejection, invalid authentication and
Unix/IP bridge cleanup, plus original-domain TCP echo over REALITY and Vision.
The latter requires a per-probe peer log containing the VLESS domain destination
and a 65,549-byte echo through a peer-only synthetic DNS mapping. It does not prove
the full shared packet runtime or deployed DNS behavior. No Xray installation or
host networking changes occur.

The harness also builds the shared data plane's `xudp_domain` example by default.
It exercises production `datagram::Route` with owned FakeIP, a distinct observed
name, no destination DNS/Direct authority, REALITY/Vision echo and size rejection.
Peer logs must show the original domain. `--domain-probe` can explicitly replace
that probe with a separately built candidate library probe; such a run does not
verify the shared route. Neither variant proves full packet-netstack/TUN or deployed
NetworkManager acceptance.
