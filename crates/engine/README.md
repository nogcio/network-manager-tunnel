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

`verify_tls_peer` performs a mandatory certificate-verified destination TLS handshake
over an owned VLESS tunnel using the pinned transport library. It creates no socket
or resolver, sends no HTTP request, and closes on completion/error/cancellation or
its ten-second deadline. The worker consumes it for CurrentNetwork DNS readiness:
direct DNS success alone cannot certify a working proxy. This proves one TCP/TLS
exchange, not UDP, host routing or leak prevention. See
[ADR 0011](../../docs/decisions/0011-profile-dns-overrides.md).

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

Explicit isolated interoperability check (not part of ordinary host checks):

```sh
python3 scripts/check_source_peer.py --peer target/research/xray-26.10.21/xray
```

The script verifies the pinned Xray binary checksum, uses a loopback-only bwrap
namespace and synthetic credentials, and fails on unavailable tools/peers. It
checks REALITY/Vision XUDP echo, oversized rejection, invalid authentication and
Unix/IP bridge cleanup. It never installs Xray or changes host networking.
