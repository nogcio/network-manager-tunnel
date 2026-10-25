# Engine stream and datagram adapters

The engine consumes a validated shared profile and one host-supplied connected TCP
socket. It uses the exact `nogcio/meow-rs` revision pinned in the workspace for VLESS,
TLS/REALITY, WebSocket and Vision. It does not launch a core or own NetworkManager,
TUN, DNS, routes, firewall policy, endpoint resolution or socket creation.

`connect_tcp` checks the approved peer address, profile port and literal profile IP,
then wraps that socket. The integration must resolve hostname endpoints and establish
their bypass policy before calling it. Every flow/reconnect must get a new explicitly
approved socket; an injected deny-only dialer prevents implicit direct fallback.
Destinations travel in VLESS, never through a local destination dialer.

Configuration preserves distinct SNI/HTTP Host/path, fingerprint, ALPN and flow fields.
The shared model rejects WebSocket ALPN offers containing `h2` before socket use;
the selected WebSocket transport implements only HTTP/1.1 Upgrade.
REALITY enables the reviewed hybrid option. The REALITY Android profile is explicitly
rejected because the fork maps it to Chrome; no silent fingerprint substitution is
allowed. Historical profiles plus the PQ overlay do not establish exact contemporary
browser fingerprint fidelity. `connect_udp` uses a destination-bound VLESS
UDP-over-TCP association over the same selected security/transport, with an injected
single-use supplied-socket dialer. There is no XUDP, native UDP dialer or packet/TUN
adapter in this package. Bound UDP carries no per-datagram source; the pinned
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
