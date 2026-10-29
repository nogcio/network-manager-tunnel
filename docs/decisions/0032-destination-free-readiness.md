# ADR 0032: Destination-free readiness and endpoint health

Status: owner-approved; implemented experimentally. This contract owns readiness
for all supported profiles, including CurrentNetwork and complete source policy.

## Decision

Activation and periodic health checks verify only the configured VPN endpoint's
secure transport. They do not resolve a control domain, request an application
destination, query a resolver to test Internet access, or depend on a third-party
website. Endpoint hostname bootstrap remains necessary traffic to the selected NM
uplink resolver; TLS SNI, REALITY identity and WebSocket Host/path come from the
validated profile. User/application traffic still uses its admitted VPN/DNS policy.

The engine's `verify_peer_transport` consumes the host-approved connected input,
checks the peer against the profile, applies the same TLS/REALITY and optional
WebSocket layers as application flows, and closes the input on completion. It
sends no VLESS destination or application payload. Ownership transfers on entry;
rejection, cancellation and the single ten-second deadline release that input.
No dialer, destination authority, insecure TLS mode or fallback is added. This
reuses the existing pinned meow transport chain and features, with no dependency
change. The real consumer is the NM worker's readiness/health path.

For FakeIP profiles, the worker also verifies durable local allocation/reverse
ownership for a reserved `.invalid` name through the existing private broker. That
check never queries an upstream resolver. Existing journal entries/identities are
preserved; no migration, reset or recycling follows from changing readiness.

## Meaning of connected

Readiness means the secure peer transport and local data-plane prerequisites are
ready for NM activation. It does **not** acknowledge VLESS credential acceptance,
the selected resolver's availability, forwarding to a destination, or Internet
reachability. VLESS and Vision can defer authentication/request handling until
actual application I/O. A bad UUID can therefore reach NM Connected and still
reject application flows. The implementation must not label a transport handshake
as VLESS authentication success.

Real DNS/application requests independently retain all certificate, DNS binding,
FakeIP ownership, Direct authorization and protocol validation. A failed request
closes/refuses its flow without changing resolver/outbound or opening a physical
fallback. An unavailable resolver cannot be replaced just to make activation pass.
Positive DNS/proxy interoperability requires actual traffic evidence, not readiness.

## Runtime ownership

The endpoint monitor retains the existing nonoverlapping twenty-second normal
interval, fifteen-second total probe bound and forty/sixty-second failure backoff.
Each check owns a fresh endpoint transport, not a persistent application session.
Endpoint failures retain the current TUN/routes/guards and do not retry application
payloads or reactivate NM. An ambiguous/cancelled broker exchange remains fatal.
The independent recovery lease, teardown barrier, NM control ownership and terminal
return to ordinary networking without VPN are unchanged.

Health success describes only that endpoint exchange. `running` and native NM
Connected are not Internet-access or protection certificates. There is no background
connectivity URL, optional reachability service or new UI reachability claim.

## Verification boundaries

Owner tests reject peer mismatch before I/O and verify cancellation/deadline EOF.
Worker tests require endpoint-only broker admission across resolver modes, with no
resolver/destination request after refusal. The offline VM suite observes initial
activation and a fresh periodic endpoint handshake without any DNS/application-peer
events, while preserving active protection. Separate traffic scenarios exercise
real credentials, DNS and source-policy forwarding/refusal. No public CA injection,
certificate-verification override or external connectivity is required by these
readiness tests. This is not complete TLS/DoH interoperability or production security
acceptance; those have their own evidence requirements.
