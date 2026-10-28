# ADR 0010: Explicit TCP hostname routing and bounded direct authority

Status: implemented experimentally for TCP; full subscription policies pending.
Date: 2026-10-26.

## Context and references

Share links describe nodes, not a subscription's global DNS/routing policy. A server
may select a different response using the client identity. Receiving a URI list does
not establish that the provider has no rules. Full-configuration import must not
extract nodes and silently discard unsupported policies.

The behavioral reference is sing-box 1.12.0:

- [Route rule semantics](https://github.com/SagerNet/sing-box/blob/v1.12.0/docs/configuration/route/rule.md).
- [Metadata recovery and ordered rule evaluation](https://github.com/SagerNet/sing-box/blob/v1.12.0/route/route.go).
- [Domain matcher inputs](https://github.com/SagerNet/sing-box/blob/v1.12.0/route/rule/rule_item_domain.go).
- [FakeIP DNS transport](https://github.com/SagerNet/sing-box/blob/v1.12.0/dns/transport/fakeip/fakeip.go).

These references distinguish a name recovered from FakeIP, reverse DNS metadata or
protocol inspection from a literal destination IP. They are research references,
not imported source or a new backend. sing-box is GPL-3.0-or-later with an additional
name/association restriction; no source is copied into this workspace. HTTP/TLS
inspection reuses the already pinned `meow-common` parsers.

## Decision

- Add an explicit **TCP-only** policy, not an opaque sing-box configuration. The
  checked model has ordered exact/suffix hostname rules and `proxy`, `direct`,
  `block` actions. Alternatives in a rule are ORed; the first match wins. A suffix
  `example.test` includes the apex and subdomains; `.example.test` includes only
  subdomains. Normalize ASCII case/root dots, enforce label boundaries, and reject
  malformed names, IP literals, unknown fields/actions/versions and excessive input.
- Use NM schema v2 for checked policy. Schema v1 must not carry this key. V2 must
  carry TCP rules and/or the explicit DNS override added by
  [ADR 0011](0011-profile-dns-overrides.md). Older implementations reject v2 rather
  than dropping policy.
  Legacy v1 profiles retain their existing behavior and are not migrated or edited.
- Inspect client TCP bytes before socket admission, using the library's HTTP Host
  and TLS SNI support. Bound this to 8 KiB and one 300 ms deadline. Replay consumed
  bytes exactly once before further relay; cancellation closes the owned flow.
  Unknown/absent names have no matching rule and remain proxied. No DNS reverse
  guess, HTTP/TLS implementation, MITM, QUIC parser or implicit direct fallback.
- A blocked flow closes before requesting any socket. `proxy` uses the existing
  endpoint-only broker path. A `direct` flow submits the observed name and original
  IPv4 socket destination over the private FD channel. A rule is not an application
  identity or authentication boundary; HTTP Host/SNI can be application-controlled.
- The root supervisor independently rechecks its own policy before DNS/socket work.
  It permits only Direct names, nonzero ports and permitted unicast IPv4 addresses.
  Loopback, LAN, link-local, shared CGNAT, benchmark/FakeIP and non-unicast addresses
  are denied. Hostname rules are not authorization for local-network access.
- Re-resolve an allowed Direct name through the selected NM uplink resolver, on a
  marked/uplink-bound socket. Bind the DNS question and A/CNAME answer chain to the
  requested name, and require the requested IP to be among these answers. This
  deliberately exposes the allowed Direct name to that resolver. It does not use
  the proxied resolver or claim confidential DNS for Direct traffic. DNS/CDN answer
  differences can deny a legitimate connection rather than expanding authority.
- Keep the connected marked IP socket in root and return only a Unix payload
  channel for the verified destination; see [ADR 0015](0015-root-owned-endpoint-relays.md).
  The worker checks descriptor family/type. Explicit refusal does not poison the
  channel; malformed replies or uncertain cancellation do. Never retry a rejected
  Direct flow through Proxy or vice versa.
- Keep NM in charge of ordinary routes and DNS. Do not add destination routes or
  broad firewall exceptions; only supervisor-created marked sockets bypass TUN.

## Bounds and evidence

The policy is at most 16 KiB, 64 rules and 128 names. Direct request frames are at
most 512 bytes and must arrive within five seconds. Direct DNS/socket setup uses
the existing five-second operation deadlines; the shared 64-socket/second budget
and worker flow/setup limits still apply. Rejecting a flow allocates no privileged
socket or firewall exception. No domains, payloads or third-party errors are logged.

Model, engine, private broker, worker and schema tests cover ordering, label
boundaries, normalization, budgets, fragmented-byte ownership, controlled deadlines,
block-before-socket, prefix replay, refusal without fallback, revalidation, DNS
answer-chain binding, peer mismatch and cancellation cleanup. Ordinary tests use
only synthetic data and loopback/private buses, not host network changes.

This is not a completed sing-box adapter. FakeIP, DNS hijacking, UDP/QUIC hostname
metadata, local-network rules, external rule sets, protocol matching and exact full
configuration execution remain unsupported. The frontend now requests the complete
configuration by default and blocks unsupported policy before node extraction. An
explicit warned legacy node-only mode exists, never as an automatic fallback.
Source/format changes or failed loads invalidate Add authority over retained nodes.
There is no automatic attachment of these rules to subscriptions
or editing of existing profiles. Real NM/direct-routing, DNS leakage, guard recovery,
and teardown require separately authorized disposable-VM acceptance before use.
