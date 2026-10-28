# sing-box client-policy compatibility

NetworkManager Tunnel translates the bounded source contract in
[ADR 0020](../decisions/0020-native-ipv4-source-policy.md), not arbitrary sing-box
configuration. Configuration admission, intended route decisions, wire behavior
and privileged deployment are separate acceptance categories.

## Complete-policy domain precedence

The behavioral reference is sing-box **v1.12.0**, matching the existing supported
legacy source shape. This is not a claim of compatibility with current 1.14 schemas.
Versioned source references:

- [FakeIP recovery, sniffing and route execution][route-reference]
- [Sniffed domain before destination FQDN in domain matching][domain-reference]
- [VLESS destination forwarding][vless-reference]

Complete TCP rules now prefer the library-observed HTTP Host/TLS SNI over the owned
FakeIP name. Complete UDP rules use the same precedence for a supplied QUIC-observed
name. Without sniffed metadata they retain the original name. The destination name
and rule name are distinct: when destination DNS is required it queries the original
identity, not the sniffed name. Unknown FakeIP never becomes usable because of sniffing.
Legacy profiles retain their previous identity-first behavior.

Previously the data plane always preferred the FakeIP name and could choose Proxy
where a sniffed-name Block rule should win. A maintained isolated comparison against
the pinned peer reproduced 12 differing decisions out of 21 TCP cases; after the
correction all 21 decisions matched. The cases cross the original Block/Direct/Proxy
name with HTTP Host and library-generated TLS ClientHello SNI, plus no-name fallback.
Ordinary public contracts additionally cover TCP/UDP dispatch, original-name DNS,
ownership refusal, invalid metadata, inbound closure and no alternate-outbound retry.

The independent Direct authorizer is unchanged. A separate regression verifies that
a Direct rule selected by a name does not authorize an unrelated destination IP:
membership in the selected resolver's answer remains necessary. This extra authority
check can refuse flows accepted by sing-box and is not counted as full parity.

## Reproduce the bounded comparison

The optional peer is a test tool only, never a production backend, dependency or
shipped executable. Download the upstream Linux amd64 v1.12.0 archive manually:

<https://github.com/SagerNet/sing-box/releases/download/v1.12.0/sing-box-1.12.0-linux-amd64.tar.gz>

Expected archive SHA-256:
`f59b1253ae0143997cb46915af30d14a33431dcbd7e39edacfcde8d73050faaf`.
The script verifies the extracted binary SHA-256:
`84b23a2304a6c4efa41dc027a78b7226a94ef6c63566b56a5a2721bdfe473446`.
It does not download, install or activate anything automatically.

```sh
python3 scripts/check_route_semantics.py --peer target/research/sing-box-1.12.0/sing-box
```

Requires `cargo`, `timeout`, Python with standard-library TLS, and rootless `bwrap`.
The test builds a project-owned synthetic probe, then starts the pinned peer in a
loopback-only user/network/PID namespace. It creates no kernel TUN, host routes,
firewall rules or NM profiles and uses only published synthetic credentials/names.
All peers/probes have deadlines; missing tools, peer evidence or readiness fail,
not skip. Logs and machine-readable results remain under `target/route-semantics/`.

The peer receives FakeIP DNS and SOCKS flows; HTTP/SNI bytes follow the successful
SOCKS handshake. Classification evidence must belong to the matching connection ID
and explicitly show the supplied sniffed name. The project probe runs the shared TCP
dispatcher with synthetic capabilities whose outbound methods deliberately refuse.
The comparison observes **intended route decisions**, not successful Direct/VLESS
connections. UDP's supplied-name precedence has ordinary contracts, not a real-QUIC
differential peer comparison. Neither side proves TUN enforcement or packet isolation.

## Remaining semantic and format gaps

- Complete FakeIP TCP/XUDP Proxy with inherited DNS preserves the original FQDN
  for remote resolution;
  only an explicit Direct domain rule performs selected-resolver DNS locally.
  Unresolved FQDNs do not match IP-only rules. Explicit resolver overrides preserve
  the user's DNS choice by retaining pre-resolution. Legacy bound UDP still pre-resolves.
  Domain XUDP uses the pinned library's typed per-packet API. Responses must preserve
  the exact original domain/port: peers returning IP or absent sources are deliberately
  rejected, not silently relabeled. This is stricter than general sing-box behavior.
- Direct requires the independent DNS membership check described above. Do not
  remove it to make a comparative test pass.
- `local` maps to the selected NM uplink's plain IPv4 DNS, not every system resolver
  feature or split-DNS arrangement. IPv6 remains explicitly blocked.
- Import still requires one selector, checked local/FakeIP/one-real-upstream DNS
  roles and a fixed ordered rule pipeline. Typed sing-box v1.12 DNS servers and
  bounded HTTP/1.1 DoH are implemented; this does not accept all modern configurations.
  Resolver string/object forms preserve the local bootstrap role; only `ipv4_only`
  and neutral cache/TTL/ECS query options are admitted. Post-sniff `reject` maps to
  closing the flow, without requiring a legacy Block outbound. Pre-sniff RST/ICMP
  semantics and `no_drop:true` are not implemented or silently approximated.
  General DNS actions/graphs, DoH headers/query tokens/custom TLS roots, general
  routing actions, broader transports and outbound graphs still reject. Route
  inline domain/suffix sets with logical OR compile into existing native ordered
  matchers, with bounded declaration/expansion budgets and no new Direct authority.
  AND/inversion, mixed set+domain route groups, IP/CIDR, regex, local/remote/binary
  sets and DNS rule-set matching remain unsupported, not silently discarded.
- These comparisons do not validate deployed DNS/FakeIP guards, native NM/Polkit,
  arbitrary providers, contemporary browser fingerprints or the full shared packet
  runtime. [Production security acceptance](../security-review.md) remains incomplete.

## TCP original-domain wire check

`connect_tcp_domain` validates canonical names and nonzero ports before transport
I/O, retains supplied-endpoint checks and uses library-owned VLESS encoding without
a local resolver. Shared TCP dispatch selects it only after durable FakeIP ownership
and a Proxy decision with inherited DNS. A Block decision never requests destination
DNS or an outbound;
Direct still resolves the original name and passes the independent Host checks.
No imported profile schema or persisted FakeIP identity changes.

The [engine peer check](../../crates/engine/README.md) exercises REALITY and Vision
TCP-domain echo through a checksum-pinned Xray test peer. Its `echo.fixture.invalid`
mapping exists only in the peer configuration. Per-mode peer logs must show the
original domain received inside VLESS, and the TCP echo must account for all 65,549
payload bytes. This is engine wire evidence, not TUN/shared-packet-runtime acceptance.
The sing-box route matrix additionally requires zero project destination DNS queries
for Block/Proxy and one for Direct. Ordinary contracts cover invalid names/ports,
endpoint mismatch, cancellation, input closure and no fallback.

The same harness builds a shared `datagram::Route` domain-XUDP probe by default,
checks REALITY/Vision 1/1400/8192-byte echo and continued traffic after invalid size
rejection, forbids destination DNS/Direct calls, and requires peer domain evidence.
The original FakeIP name differs from the supplied observed rule name. This tests
the production route and engine, not yet the full packet-netstack/TUN path.

[route-reference]: https://github.com/SagerNet/sing-box/blob/v1.12.0/route/route.go
[domain-reference]: https://github.com/SagerNet/sing-box/blob/v1.12.0/route/rule/rule_item_domain.go
[vless-reference]: https://github.com/SagerNet/sing-box/blob/v1.12.0/protocol/vless/outbound.go
