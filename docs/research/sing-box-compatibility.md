# sing-box client-policy compatibility

NetworkManager Tunnel translates the bounded source contract in
[ADR 0020](../decisions/0020-native-ipv4-source-policy.md), not arbitrary sing-box
configuration. Configuration admission, intended route decisions, wire behavior
and privileged deployment are separate acceptance categories.

## Current stable feature comparison: 1.14.4

As of 2026-10-29, GitHub identifies [v1.14.4][stable-release], published on
2026-10-24, as the latest stable release. The latest listed prerelease is
[v1.15.0-alpha.13][preview-release], not the stable compatibility target. This is
a source/documentation assessment of Linux client functionality, not new runtime
acceptance or a claim that the existing 1.12 peer comparison covers 1.14.4.
Build tags and platform restrictions still apply to sing-box features.

| Capability in sing-box 1.14.4 | NetworkManager Tunnel status |
| --- | --- |
| VLESS secure stream transport | TCP TLS/REALITY, optional Vision, and WS TLS without Vision; not every TLS/transport option |
| V2Ray HTTP, WS, QUIC, gRPC, HTTPUpgrade transports | Only the checked TCP/WS combinations; no general HTTP/gRPC/QUIC/HTTPUpgrade transport support |
| VLESS UDP encoding selection | Library XUDP only; no general choice of plain UDP or `packetaddr` |
| Shared stream multiplexing (`smux`, `yamux`, `h2mux`), padding, TCP Brutal | Not exposed/implemented; domain XUDP is not equivalent to shared stream multiplexing |
| TLS ECH, certificate pinning/client certificates, configurable TLS versions/curves, fragmentation/spoofing options | Not represented by the admitted profile contract; existing fingerprint labels are not full TLS-option parity |
| General route conditions and logical AND/OR/inversion | Source v2 adds bounded exact/suffix domains, destination IPv4 CIDR/ports and logical AND/OR/inversion; no general process/user/device/source/network matcher |
| Inline, local and remote source/binary rule-sets | Bounded inline destination predicates, including CIDR/ports/logical conditions and shape-dependent outer composition; no file/download/binary-set lifecycle |
| DNS server selection and response policy | Source v3 adds bounded ordered exact/suffix real-DNS selection, explicit endpoint Direct/Proxy or NM uplink DNS; no general response-policy graph |
| DNS `evaluate`, `respond`, `match_response`, `race`, `speculative` | Not implemented |
| DNS UDP/TCP/TLS/HTTPS, QUIC/HTTP3, hosts, mDNS and resolved integration | Bounded UDP/TCP/DoT/HTTP1.1 DoH; no DoQ/HTTP3/hosts/mDNS/general resolved split-DNS integration |
| FakeIP and dual-stack DNS/TUN | Durable bounded IPv4 FakeIP with empty AAAA; IPv6 endpoints/payloads are blocked, not supported |
| TUN routing, selective capture and UDP NAT policy | NM-owned routes/DNS and bounded TCP/UDP worker; no general sing-box TUN stack/capture/NAT option surface |
| ICMP routing | Not implemented; sing-box routes ICMP to eligible Direct/WireGuard/Tailscale paths, not arbitrary ICMP through VLESS |
| Selector and URLTest outbound groups | Explicit per-node NM profiles; no URLTest, automatic server selection or arbitrary chained outbound graphs |
| Other proxy protocols and VPN endpoints | VLESS only; no Shadowsocks/VMess/Trojan/Hysteria2/TUIC/AnyTLS or WireGuard/Tailscale/OpenVPN/OpenConnect backend |
| Foreign listeners, controllers, web UI and server roles | Deliberately outside the NM client product boundary, not implicit implementation commitments |

The destination-predicate row includes the experimental source-v2 implementation
described in [ADR 0020][destination-predicates].
It has local model/import/TCP/UDP/authority regressions, not a new differential
comparison against a 1.14.4 peer or deployed VM acceptance. The old 40-case VM
result must not be counted as verification of these new predicates.

The transport and TLS rows describe missing configurable behavior, not an assertion
that every combination in sing-box is valid or desirable. In particular, insecure
verification modes are not a parity target. Existing strict Direct DNS membership
and domain-XUDP response identity checks remain intentional behavioral differences.

### Important differences from the old reference

- Legacy DNS server formats were removed in 1.14.0. The old special Block/DNS
  outbounds and legacy inbound sniff/domain-strategy fields were removed in 1.13.0.
  Old names can remain in documentation examples/indexes; the versioned
  [deprecation/migration list][stable-deprecations] governs these removals.
  Our ability to import a legacy source does not establish modern schema parity.
- 1.14 adds DNS response matching and `evaluate`/`respond`, DNS racing/speculation,
  ECS/DNSSEC query conditions and preferred-domain routing, plus source MAC/hostname
  conditions. Some conditions are platform-specific or require neighbor discovery;
  Android-only conditions are not Linux-client backlog by default.
- 1.14 remote rule-sets can use explicit HTTP clients and initial local content.
  Our top-level importer does not accept `http_clients`, `endpoints`, `services` or
  `certificate` sections. These cannot be admitted by ignoring their semantics.
- sing-box TUN self-managed routing/redirect settings are not APIs to reproduce
  literally: NM must remain our profile, normal-route and DNS owner. Functional
  equivalents need an explicit mapping rather than a second network manager.

### Recommended VPN implementation order

1. Define a bounded 1.14.4 client-source target and map each admitted field to model,
   runtime and NM ownership. Keep the existing legacy import contract explicit.
2. Bounded destination predicates and reusable inline sets are implemented in
   source v2, including conditional outer-group composition. Local/remote assets
   need bounded update,
   trust and persistence design; imports must not execute arbitrary file paths.
3. Bounded per-domain real-resolver selection is implemented experimentally in
   source v3 with independent Direct authority; response filtering and parallel DNS
   racing remain unsupported. A new resolver
   path is a network-policy decision, not a harmless reachability optimization.
4. Add additional VLESS transports/TLS options only for a concrete consumer using
   reviewed protocol libraries. General multiplexing is a separate capability.

This order is a proposal, not approval to expand scope, fetch provider data,
change protections, install packages or publish upstream patches. No new peer,
VM workload or external VPN traffic was run for this feature assessment. Full
sing-box parity and a percentage-complete estimate are not claimed.

[stable-release]: https://github.com/SagerNet/sing-box/releases/tag/v1.14.4
[destination-predicates]: ../decisions/0020-native-ipv4-source-policy.md#destination-predicates-in-native-source-policy-v2
[preview-release]: https://github.com/SagerNet/sing-box/releases/tag/v1.15.0-alpha.13
[stable-deprecations]: https://github.com/SagerNet/sing-box/blob/v1.14.4/docs/deprecated.md
[stable-vless]: https://github.com/SagerNet/sing-box/blob/v1.14.4/docs/configuration/outbound/vless.md
[stable-transports]: https://github.com/SagerNet/sing-box/blob/v1.14.4/docs/configuration/shared/v2ray-transport.md
[stable-multiplex]: https://github.com/SagerNet/sing-box/blob/v1.14.4/docs/configuration/shared/multiplex.md
[stable-tls]: https://github.com/SagerNet/sing-box/blob/v1.14.4/docs/configuration/shared/tls.md
[stable-route]: https://github.com/SagerNet/sing-box/blob/v1.14.4/docs/configuration/route/rule.md
[stable-actions]: https://github.com/SagerNet/sing-box/blob/v1.14.4/docs/configuration/route/rule_action.md
[stable-dns]: https://github.com/SagerNet/sing-box/blob/v1.14.4/docs/configuration/dns/rule_action.md
[stable-dns-servers]: https://github.com/SagerNet/sing-box/blob/v1.14.4/docs/configuration/dns/server/index.md
[stable-rule-sets]: https://github.com/SagerNet/sing-box/blob/v1.14.4/docs/configuration/rule-set/index.md

Versioned references: [VLESS][stable-vless], [transports][stable-transports],
[multiplexing][stable-multiplex], [TLS][stable-tls], [route rules][stable-route],
[route actions][stable-actions], [DNS actions][stable-dns],
[DNS servers][stable-dns-servers], [rule-sets][stable-rule-sets].

## Complete-policy domain precedence

The behavioral reference is sing-box **v1.12.0**, matching the existing supported
legacy source shape. It remains the runtime comparison reference, separately from
the 1.14.4 feature assessment above; no 1.14.4 behavioral equivalence is implied.
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

- Complete source-v1/v2 FakeIP TCP/XUDP Proxy with inherited DNS preserves the original FQDN
  for remote resolution;
  only an explicit Direct domain rule performs selected-resolver DNS locally.
  Unresolved FQDNs do not match IP-only rules. Explicit resolver overrides preserve
  the user's DNS choice by retaining pre-resolution. Legacy bound UDP still pre-resolves.
  Source v3 with explicit DNS rules instead pre-resolves original owned names through
  the selected resolver, including Proxy, and sends real-IP VLESS destinations.
  Domain XUDP uses the pinned library's typed per-packet API. Responses must preserve
  the exact original domain/port: peers returning IP or absent sources are deliberately
  rejected, not silently relabeled. This is stricter than general sing-box behavior.
- Direct requires the independent DNS membership check described above. Do not
  remove it to make a comparative test pass.
- `local` maps to the selected NM uplink's plain IPv4 DNS, not every system resolver
  feature or split-DNS arrangement. IPv6 remains explicitly blocked.
- Import still requires one selector, checked local/FakeIP/default-real-upstream DNS
  roles and a fixed ordered rule pipeline. Typed sing-box v1.12 DNS servers and
  bounded HTTP/1.1 DoH are implemented; this does not accept all modern configurations.
  Resolver string/object forms preserve the local bootstrap role; only `ipv4_only`
  and neutral cache/TTL/ECS query options are admitted. Post-sniff `reject` maps to
  closing the flow, without requiring a legacy Block outbound. Pre-sniff RST/ICMP
  semantics and `no_drop:true` are not implemented or silently approximated.
  Ordered exact/suffix real-DNS rules may follow mandatory bootstrap/client-FakeIP
  roles; no per-domain FakeIP suppression or general DNS condition tree is admitted.
  General DNS actions/graphs, DoH headers/query tokens/custom TLS roots, general
  routing actions, broader transports and outbound graphs still reject. Route
  inline destination sets compile into existing native ordered predicates, with
  bounded declaration/expansion budgets and no new Direct authority. Their grouped
  composition distinguishes a single default entry from multi-entry/logical/inverted
  sets and keeps referenced tags independent. Recursive references, source-address
  conditions/remapping, regex, local/remote/binary sets and DNS rule-set matching
  remain unsupported, not silently discarded.
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
