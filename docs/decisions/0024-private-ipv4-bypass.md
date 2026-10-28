# ADR 0024: Explicit all-RFC1918 physical bypass with DNS precedence

Status: owner-approved mode, distinct from legacy connected-only LAN bypass.

## Policy and compatibility

The new `private-rfc1918` value of schema-v2 `vpn.data.lan-bypass` corresponds to
`Draft::private_lan_bypass`. All IPv4 destinations in `10.0.0.0/8`,
`172.16.0.0/12` and `192.168.0.0/16` bypass the selected VPN and its legacy hostname
rules. Existing physical routes determine the interface and gateway; no subnet
discovery, route installation or gateway guessing is added to the supervisor.
This includes networks reachable behind a router, such as `10.2.2.0/24`, without
assuming the host has an address on that network. It does not guarantee that the
router actually forwards them. ICMP and other local IP protocols stay physical.

CGNAT, link-local, multicast, loopback and benchmarking ranges are not added to
this exception. IPv6 remains blocked. FakeIP never becomes a private real target.
Complete source policy, legacy hostname rules and connected-only mode cannot
combine with this mode; conflicting rule precedence rejects instead of dropping rules.
The complete source pipeline retains its separate ordered non-public semantics.

Existing `connected-rfc1918` profiles keep their original behavior, not a silent
widening on update. The COSMIC new-profile/replacement checkbox explicitly selects
the broad mode; saved details distinguish both modes. An owner-authorized change
to an existing profile explicitly changes the mode through NM, preserving other
settings/secrets. Reconnect is required to change an existing activation.

## Routes, firewall and DNS

NM receives the bounded IPv4 complement of the three private ranges. Private
routes, including more-specific physical DNS/gateway `/32` routes, remain physical.
The guard grants those RFC1918 destinations without granting public or IPv6
physical traffic. This is deliberately broader than a selected-uplink exception.

With interception enabled, private UDP/TCP port 53 is first output-DNATed to
`198.18.0.2:53`, whose normal NM route is the TUN. The kernel's nftables/conntrack
own destination/reply translation; no protocol parser or physical DNS fallback is
added. Root-marked endpoint/bootstrap/resolver sockets bypass the rewrite to avoid
recursion. The existing worker/resolver applies FakeIP and selected DNS policy.

Linux can retain the original interface throughout OUTPUT, rerouting only after
that hook. The output filter accepts only conntrack-DNATed TCP/UDP port 53 to the
fixed internal resolver. A postrouting rule rejects that translated destination
unless its final interface is `nmtun0`. The separate FakeIP guard also checks
postrouting, rejecting reserved-range physical traffic, including marked sockets.
NAT, the narrow exception and final-egress check share the same owned transaction;
unsupported kernel features fail activation, not DNS policy. Clean teardown removes
the owned NAT/filter tables under ADR 0022. Existing DNS sockets/conntrack mappings
and application caches may need retry/expiry; unrelated state is never flushed.

FakeIP names resolving to private real IPs still enter the worker initially. They
use bounded Unix TCP/UDP relays, not VLESS to a private target. Root checks the
explicit mode and private non-DNS destination before creating marked sockets that
follow normal routes. Endpoint/bootstrap sockets retain their selected-uplink
binding. No IP descriptor is exported to the worker.

## Verification

Model/schema/client tests distinguish modes, reject conflicts/v1 downgrade, and
preserve rejected input. Route contracts cover private, public, CGNAT, link-local
and FakeIP boundaries. Explicit isolated kernel-adapter verification:

```sh
cargo test --locked -p nm-tunnel-service network::tests::private_dns_redirect_and_physical_exception_are_installed_in_one_owned_table
python3 scripts/check_private_lan.py --rules target/private-lan/guard.nft
```

The test uses nested user/network/PID namespaces, synthetic veth peers, gateway
host routes, a routed private network and echo markers, not external traffic or a
handwritten DNS implementation. It checks private reachability, TCP/UDP DNS/reply
translation, marked bootstrap exclusion, public/IPv6/FakeIP rejection, bad internal
DNS egress rejection and new-socket behavior after teardown. Missing tools or
capabilities fail rather than skip. Host networking is never changed. This is not
NM precedence/teardown, full source execution or native desktop acceptance.
