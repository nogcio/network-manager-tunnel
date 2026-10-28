# ADR 0012: Explicit connected RFC1918 LAN bypass

Status: experimental implementation; native/VM route and packet acceptance pending.
Date: 2026-10-26.

This ADR describes standalone LAN bypass. Combining it with DNS interception uses
the more restrictive TCP/UDP relays in [ADR 0014](0014-intercepted-lan-relays.md).

## Scope

A new-profile option permits directly connected RFC1918 IPv4 subnets of the selected
NM uplink to bypass the VPN. It is off by default, stored as schema-v2
`vpn.data.lan-bypass=connected-rfc1918`. Other values reject before privileged setup.
No interface name, subnet or DHCP snapshot is persisted. Existing profiles and the
active connection are not edited. Saved-profile details show the requested mode.

This is an explicit exception to VPN and hostname routing for those destinations,
including local DNS and non-TCP/UDP traffic. It is **not** a translation of a foreign
`ip_is_private` rule: it excludes CGNAT, link-local, multicast, non-connected private
networks and all IPv6. Complete configurations requiring broader matching remain
rejected, not approximated. Selection never bypasses failed subscription admission.

## Activation and ownership

After full model validation, read at most sixteen IPv4 address/prefix entries from
the selected NM device's `Ip4Config.AddressData`. Only entire RFC1918 prefixes are
eligible. A private address with a prefix covering public destinations rejects;
invalid prefix/type or no eligible subnet also rejects. All planning completes
before firewall/TUN allocation, leaving existing resources unchanged on rejection.
Public addresses add no exception. Interface names are bounded and checked before
generating nft input; loopback and our TUN cannot be selected as uplinks.

The existing guard gains only `oifname SELECTED ip daddr { CONNECTED_PREFIXES }`
acceptance. IPv6 blocking precedes it; there is no all-interface private-address
allowance or generic Direct socket capability. Existing marked upstream sockets
and TUN allowance remain unchanged. Guard replacement stays a single nft transaction.
On unexpected failure the guard, including explicitly authorized LAN exceptions,
remains; public output stays blocked. Clean disconnect removes it as before.
There is no automatic authorization of a replacement uplink: reconnect is required.

NM still owns routes. The VPN reports `never-default=true` and the disjoint IPv4
CIDR complement of those LAN prefixes through standard `Ip4Config.routes` (`aau`:
network-order destination, prefix, zero next-hop, unused metric). Existing uplink
connected routes handle LAN; all other destinations, including internal DNS/FakeIP
space, are covered by VPN routes. No `ip route`, netlink route writer or competing
route manager is introduced. The guard prevents an unrelated more-specific physical
route from turning this into public bypass; an unusable route fails rather than
opening an unmarked physical fallback. Legacy profiles keep normal default routing.
Generic user-supplied NM routes/never-default overrides remain rejected.

## Dependencies and references

Route summarization and aggregation reuse crates.io ipnet 2.12.2 (`std`, no default
features), already locked, MIT OR Apache-2.0. This is address-set planning, not a
protocol parser. No foreign source code is copied. Contract references inspected:

- Installed libnm 1.58.1 `nm-vpn-dbus-interface.h`: routes and never-default keys.
- [NM 1.58.0 VPN configuration consumer](https://github.com/NetworkManager/NetworkManager/blob/1.58.0/src/core/vpn/nm-vpn-connection.c):
  `aau` IPv4 routes, four-element layout, route merging and never-default handling.

## Verification and gaps

Pure planning tests check excluded boundaries, exact remaining address cardinality,
protected/public coverage, interface-scoped guard output and rejection without
mutation. Schema/client/UI tests check explicit v2 storage, unknown-scope rejection,
metadata observation, default-off and source-preserving creation-only controls.
Ordinary checks do not run nft, activate NM or change host routes/DNS.

Live NM application, DNS with never-default, route removal, packet capture for
public/IPv6 fail-closed behavior and uplink loss still require authorized disposable
VM acceptance. Building and unit tests alone do not establish a working LAN bypass.
FakeIP, full private-IP subscription matching and ordered full-policy translation
remain separate work; this component is not authorization for partial installation.
