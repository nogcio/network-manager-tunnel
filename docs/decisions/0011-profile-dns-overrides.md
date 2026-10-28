# ADR 0011: Per-profile upstream DNS overrides and bounded uplink forwarding

Status: experimental for new profiles; FakeIP/full-policy bypass pending.
Date: 2026-10-26.

## Decision and scope

Keep a profile's resolver override separate from source routing policy. Choosing
another upstream must never delete domain rules, disable FakeIP silently or turn
an unsupported full configuration into a node-only import. Full configuration
execution remains rejected until all required semantics can be preserved.

The checked model exposes three choices:

- `Inherit`: no override. Admitted source policy will supply the upstream; existing
  URI-only profiles have the documented legacy `1.1.1.1` VPN default. A URI list
  does not establish the provider's global DNS policy.
- `CurrentNetwork`: use the first usable IPv4 DNS server from the selected primary
  NM uplink's `IP4Config.NameserverData`, read before activation changes DNS. Store
  only the mode, not a stale DHCP address. This is explicitly **plain UDP/TCP port
  53 outside the VPN**, not importing an OS stub's DoT, IPv6, search-domain or
  per-domain policy. Invalid/unavailable uplink DNS fails without fallback.
- `ProxyIpv4`: use one explicit public IPv4 resolver through the VPN, without
  direct fallback. Private/IPv6/encrypted resolvers fail validation before NM save
  or privileged setup.

These are plugin upstream policies, not competing host resolver configuration.
NM continues to own routes/DNS. The plugin publishes effective DNS via Ip4Config;
exclusive NM priority and `~.` remain required. Generic NM `ipv4.dns` overrides
remain rejected: bypassing the plugin resolver would break future FakeIP/domain
ownership. No `/etc/resolv.conf` writer or separate DNS daemon is introduced.

## Profile and frontend lifecycle

An override uses `vpn.data.dns-override`: `current-network` or `proxy-ipv4:ADDRESS`.
Absence means Inherit. V1 must not carry TCP/DNS policy keys; v2 requires at least
one (or the connected-LAN policy added by [ADR 0012](0012-connected-lan-bypass.md)).
Unknown values and incompatible policies fail closed. Older v1 backends reject
v2 rather than ignoring an override. The supervisor revalidates the complete model
before privileged resources.

COSMIC selects DNS for the next explicitly added profile. It clones the checked
node, changes only the override and validates again before starting an NM write.
Invalid selections leave source data, routing rules, pending control and saved
profiles unchanged. Selection is frozen during NM mutations. Profiles still save
persistently with autoconnect off. Saved-profile details read stored policy without
GetSecrets or DHCP lookup, not proof of the active resolver's behavior.

This ADR did not add saved-profile mutation. Later
[ADR 0018](0018-checked-profile-replacement.md) adds explicit checked replacement,
not a manual editor or automatic migration. The source URL, DHCP server,
DNS messages and replies are not persisted by this feature. Selecting a policy
never starts networking, activation or disconnect.

## Runtime and privilege boundary

For CurrentNetwork, NM receives `198.18.0.2` as tunnel DNS. The unprivileged netstack
handles UDP/TCP port 53 there; this is not a kernel listener or global DNS hijack.
Without a separate explicit policy, hardcoded application DNS/DoH is not rewritten.
[ADR 0013](0013-tun-dns-interception.md) adds optional IPv4 TUN port-53 interception;
FakeIP and broader source DNS-hijack semantics still need implementation/admission.

The worker submits only a DNS message and transport flag over the private broker,
never an upstream IP/port/URL/interface. The supervisor checks its own validated
CurrentNetwork policy and uses the previously selected NM resolver. Other profiles
cannot obtain this forwarding capability. The existing hickory-proto parses DNS;
tokio-util LengthDelimitedCodec handles bounded TCP framing. No handwritten DNS
parser, retry or generic dialer.

Only one IN-class QUERY question is admitted, with no update/answer/authority or
signature material. Responses must match ID, opcode, type and question. Negative
answers and truncation are relayed unchanged, never triggering internal fallback.
A client's explicit TCP query uses TCP. Upstream sockets are marked/uplink-bound;
normal guard and IPv6 blocking remain unchanged, without broad firewall exceptions.

Bounds: 4096-byte messages; five-second request-frame/upstream/reply-write deadlines;
the shared 64-request/second broker budget; 32 additional in-flight UDP DNS tasks;
ten-second worker broker deadlines; and 60-second TCP client idle deadlines. DNS
tasks are separate from the 64 proxied UDP associations. Uncertain cancellation,
malformed replies and size/identity mismatches poison the serialized channel;
explicit refusal does not. Errors contain no names, payloads or third-party text.
The supervisor owns/closes upstream sockets; none survive session teardown.

## Readiness and compatibility

Default/manual modes retain a bounded proxied DNS exchange, now using the selected
upstream instead of an unconditional constant. CurrentNetwork cannot certify a proxy
using direct DNS success alone: it resolves the existing probe name `example.com`
through the selected DNS, then performs a certificate-verified TLS handshake to
that name on port 443 **through VLESS**. The pinned TLS library owns the handshake,
verification is explicitly enabled and the engine deadline is ten seconds inside
the overall probe bound. No HTTP request or direct TCP fallback. This proves only
one TCP/TLS exchange, not UDP, completed NM routing or leak prevention.

Manual through-VPN DNS currently conflicts with Direct hostname rules: independent
Direct authorization still resolves through uplink DNS. Reject that combination
before save/setup rather than leaking verification queries to another resolver or
trusting arbitrary worker-provided addresses. CurrentNetwork plus Direct rules is
compatible. Inherit retains ADR 0010's documented Direct-name DNS behavior. Guarded
proxy-DNS authorization remains future work.

## Evidence and remaining acceptance

Model/client/schema tests cover persistence, no DHCP snapshots, cross-policy
rejection without mutation and secret-free observation. Private broker/worker tests
cover framing, ID/question binding, negative answers, refusal, cancellation, no
fallback, no privileged work on invalid input and oversized client-frame rejection.
TLS tests cover invalid names, deadlines and cancellation ownership, not positive
public-CA interoperability.

Ordinary tests contact no router, real NM or external service and alter no host
routes/DNS/firewall. Positive forwarding, verified readiness, packet-level leakage,
NM DNS application and teardown need authorized VM/native evaluation. The complete
target remains FakeIP plus the selected upstream and explicit LAN bypass. These
component tests do not justify partial installation or automatic migration.
