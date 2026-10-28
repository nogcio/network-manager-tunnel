# ADR 0017: IPv4-only first version

Status: accepted by owner; endpoint admission and disclosure implemented.
Date: 2026-10-26.

## Decision

Defer IPv6 transport, endpoints, DNS upstreams, LAN bypass and FakeIP until after
the first IPv4-only joint test. IPv6 FakeIP is no longer a prerequisite for that
test. This is an explicit product limitation, not transparent preservation of an
IPv6-capable subscription and not permission to drop unrelated source policies.

Shared profile validation rejects IPv6 literal endpoints, including IPv4-mapped
IPv6, before saving. URI import rejects them with a static IPv4-only explanation;
node-only subscriptions retain unsupported rows rather than hiding or converting
them. Previously stored IPv6 endpoint data also rejects during backend admission,
without rewriting the saved connection or its secrets. Hostname endpoints use the
existing bounded A-only bootstrap; an IPv6-only answer cannot activate the VPN.
An ordinary hostname with an A record remains supported even if it also has AAAA.

Keep runtime leak protection: the VPN guard blocks non-loopback IPv6, including
when connected-LAN bypass is enabled. NM still advertises no IPv6 VPN configuration,
and the worker does not admit IPv6 payloads. Do not disable IPv6 globally, change
host sysctls, delete library code or reinterpret IPv4-mapped IPv6 as an IPv4 grant.
Local loopback remains local; this decision does not block localhost services.
Guard installation and failure retention keep their existing lifecycle.

Persistent IPv4 FakeIP already answers A with durable identities and AAAA with
NODATA; retain this behavior. Legacy/non-FakeIP DNS forwarding is not silently
changed into a new resolver policy and can still return AAAA records, but those
records do not authorize IPv6 traffic. No blanket removal of IPv6 DNS records from
arbitrary upstream responses or handwritten DNS/IP parser is introduced.

## Complete subscriptions

The owner accepts running the IPv4-only subset instead of the source's IPv6
behavior, with an explicit UI warning. A future complete importer may therefore
disable the source's IPv6 FakeIP pool/AAAA synthesis and IPv6 tunnel addresses as
part of that disclosed subset. It must still validate the source and preserve its
IPv4 DNS/routing behavior. Arbitrary IPv6-only resolvers, endpoints, rules or other
settings must not be silently mapped onto IPv4 or an unrelated resolver/outbound.
Any setting without a checked IPv4 interpretation continues to reject admission.

The bounded complete IPv4 importer is now implemented experimentally under
[ADR 0020](0020-native-ipv4-source-policy.md). This decision
does not bypass required policy checks or introduce node-only fallback. UI import and saved
details disclose IPv4-only support now; no source configuration is rewritten or
executed merely by showing that warning.

## Evidence and remaining work

Contracts cover URI/draft rejection without mutation or private diagnostics,
unsupported subscription-row retention, and backend rejection of saved IPv6
endpoints in schemas v1/v2 with settings/secrets unchanged. Existing guard tests
continue to cover IPv6 blocking. Ordinary checks never change host networking.

Exact private-source compatibility, native
[saved-profile replacement](0018-checked-profile-replacement.md), positive relay/NM/boot
acceptance and the authorized installation/reconnection plan remain necessary.
IPv6 support is later work, not an installation gate for this IPv4-only version.
