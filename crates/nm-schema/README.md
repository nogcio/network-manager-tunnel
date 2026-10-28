# NetworkManager settings contract

Pure schema-v1/v2 conversion shared by `nm-tunnel-client` and `nm-tunnel-service`.
This package opens no bus connection, creates no sockets, allocates no tunnel
resources and stores nothing. It belongs to the `contract` dependency layer, not
the protocol engine or the profile model.

## Ownership and admission

- `encode_profile` converts an executable validated profile into NM dictionaries.
  It generates an independent connection UUID, disables autoconnect and keeps the
  credential exclusively in `vpn.secrets`. Its returned values contain secrets;
  Debug is redacted, but serialization is not a zeroization guarantee.
- `decode_configuration` checks public settings without looking up or inventing
  credentials. The returned `Configuration` is not a `Profile`; its empty credential
  cannot pass executable validation. NM NeedSecrets uses this path.
- `decode` requires the one supported credential and returns an executable `Profile`.
  Unknown, oversized and contradictory settings reject with static errors, without
  changing the input or allocating runtime resources.
- `decode_policy` owns version/mode admission for non-secret observation and returns
  the model's immutable `NetworkPolicy`, shared with executable profiles.
  It validates network-policy combinations through the model's `validate_policy`;
  it is a projection, not proof of complete transport validity, credentials or
  active enforcement. Incompatible stored metadata reports an observation error,
  never an invented disconnected state.
- `ip_policy` checks the supported NM IPv4/IPv6 settings before service activation.
  Only NM installs normal routes, addresses and DNS.
- `ProfileChanges::apply` validates narrow non-secret name/network edits without
  credentials. It preserves transport, identity, permissions and IP dictionaries;
  source-required modes and incompatible resolver/routing combinations reject.
  NM-version checks and actual mutation remain client responsibilities.

These are synchronous operations: no background tasks or independent cancellation
lifecycle exist. Callers own dictionaries and transient credential copies. Settings,
policy domains and subscription identities must never be logged.

Client replacement retains connection identity/ACLs and replaces explicitly reviewed
VPN/IP sections; that operation and its indeterminate-write behavior remain owned
by the client, not this codec. Schema versions and stored field names are unchanged;
there is no automatic migration or widened policy admission.

Public contract tests exercise round trips, secret separation, non-executable
configuration and agreement between metadata and service policy rejection. They
do not establish NM/native acceptance or protocol interoperability.
