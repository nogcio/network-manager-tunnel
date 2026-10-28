# ADR 0007: Explicit NM storage and connection control in COSMIC

Status: implemented experimentally; bounded synthetic NM/TUN VM checks passed,
broader native acceptance pending. Source URL persistence is superseded by
[ADR 0028](0028-subscription-url-secret-service.md); failure recovery by
[ADR 0026](0026-automatic-session-recovery.md).
Date: 2026-10-25.

## Context

The frontend needs an explicit NM profile lifecycle independent of subscriptions.
Requiring a subscription reload or keeping the editor alive must not become a
condition for using NM profiles. The backend and dependency graph remain experimental.

## Decision

- Read NM profile and active-connection metadata at startup and every three seconds
  while the app is open. This revises ADR 0003's initial disabled-Connect state;
  it does not authorize automatic subscription fetching, secret retrieval, writes
  or connection activation. Debug previews perform none of these NM reads.
- Keep NM as the only persistent profile store. Display this service's schema-v1
  VLESS profiles separately from the in-memory subscription list. Select saved
  profiles by NM UUID, never by a mutable list position or authentication UUID.
- Always save persistently on explicit Add, with a visible explanation that NM
  stores profiles and credentials on disk, not in a desktop keyring. This revises
  the initial session-only default and optional persistence decision (2026-10-26):
  profiles should remain usable after restart without a separate storage toggle.
  Do not maintain an app-side profile database. The original session-only URL rule
  is superseded by ADR 0028's desktop Secret Service catalog; VPN credentials remain
  exclusively NM-owned.
- Use AddConnection2 TO_DISK only, with autoconnect off and credentials only in
  `vpn.secrets`. Never fall back to IN_MEMORY on failure or automatically migrate
  existing temporary profiles. NM owns backing-file permissions. Request standard
  interactive NM/Polkit authorization only for explicit save/control operations. No new policy
  permission, privileged GUI or custom secret store is introduced.
- Enable Connect only for an observed saved profile and registered backend with
  no observed active connection for this service. Registration is not readiness.
  Connect/Disconnect call NM's normal ActivateConnection/DeactivateConnection API;
  the GUI never configures routes, DNS, firewall rules or worker processes.
- A method reply means request acceptance, not Connected or completed teardown.
  Show observed NM state; report unknown/unavailable state instead of fabricating
  Disconnected. An accepted activation that disappears reports failure, not success.
  Ignore observations initiated before a later UI mutation.
- Bind saved/active handles to NM's unique bus owner, object path and independent
  profile UUID. Revalidate identity before control. No public arbitrary-path handle
  constructor exists; a stale path/owner must not redirect a request to another profile.
- Treat missing replies, transport loss and deadlines as indeterminate writes.
  Never retry save/control automatically. After ambiguous save, further additions
  remain disabled for that app session; refresh cannot clear that uncertainty.
- Closing the GUI sends no Disconnect. Reopening can observe/control the existing
  NM connection without a subscription or credentials lookup.
- The original retained-crash-guard/manual-recovery behavior is superseded by
  ADR 0026's automatic terminal cleanup and return to ordinary networking without
  VPN. The frontend still never clears guards. Native secret-agent integration
  remains future work. Packaging follows
  [ADR 0008](0008-local-arch-installer.md).

## Evidence and limits

Private-bus tests cover storage flags, absent secret lookup, request-vs-state,
identity/owner replacement, indeterminate saves and read races. UI state tests
cover guarded control, stale observations, explicit additions and failure
feedback without optimistic Connected state or automatic retries.

The [service guide](../../crates/nm-service/README.md#build-packaging-and-acceptance)
owns the synthetic VM client probe for persistent storage, activation/TUN echo,
client-independent lifetime, unprivileged observation and persistent-file permissions.
These checks do not prove reboot behavior, desktop Polkit prompts, native widget
input or accessibility. Current per-row controls and telemetry observation are
documented in the [frontend guide](../../frontends/cosmic/README.md); outstanding
product acceptance lives in the [roadmap](../roadmap.md).
