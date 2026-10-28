# ADR 0018: Checked replacement of a saved NM profile

Status: implemented lab-client API; the original COSMIC flow is superseded by
[ADR 0027](0027-cosmic-profile-and-source-management.md). Private-bus/state checks
are not native NM/Polkit acceptance.
Date: 2026-10-26.

## Scope and real consumers

The original COSMIC saved-profile details provided **Replace from subscription…**. Select a
supported entry from an admitted source, review the target and replacement node,
then explicitly confirm. This is full VPN/IP replacement, not a manual protocol
editor, automatic subscription synchronization or automatic schema migration.
The new `replace_profile` client API also has an explicitly authorized lab-import
consumer. It adds no dependencies, privileged API, daemon or profile database.

Preserve the target's independent NM UUID, name, connection permissions and other
connection-level properties. Replace the `vpn`, `ipv4` and `ipv6` sections with the
selected validated profile's transport, credentials, DNS/routing and standard IP
configuration. Previous overrides in those three sections are intentionally not
merged: merging stale rules/overrides could defeat the new policy. The UI and CLI
must disclose this before confirmation. Preserve other NM setting sections.

Credentials come from the selected imported profile, never GetSecrets. They remain
in `vpn.secrets`, with NM-owned system disk storage disclosed before confirmation.
No source URL or opaque source configuration is persisted. Diagnostics and Debug
are redacted. Replacement does not change the source entry or another saved profile.

## Identity, concurrency and persistence

Saved handles remain pinned to bus ID, unique NM owner, path and UUID. Read
VersionId before and after GetSettings/Unsaved with property caching disabled;
if it changes, discard the observation. Older NM can still be observed/controlled,
but missing/zero VersionId cannot authorize replacement. A newly created/replaced
handle also requires a fresh snapshot; never guess the next version.

Re-read and verify the pinned UUID and expected nonzero VersionId before updating.
Call Update2 on the unique owner with the exact `version-id` argument, requiring
NM 1.44+ support for the server-side concurrency check. NM rejects a concurrent
edit even after local validation or during authorization. No legacy Update or
unconditional/memory-only fallback exists. Loss of current NM ownership before
dispatch rejects; the addressed unique owner cannot redirect to its replacement.
There is still no atomic bus ownership-check-and-call operation.

Flags are TO_DISK | BLOCK_AUTOCONNECT | NO_REAPPLY (`0x61`), and the saved
connection's autoconnect is false. The existing active session is not disconnected,
activated or reconfigured by this client. New VPN settings require explicit
reactivation; a successful save is not live application or readiness certification.
No host route/DNS/firewall writer is introduced.

Definite remote method errors are refusals. Missing replies, cancellation and
transport/20-second deadline failure are indeterminate: the update may have
completed. Never retry, roll back or create another profile automatically. Return
confirmed success without a fallible post-write read; refresh observation separately.

## Frontend review ownership

The review pins the observed target handle and an owned validated replacement.
Source/list/format, DNS/LAN choice and node-selection changes invalidate the review.
Unsupported or stale row selection cannot retain a previous candidate. Confirmation
requires an admitted current list and unchanged target observation. A stale target
must be selected again; polling never silently upgrades the review's target version.
Busy state prevents overlapping mutations. Navigation/cancellation before dispatch
has no NM effect. Navigation during a dispatched update does not imply cancellation.

Ambiguous completion disables both additions and replacements for that UI session,
as for existing saves. Failed replacement retains the loaded list, selection and
previously added mappings; it never disconnects the working VPN or changes DNS
selection to force admission. Complete source import retains its independent
fail-closed barrier until IPv4 DNS/routing translation is implemented.

## Evidence and limitations

Private-bus tests cover identity/ACL preservation, intended VPN/IP overwrite,
credential separation, missing versions, read/update races, path/UUID reuse,
bus/owner changes, refusal without mutation and completed updates with lost replies
without retries or activation. UI state tests cover invalid target/review events,
failure-state preservation and ambiguous-outcome save blocking. These do not prove
the native confirmation/input/Polkit UX or NM's on-disk/active-session behavior.
Authorized NM/VM acceptance and an autonomous install/reconnect plan remain required.

The checked contract was inspected in NetworkManager **1.54.0**:
[Settings.Connection XML][nm-xml] describes Update2 flags and `version-id`;
[the implementation][nm-source] exposes VersionId and performs the comparison
after authorization. No upstream source was copied.

[nm-xml]: https://github.com/NetworkManager/NetworkManager/blob/1.54.0/introspection/org.freedesktop.NetworkManager.Settings.Connection.xml
[nm-source]: https://github.com/NetworkManager/NetworkManager/blob/1.54.0/src/core/settings/nm-settings-connection.c
