# ADR 0027: COSMIC profile editing and session source management

Status: implemented client/frontend contracts; source persistence is superseded by
[ADR 0028](0028-subscription-url-secret-service.md). Bounded inactive NM storage
checks passed; active-session, concurrent-control and desktop prompt acceptance pending.
Date: 2026-10-27.

## Boundaries and consumers

The COSMIC V4 frontend consumes three narrow NM-client operations: `edit_profile`,
`delete_profile` and `update_from_source`. They add no dependency, privilege, service
method, protocol support, host networking writer or mandatory UI daemon. Existing
installed backends can use the resulting schema-v1/v2 settings. A new frontend can
run from source without reinstalling or disconnecting the owner's current VPN.

NM remains the profile/activation owner. The frontend's source catalogs are imported
session data, not a persisted profile or credential database. `subscriptions.rs`
owns sources, HTTP-candidate reviews and explicitly mapped update progress;
`profile_editor.rs` owns drafts and disconnect-before-delete. `operations.rs` reserves
unique storage tickets and retains the session-long indeterminate-write barrier.
Navigation, message dismissal and observation cannot release another operation's ticket.

## Narrow edits

The shared codec's `ProfileChanges` patches only display name and the supported
DNS/LAN/interception/FakeIP keys. It validates a non-secret configuration, never
manufactures a credential, and preserves UUID, permissions, transport, unrelated
settings and IP dictionaries. Connected-only and broad RFC1918 bypass remain distinct.
Source-required protection cannot be disabled and incompatible combinations reject.

The client revalidates bus ID, unique NM owner, path, UUID and nonzero VersionId,
then sends Update2 with the expected version and TO_DISK | BLOCK_AUTOCONNECT |
NO_REAPPLY (`0x61`). No fallback, GetSecrets, activation or live reapplication occurs.
No secrets are included in an edit request. NM retains existing secrets when an
update contains none; this was inspected in NetworkManager 1.54.0's
[`update_auth_cb`][nm-source]. A private-bus peer verifies our outgoing omission
and preserved fields; it does not prove native NM storage behavior.
Separately, an owner-authorized disposable Arch VM with NM 1.58.1 passed persistent
save, narrow edit, stale-version refusal, source override preservation and deletion
through the real client API. A guest nobody client was refused without a leftover
fixture. This does not establish desktop Polkit prompt UX or active-session editing.

## Deletion

Confirmation identifies one observed profile. If active, one explicit NM deactivate
request precedes an observation wait, bounded to 45 seconds after acceptance.
Only a post-request, matching snapshot with no active target authorizes deletion.
Missing observations, changed/removed targets, refusal and deadline stop this
pipeline without requesting Delete. No guard is inspected, removed or inferred by UI.

The delete API independently revalidates the versioned handle and inactivity before
one standard NM Delete. NM owns profile and credential removal. Delete has no
server-side version-id/inactivity argument: an external edit/activation after our
last check, including during authorization, cannot be excluded. This limitation is
not represented as an atomic conditional deletion. Native concurrent-control and
Polkit acceptance remain required. Other profiles and sources are not deleted.

## Subscription updates and identity

A source download produces a candidate; the old admitted catalog survives failure
and remains unchanged until Apply. The supported formats do not prove stable server
identity across configuration changes. Exact unique configuration equality can
retain a saved-row association without writing; name, order, filtered index and
duplicate configuration cannot authorize automatic replacement. The review requires
explicit mapping for changed linked profiles. It never offers arbitrary replacement
of unrelated profiles from Settings. Source removal leaves all NM profiles running
or stored, and no refresh creates profiles or recreates deliberately deleted ones.

`update_from_source` retains the connection dictionary and existing IP dictionaries.
It validates the candidate combined with existing DNS, LAN and protection overrides
before dispatch; new mandatory-policy conflicts reject rather than weakening policy.
VPN settings and source credentials are updated only after the storage disclosure
and explicit Apply. Version checks and `0x61` match narrow edits. The running VPN is
not restarted. The old full-replacement API remains only for its explicit lab client;
its contract in ADR 0018 is not silently changed.

Multiple mapped profiles are written sequentially, not transactionally. Completions
are bound to both storage ticket and target UUID; a prior step's duplicate cannot
complete the next step. Confirmed updates are recorded and not replayed. Failure
stops remaining writes and reports the confirmed count without automatic rollback.
Deadline, missing reply or transport loss may mean a completed remote write. Those
outcomes block Add/Edit/Delete/Apply for the rest of the app session. Definite refusal
does not become success. Remote calls have the existing 20-second total deadline;
future cancellation never claims cancellation of an already dispatched NM request.

## Deferred contracts, not simulated capabilities

The original implementation kept sources/URLs session-only. ADR 0028 supersedes
that deferral with an owner-approved, experimentally implemented desktop Secret
Service catalog. Reopening restores source URLs/associations without fetching nodes
or activating VPN. Downloaded nodes/credentials are not cached. No XDG token file,
private keyring, new NM credential agent or implicit credential migration was added.
Missing/locked storage remains explicit; native provider acceptance is pending.

ADR 0026 remains authoritative for recovery: terminal failure restores ordinary
networking without VPN. V4's retained-protection reconnect/Stop/Retry/Allow-unprotected
journey conflicts with that backend contract. The owner explicitly retained ADR 0026
in ADR 0028; those retained-guard controls are not part of accepted behavior.
The UI does not manufacture those operations or certify guard state from NM readiness.
No unavailable recovery control is presented as a working product capability.

Native focus/screen-reader behavior, scaling, desktop Polkit, active-session updates,
concurrent deletion and packet protection remain separate acceptance. Synthetic previews are
local, display-only/draft-only fixtures with no actionable NM handles or network I/O.
Builds, private buses and captured pixels do not certify native UX or VPN security.

[nm-source]: https://github.com/NetworkManager/NetworkManager/blob/1.54.0/src/core/settings/nm-settings-connection.c
