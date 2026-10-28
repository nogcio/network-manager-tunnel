# ADR 0028: Desktop Secret Service for subscription URLs

Status: owner-approved boundary, experimental frontend implementation; native acceptance pending.
Date: 2026-10-27.

## Decision

The owner explicitly approved storing subscription URLs through the standard
desktop Secret Service. This is a narrow exception to the earlier all-secrets-in-NM
rule: VPN credentials remain in NM `vpn.secrets` and its secret-agent flow. No
credential migration, hidden NM source profiles, plaintext URL file, application
encryption or private keyring is authorized or required.

An optional owner-only XDG catalog may store only bounded non-secret source metadata
and independently generated source/item identifiers. It is not an NM profile database.
URLs/tokens must not appear in filenames, item attributes, labels, logs or diagnostics.
Do not persist imported node credentials outside NM. Missing/locked/refused Secret
Service must remain an explicit error, never a reason to write a plaintext fallback.
Loading metadata on launch must not fetch subscriptions or activate VPN.

Use a maintained Secret Service client, not handwritten session cryptography.
Document its exact resolved source/features, license, maintenance, security and native
cost before admitting the dependency. A public API must have the actual COSMIC
persistence consumer, not a speculative future caller.

## Required persistence semantics

The implementation keeps the entire bounded source catalog in **one Secret Service
secret payload**, rather than splitting URL and metadata across two stores. It
contains source IDs/names/import mode and linked NM UUID/label associations, never
downloaded nodes, credentials or an NM profile copy. Attributes and label are static;
URLs appear only inside the secret value. `secret-service` 5.2.0 supplies an encrypted
DH session with the provider; there is no plaintext-session fallback. Dependency
resolution/features/cost are recorded in [dependency review](../dependency-review.md).

The only local file is `$XDG_STATE_HOME/network-manager-tunnel/sources.lock`
(fallback `$HOME/.local/state/...`), held for the app lifetime. Descriptor-relative
NOFOLLOW traversal rejects symlink paths and unsafe ownership/modes; the app directory
is owner-only and the regular single-link lock file is 0600. A second cooperative
Tunnel instance cannot load/write the catalog while the first owns this lock.
This does not prevent another same-user program from changing a keyring item.

Startup restores unlocked data without HTTP/NM writes. Locked storage needs the
explicit Restore action and desktop authorization. After restart, server catalogs
are intentionally not cached: Update downloads a new candidate; UUID associations
survive with no assumed server index, so changed profiles still require explicit
mapping. Missing storage leaves sources visibly session-only, never saved in plaintext.
Restoring over existing session sources is refused instead of overwriting them.

Writes are serialized, bound to unique tickets and bounded to 30 seconds including
desktop authorization. A confirmed save may be followed by a newer requested dirty
snapshot, but a failed write is never automatically retried. Unknown writes retain
the session-long storage barrier. NM profile writes and keyring writes are separate:
a successful NM save is not rolled back if saving its source association fails;
the UI explicitly reports unconfirmed persistence and retains session data.
Source removal replaces the catalog with that source omitted; NM is unchanged.
The encrypted item may remain as an empty catalog, containing no removed URL.

Versioned bounded metadata admission rejects malformed/unknown documents and
unsafe storage paths without replacing existing data. The lifetime single-writer
lock prevents cooperative Tunnel instances from silently losing catalog changes;
Secret Service supplies item replacement, not a cross-NM transaction. Disclose
confirmed partial outcomes; never claim rollback or automatically repeat an
ambiguous secret write. Stable source identifiers and unique tickets bind
async completions so a late result cannot replace another source.

URL access must support locked/missing items and explicit desktop authorization.
Unlock prompts and all async work need cancellation/deadline ownership; cancellation
does not prove a dispatched secret write was cancelled. Source removal must not
remove NM profiles, credentials, active VPN, routes, DNS or firewall state.
Ordinary checks use synthetic filesystem roots and private-bus/fake storage peers,
never the owner's actual keyring. Native Secret Service/prompt acceptance is separate.
`scripts/check_source_store.py` additionally exercises the actual adapter against
checksum-pinned GNOME Keyring 51.1 on a private bus and temporary HOME/XDG tree.
Save/reopen, linked UUIDs, confirmed removal and locked reads are checked without
HTTP, NM or the real desktop keyring. This is provider protocol acceptance, not
desktop authorization/input/accessibility acceptance or a guarantee of every provider.

## Recovery remains unchanged

The owner explicitly selected retaining ADR 0026's automatic return to ordinary
networking after terminal failure. Figma's retained-protection A01–A04 journey is
therefore not the accepted backend contract. Do not implement Stop/Retry/Allow
unprotected controls that imply a persistent retained guard, or change the installed
VPN while implementing source persistence. ADR 0027's storage deferral is superseded
by this boundary and experimental implementation, not by native acceptance.
