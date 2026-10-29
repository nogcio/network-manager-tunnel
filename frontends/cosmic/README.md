# NetworkManager Tunnel: COSMIC frontend

Native standalone libcosmic app, not a web UI or embedded COSMIC Settings plugin.
Uses system theme/typography, grouped list rows, native controls and the standard
right-hand context drawer. Core owns the native CSD, NavHandle and single-select
NavBar for Connections and Subscriptions. The window title is Tunnel; page titles
and actions live in the content pane, not the CSD. There is no persistent instructional footer.
The wgpu renderer retains upstream software fallback.
There is no custom window chrome or mandatory tray process.
The pinned toolkit's centered CSD title was absent in native captures, so Tunnel
uses its standard start slot for the fixed app label. This is an explicit layout
adaptation from Figma, not an application-drawn replacement header.
The separate native header title is empty to avoid a duplicate app label on X11;
the operating-system window title remains Tunnel.
Ordinary launches leave the toolkit theme unset: COSMIC owns live system theme,
accent and corner radii. Only explicit debug synthetic previews override the theme
to exercise dark/light/high-contrast variants; they do not set production geometry.

## Localization

The frontend follows the COSMIC application-template pattern: embedded Fluent
catalogs, `i18n-embed` desktop language negotiation, `i18n-embed-fl` compile-time
message/argument checks, and English fallback. English and Russian resources live
under `i18n/en/` and `i18n/ru/`; there is no separate application language preference
or translated documentation tree. Language selection occurs at launch from standard
locale preferences (`LANGUAGE`, `LC_ALL`, `LC_MESSAGES`, `LANG`), without changing
desktop settings. Restart after changing the desktop's language.

Navigation, controls, safety disclosures, dialogs, progress and typed UI errors use
localized messages. User profile/source names, URLs, protocol names, explicit binary
units and backend diagnostic codes/static per-node diagnostic explanations are not
rewritten. Russian server counts use Fluent plural categories, not English suffixes.
Unknown languages fall back to English. Tests compare catalog IDs/arguments, exercise
regional locale negotiation and check that user values are not parsed as Fluent.

## Connections and traffic

Connections displays NM's observed state, active profile and explicit Disconnect.
Each saved profile has its own Connect and information actions, not radio selection
followed by a distant global button. Search filters names locally, bounded to 128
characters, without secret lookup. Connect requires an observed profile, registered
backend and no active connection for this service. Switching requires explicit
Disconnect first. Unknown NM state is not Disconnected; method acceptance is not
readiness or completed teardown. Closing the app never disconnects.
When disconnected or NM is unknown, no large traffic chart is shown. Last-attempt
statistics remain available separately. NM refresh belongs beside its unavailable state. Observed
Disconnecting disables another disconnect request. Bounded glyph wrapping keeps
unbroken profile/node names clear of row actions.

Usage comes from the backend's read-only v1 telemetry through `nm-tunnel-client`:
download/upload rates, totals and a 60-second history. The chart uses toolkit canvas,
theme-owned colors, labelled axes and solid/dashed lines. Values/totals also appear
as ordinary text. Snapshots replace history wholesale. Samples become non-live
after three seconds even if UI observation stalls; stale/missing rates show `—`,
not false zeros. Retained totals describe the last attempt. TUN packet accounting
is not application payload or provider billing.
Missing sampling intervals break both plotted series. Dashed segments are stroked
independently instead of joining through an unknown interval.

Backend statistics use the context drawer for last observed counters, TCP/UDP flows,
errors and setup stages. Profile details show only NM metadata: the telemetry API
cannot associate an attempt with a profile, even when it is active. The global
details action can show the backend's last
attempt after NM removes its active connection. Neither worker nor NM readiness
proves firewall protection; guard presence is not part of the statistics API.

NM reads run at startup and about every three seconds; independent usage reads run
about once per second. Reads are coalesced and ignore pre-mutation completions.
Usage observation does not D-Bus-activate the backend or authorize interactively.
Navigation/search/drawer actions stay usable during HTTP/NM operations and never
own or complete those operations.

`navigation.rs` owns native primary selection and independent pane scroll offsets,
not profile or download state. Switching primary sections retains drafts/search and
restores the corresponding viewport. Escape closes context first; it does not leave
a primary section. Invalid/removed navigation entities have no effect. Profile
Settings and backend statistics use a non-modal side-by-side Context Drawer when
Core has sufficient width. In condensed mode the same content is a secondary page
with Back above its title; the parent primary selection remains active. Closing
context restores the parent viewport without an application-requested window resize.
The pinned toolkit has no exported PageHeader widget: page headings and Back use
its native text/button composition. The app label uses the CSD start slot; the
center title was not visible in synthetic captures with this toolkit revision.

`operations.rs` owns the pure NM operation lifecycle: Idle, Adding (with the
admitted catalog row), ticketed Storage, Requesting control, and Awaiting observation.
Only the matching dispatched completion releases a mutation; unrelated or
unsolicited completions leave its state and feedback unchanged. Accepted control
does not mean Connected and only subsequent NM observation can finish its feedback.
A new explicit action may supersede accepted control feedback, never an in-flight
mutation. Storage uncertainty is sticky for the app session and does not prevent
explicit connection control or read-only work. HTTP loading and coalesced NM/usage
reads retain separate lifetimes; no transition retries a remote operation.

`reads.rs` replaces shared epochs/pending booleans with unique tickets and separate
NM, usage and recovery slots. Invalidating a pre-mutation result does not release
its pending slot or pretend to cancel its remote read. Duplicates/foreign tickets
cannot complete newer work. Independent helper progress is observed about once per
second without activation and shown with the connection summary. Missing, failed or
locally stale status never certifies cleanup; confirmed guard cleanup is historical,
not VPN readiness or proof that NM already removed its routes.

## Explicit subscription import

`catalog.rs` owns loaded-node selection, admission, search and NM reconciliation;
`options.rs` owns pure DNS/LAN/protection choices and profile-copy validation. These
modules neither call NM nor fetch subscriptions. An invalidated catalog retains
read-only rows but cannot provide a profile for Save.
`download.rs` owns the memory-only source, format, HTTP error and unique in-flight
request ticket. Source/format freeze until matching completion; a late or duplicate
result cannot re-admit an older list or invalidate a newer review. No HTTP completion
owns NM feedback or resets the session-long indeterminate-write barrier.

**Request complete configuration** is on by default. It selects the complete
sing-box response envelope and refuses unsupported policies without extracting
nodes or retrying in another format. The bounded native IPv4 subset is experimental,
not general source-format compatibility. A node-only
response to a complete request is an error, not proof that a provider has no rules.

Turning the option off explicitly chooses legacy node-only import. Its warning
states that source DNS/routing are not requested/imported, legacy default DNS is
`1.1.1.1` before a profile override, and domain/LAN exceptions are absent. This is
not a workaround that
preserves unsupported policies. Source/format changes and failed loads retain old
nodes for inspection but block Add until a successful reload. Neither format nor
source changes during a pending download or NM mutation.

`subscriptions.rs` owns multiple session sources, their retained catalogs, source
settings and candidate update reviews. Full-row native Subnav buttons open a source;
Back belongs above the nested title. `source_store.rs` persists bounded names, URLs,
import modes and linked NM UUID/label associations in a desktop Secret Service
secret over DH-encrypted transport; the provider owns at-rest protection.
`source_persistence.rs` owns ticketed restore/save progress and errors.
There is no plaintext token file, private keyring, automatic startup fetch or duplicate
profile database. Native provider/prompt acceptance remains pending. See
[ADR 0027](../../docs/decisions/0027-cosmic-profile-and-source-management.md).
The owner-approved storage exception and lifetime XDG single-writer lock are defined
in [ADR 0028](../../docs/decisions/0028-subscription-url-secret-service.md).

1. Choose **Add subscription**, enter a name and visible HTTPS URL, select an import
   mode, then confirm **Add subscription** in the pinned footer. One checked download
   admits the session source; failure leaves the form available without creating profiles.
   With a retained list, the action is **Reload subscription**.
   The default complete mode currently rejects required unsupported policies;
   legacy node-only mode requires an explicit choice with the warning above.
2. Review/search the admitted source's servers.
   Unsupported entries have an explanation, not a Save action.
3. Review the storage notice: **Save profile** saves profile settings through NM
   and delegates credentials to the desktop's registered NM secret agent. There is
   no direct VPN keyring access or silent system-secret fallback. Existing profiles
   keep their storage mode. A new persistent session waits under protection through
   network loss until recovery or explicit Disconnect; startup/autoconnect stays off.
4. Press **Save profile** on a particular row. Autoconnect stays off; saving never
   connects. Return to Connections to explicitly connect the observed NM profile.

**DNS and LAN for the next added profile** offers source/default, current-network plain
IPv4 DNS outside VPN, and one manual public IPv4 resolver through VPN. Only the
new profile copy changes; routing rules remain. Invalid choices reject before NM
writes, and choices freeze during NM mutations. CurrentNetwork stores only the
mode and rereads uplink DNS at activation, not OS DoT/IPv6 policy. Manual DNS plus
Direct hostname rules is currently rejected rather than leaking verification
queries through another resolver. Saved details show stored policy, not proof of
active DNS behavior. The profile editor below can update saved policy;
there is no manual protocol editor or automatic migration. Full
native override/packet acceptance remains pending; see
[ADR 0011](../../docs/decisions/0011-profile-dns-overrides.md).

The new-profile bypass switch explicitly selects all RFC1918 physical routes,
including routed LANs. The saved-profile editor also retains connected-only mode
as a distinct choice; no old profile is widened automatically. Route/packet
acceptance is still pending; see
[ADR 0012](../../docs/decisions/0012-connected-lan-bypass.md).

DNS/LAN options also offer explicit default-off **Intercept tunnel DNS** and
**Persistent IPv4 FakeIP** choices. Choose interception first; enabling FakeIP locks
that opt-in until FakeIP is turned off. Choices freeze during NM writes.
They never disable admitted source requirements or alter existing profiles without
an explicit save. FakeIP protection is automatic
and session-scoped, removed on disconnect or terminal failure. Ordinary traffic then
resumes without VPN through automatic backend cleanup. No boot
enablement is required; cached synthetic destinations are unprotected outside the
session or after reboot. These choices do not import missing source
routing/blocking rules or implement full DNS-hijack compatibility. Combined LAN/interception
details identify the guarded direct TCP/UDP relay mode, where other LAN IP protocols
are unsupported. See [ADR 0013](../../docs/decisions/0013-tun-dns-interception.md) and
[ADR 0014](../../docs/decisions/0014-intercepted-lan-relays.md).

The new-profile LAN checkbox now explicitly chooses all-RFC1918 physical bypass,
including routed private networks. Saved connected-only profiles keep their older
mode. Enabled DNS interception still applies to private port-53 destinations,
including gateway host routes; see [ADR 0024](../../docs/decisions/0024-private-ipv4-bypass.md).

Added rows retain returned NM UUIDs and source associations in memory. Successful
NM observations reconcile removed profiles; failed observations preserve markers.
This is not deduplication across subscriptions. Ambiguous saves disable additions
and all other profile mutations for the app session; navigation, feedback dismissal and refresh
do not permit retry.
No writes/requests are retried automatically.
An ambiguous save has one persistent warning across pages, not duplicated banners.

### Profile settings and deletion

Settings shows saved NM configuration, never profile-attributed backend statistics.
**Edit settings** opens a scrollable secondary page with stable Cancel/Save actions.
Name, DNS, the distinct LAN modes and supported interception/FakeIP can be edited.
Required source modes stay locked. Invalid DNS is shown locally and blocks Save,
not Cancel/Back. Saving uses version-checked, non-secret Update2 with NO_REAPPLY:
UUID, permissions, transport, IP settings and NM-owned secrets are preserved.
An active profile's changes apply on the next connection, without a restart.

**Delete profile** requires a native confirmation. For an active target it requests
NM disconnection once, then requires a fresh matching observation showing no active
object before Delete. The observation wait is bounded to 45 seconds after acceptance;
unknown state, target changes and timeout stop the pipeline without requesting Delete.
Delete itself revalidates identity/version and inactivity, but NM has no atomic
Delete version/inactivity precondition; native concurrent-control acceptance is pending.
Cancel/Escape before dispatch never writes. Sources and other profiles are kept.

### Source updates

**Update subscription** downloads a candidate without replacing the admitted list.
Failures retain the previous source. **Apply update** is explicit; it never saves
new profiles, deletes disappeared profiles or reconnects VPN. Exact unique configuration
matches preserve existing row markers; equal names, changed fields, duplicate
configurations and list positions do not prove stable identity. Changed saved profiles
must be explicitly mapped in the review. Only that source's linked NM profiles can
be mapped, and all target handles are version-pinned.

Mapped updates preserve UUID/name/ACL, IP settings and compatible DNS/LAN/protection
overrides. New mandatory source conflicts reject. Writes execute sequentially; confirmed
ones remain applied on a later failure. The result reports the confirmed count without
invented rollback. Completed rows are not replayed; unknown writes block further
storage for the app session. No update automatically recreates a deleted profile.
Removing a source forgets its URL/associations, not NM profiles or the active VPN.
Removal is durable only after the replacement keyring catalog is confirmed. A
persistence failure retains session changes but does not claim the old keyring item
was changed. Unknown writes block later storage.
Changing its URL in Settings also requires a successful candidate check and explicit
Apply; cancellation or HTTP failure preserves the previous name/URL and profiles.

On launch, unlocked stored subscriptions are restored without HTTP or NM writes.
Locked storage needs **Restore subscriptions** and the desktop keyring's authorization.
Server credentials/lists are not cached: reopen a source and explicitly Update to
download its servers. Existing UUID associations survive, but no old row index is
trusted. A second Tunnel writer is refused. Definite save failure needs explicit Retry;
lost replies/deadlines are unknown, not automatic retries or rollback. Tests use only
synthetic roots and never contact the owner's real keyring.

The explicit isolated provider check is:

```sh
python3 scripts/check_source_store.py
```

It requires the checksum-pinned GNOME Keyring 51.1 peer recorded in that script,
a private D-Bus and a temporary HOME/XDG tree under `target/vault-lab/`. Missing tools
or a different peer fail, not skip. The project-owned `vault_lab` probe rejects an
ordinary desktop environment. The check covers encrypted save/reopen, UUID associations,
confirmed source removal and locked reads without prompting. It does not accept the
real desktop's unlock dialogs, focus/accessibility or NM/Polkit behavior.

The source accepts plain/base64 URI lists, with at most 24 rendered rows per page.
Search/paging preserve original row identity. Failed reload preserves the list.
Retained nodes are labelled after a failed reload. Multi-page lists have controls
above and below the rows; page changes reset the viewport to the top.
No discovery, startup fetching, redirects, automatic refresh, clipboard discovery,
disk cache, subscription history or automatic connection is implemented. Saved NM
profiles remain usable without a subscription. There are no manual protocol fields,
direct secret retrieval or competing desktop secret-agent implementation. Standard
NM agent requests use exact UUID hints through the backend's bounded interactive
handshake; real desktop keyring unlock/prompt acceptance remains incomplete. See
[ADR 0033](../../docs/decisions/0033-persistent-network-lifetime-and-nm-agents.md).
See the [subscription](../../crates/subscription/README.md) and
[NM client](../../crates/nm-client/README.md) contracts.

## Run and verify

```sh
cargo run --locked -p nm-tunnel-cosmic
```

Debian/Ubuntu native UI prerequisites: C linker, pkg-config, libwayland-dev,
libxkbcommon-dev and libfontconfig1-dev. Building the workspace/backend additionally
requires CMake, Clang/libclang and a C/C++ toolchain for BoringSSL and lwIP;
the private-bus tests need dbus-daemon. Use the pinned Rust toolchain and an existing
desktop session. Running does not install
anything or change routes/DNS/firewall. Default size is 1024×840, minimum 520×520,
with bounded content width, scrolling, wrapping names and reflowing metric rows.
The toolkit owns drawer placement. Native input, scaling/theme changes, Polkit and
accessibility need separate acceptance; tests/captured pixels cannot establish them.

Installed builds use `--release --locked`, without `preview`. A new frontend can
observe an existing connection without replacing/restarting the backend.
Launching source does not update the installed package; local snapshot packages
must be rebuilt to include later source changes. The Route icon depicts two endpoints
and a path, not a security guarantee. Interface symbols are embedded and inherit
the native theme even when running from source. The desktop entry uses
`Icon=io.github.nm_tunnel.Cosmic`; packaging installs the original full-color and
symbolic SVGs in the hicolor icon theme. Source builds do not install those assets.

### Synthetic previews

Debug-only `preview` disables real HTTP/NM/telemetry I/O and network actions.
Iced captures only our own window after window-frame readiness, never the desktop.
Generated images go under `target/ui/`, not into source control.
The project README includes one explicitly selected, sanitized own-window capture
under `docs/images/`; its profiles and traffic are labeled synthetic.

```sh
NM_TUNNEL_PREVIEW=traffic NM_TUNNEL_CAPTURE=traffic.png cargo run --locked -p nm-tunnel-cosmic --features preview
NM_TUNNEL_PREVIEW=long NM_TUNNEL_PREVIEW_SIZE=520x680 NM_TUNNEL_CAPTURE=import-narrow.png cargo run --locked -p nm-tunnel-cosmic --features preview
```

The state catalog in `src/preview.rs` covers empty/saved profiles, observed
connection transitions, missing NM/backend, profile and backend drawers, imports
(search/unsupported/added/saving/ambiguous/error/multiple pages), and usage
(missing/error/stale/zero/large/history gaps). It also includes `subscriptions`,
`subscription-review`, `subscription-settings`, `edit`, `edit-invalid`,
`delete-profile` and `delete-active`. Source removal/empty/update results and profile
save/delete/error/uncertain states have separate fixtures in the same catalog.
Fixtures never create actionable NM handles;
preview permits local draft/navigation changes but not saves, Apply or network work.
The primary traffic chart requires one observed Connected profile; transitional,
unknown and multiple-active NM states cannot reuse a live old backend sample there.
Source/list scroll positions are retained separately and scroll messages are bound
to the originating source, not whichever source is open when the event is delivered.
Saved-profile fixtures are display-only projections, never fabricated actionable
NM handles. No fixture claims a verified VPN.
`NM_TUNNEL_PREVIEW_THEME` accepts `dark`, `light`, `dark-hc`, or `light-hc`;
`COSMIC_SCALE` is the toolkit's process-local scale override. Neither changes the
desktop's theme or settings. Captures wait for controlled redraws, not a sleep.
`NM_TUNNEL_PREVIEW_SCROLL=bottom` requests the page's bottom after layout, for
checking pagination/footers without timing-based input automation.
Without a capture filename, the synthetic window stays open. Capture names must
be simple `.png` basenames. Release builds ignore preview variables even with the
feature enabled; normal builds expose no capture command.

## Outstanding native accessibility limits

The pinned toolkit's text-input implementation has no accessibility-node
implementation, and its ordinary keyboard focus traversal does not itself reveal
offscreen controls in a scrollable. Input semantics and keyboard focus visibility
remain acceptance blockers requiring toolkit remediation/native verification, not
claims that enabling the a11y feature makes the UI accessible. Icon actions have
explicit names; repeated row actions include profile-specific descriptions.
Primary navigation restores pane scroll targets; pagination resets the node pane.
Full screen-reader behavior, focus reveal through long lists,
drawer focus entry/restoration and large-text behavior remain unverified.
An isolated Xvfb/private-bus probe with AT-SPI 2.62.1 and python-atspi 2.58.2 found
no application accessibility tree even with `IsEnabled=true`. The pinned AccessKit
Unix adapter listens for the old `ScreenReaderEnabled` property, which that provider
rejects as absent. Installing accessibility tools is therefore not native acceptance.
Synthetic keyboard entry was exercised on a private display, not the user's desktop;
this does not resolve screen-reader registration or offscreen focus visibility.

## Safety

NM owns profiles, activation, normal routes and DNS. UI is unprivileged and never
changes firewall rules; automatic cleanup belongs to backend/recovery service, never
the GUI. There is no second profile database or custom
credential store. Future persistence requires XDG paths and separate secret review.
Keep real URLs, credentials, bodies and identifying node details out of logs/issues/
screenshots. Owned credentials use `secrecy`; messages have redacted Debug. Toolkit,
HTTP/D-Bus buffers, clipboard history and swap are not guaranteed to be zeroized.
