# NetworkManager Tunnel: COSMIC frontend

Native standalone libcosmic app, not a web UI or embedded COSMIC Settings plugin.
Uses system theme/typography, grouped list rows, native controls and the standard
right-hand context drawer. One title and the import action live in the native
window header; there is no second page title or persistent instructional footer.
The wgpu renderer retains upstream software fallback.
There is no custom window chrome or mandatory tray process.

## Connections and traffic

Connections displays NM's observed state, active profile and explicit Disconnect.
Each saved profile has its own Connect and information actions, not radio selection
followed by a distant global button. Search filters names locally, bounded to 128
characters, without secret lookup. Connect requires an observed profile, registered
backend and no active connection for this service. Switching requires explicit
Disconnect first. Unknown NM state is not Disconnected; method acceptance is not
readiness or completed teardown. Closing the app never disconnects.
When disconnected, profiles precede the full graph so Connect stays discoverable
in compact windows. NM refresh belongs beside its unavailable state. Observed
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

## Explicit subscription import

Import subscription opens a separate page. Back/Escape returns to Connections;
Escape first closes an open drawer. There is no permanent subscription-management
sidebar for the single in-memory source.

1. Paste an HTTPS source into the masked field and press **Load subscription**.
   With a retained list, the action is **Reload subscription**.
2. Review/search nodes. Unsupported entries have an explanation, not an Add action.
3. Optionally enable **Remember added profiles**. Off means session-only NM storage;
   on permits NM persistent storage including credentials on disk, not a desktop
   keyring. Consent applies to subsequent additions, not existing profiles.
4. Press **Add profile** on a particular row. Autoconnect stays off; adding never
   connects. Return to Connections to explicitly connect the observed NM profile.

Added rows retain returned NM UUIDs in memory until a successful reload. Successful
NM observations reconcile removed profiles; failed observations preserve markers.
This is not deduplication across subscriptions. Ambiguous saves disable additions
for the app session; navigation, feedback dismissal and refresh do not permit retry.
No writes/requests are retried automatically.
An ambiguous save has one persistent warning across pages, not duplicated banners.

The source accepts plain/base64 URI lists, with at most 24 rendered rows per page.
Search/paging preserve original row identity. Failed reload preserves the list.
Retained nodes are labelled after a failed reload. Multi-page lists have controls
above and below the rows; page changes reset the viewport to the top.
No discovery, startup fetching, redirects, automatic refresh, clipboard discovery,
disk cache, subscription history or automatic connection is implemented. Saved NM
profiles remain usable without a subscription. There are no manual protocol fields,
profile editing/deletion UI, secret retrieval or desktop secret-agent implementation.
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
anything or change routes/DNS/firewall. Default size is 760×780, minimum 520×520,
with bounded content width, scrolling, wrapping names and reflowing metric rows.
The toolkit owns drawer placement. Native input, scaling/theme changes, Polkit and
accessibility need separate acceptance; tests/captured pixels cannot establish them.

Installed builds use `--release --locked`, without `preview`. A new frontend can
observe an existing connection without replacing/restarting the backend.
Launching source does not update the installed package; the owner's experimental
local Arch package currently has an older UI. The Route icon depicts two endpoints
and a path, not a security guarantee. Interface symbols are embedded and inherit
the native theme even when running from source. The desktop entry uses
`Icon=io.github.nm_tunnel.Cosmic`; packaging installs the original full-color and
symbolic SVGs in the hicolor icon theme. Source builds do not install those assets.

### Synthetic previews

Debug-only `preview` disables real HTTP/NM/telemetry I/O and network actions.
Iced captures only our own window after window-frame readiness, never the desktop.
Generated images go under `target/ui/`, not into source control.

```sh
NM_TUNNEL_PREVIEW=traffic NM_TUNNEL_CAPTURE=traffic.png cargo run --locked -p nm-tunnel-cosmic --features preview
NM_TUNNEL_PREVIEW=long NM_TUNNEL_PREVIEW_SIZE=520x680 NM_TUNNEL_CAPTURE=import-narrow.png cargo run --locked -p nm-tunnel-cosmic --features preview
```

The state catalog in `src/preview.rs` covers empty/saved profiles, observed
connection transitions, missing NM/backend, profile and backend drawers, imports
(search/unsupported/added/saving/ambiguous/error/multiple pages), and usage
(missing/error/stale/zero/large/history gaps). Import states open the import page.
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
Page navigation and pagination reset their own scroll targets; entering Import
requests URL focus. Full screen-reader behavior, focus reveal through long lists,
drawer focus entry/restoration and large-text behavior remain unverified.

## Safety

NM owns profiles, activation, normal routes and DNS. UI is unprivileged and never
clears a retained failure guard. There is no second profile database or custom
credential store. Future persistence requires XDG paths and separate secret review.
Keep real URLs, credentials, bodies and identifying node details out of logs/issues/
screenshots. Owned credentials use `secrecy`; messages have redacted Debug. Toolkit,
HTTP/D-Bus buffers, clipboard history and swap are not guaranteed to be zeroized.
