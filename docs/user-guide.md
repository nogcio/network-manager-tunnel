# Experimental COSMIC user workflow

This is an experimental workflow, not a supported daily-driver privacy guarantee.
The backend must already be installed in an explicitly authorized evaluation
environment with a recovery plan. Arch/AUR and local-package limits are in
[installation](installation.md). Do not run the GUI as root. This guide describes
the current source UI; an older installed package may have different controls.

## First connection

1. Open **NetworkManager Tunnel**. It reads saved and active NM metadata; it does
   not fetch a subscription, retrieve VPN credentials or connect automatically.
2. Open **Subscriptions**, choose **Add subscription**, enter a name and HTTPS
   URL in the visible field, then confirm **Add subscription** in the bottom footer.
   The source is checked before it is added; failure creates no profiles.
   URLs are stored through the desktop Secret Service; downloaded nodes stay in
   memory only. Unsupported entries remain visible
   with a safe explanation. Loading performs the requested HTTPS fetch but does not
   save or activate a profile or change routes/DNS.
   **Complete configuration** is selected by default. Only the checked native
   IPv4 subset is accepted: unsupported required FakeIP/DNS/routing or integration
   settings reject the entire import without extracting nodes or trying another format.
   Explicit legacy node-only mode can load share links, but does not preserve the
   provider's global rules; its default is VPN DNS `1.1.1.1` before a separate
   profile override, without source domain/LAN exceptions.
   Do not select it expecting unsupported complete policies to remain effective.
   The approved complete-import boundary excludes foreign mixed listeners,
   Clash API/web UI downloads and cache paths, with explicit disclosure: NM/COSMIC
   supplies native integration instead. This does not discard DNS/FakeIP or routing/
   blocking rules, and does not open unsupported full-policy execution. See
   [ADR 0019](decisions/0019-source-client-integration-exclusions.md).
3. Review/search the source's servers.
   Source URLs and associations are restored from the desktop keyring after restart.
   Locked storage needs **Restore subscriptions** and desktop authorization.
   Unavailable/unconfirmed storage is visibly session-only, never plaintext.
   **Save profile** saves profile settings on disk through NM and delegates
   credentials to the desktop's registered NM secret agent. The import page explains
   this before adding. Agent/keyring availability and prompts belong to the desktop;
   missing storage never selects a silent system-secret fallback. Existing profiles
   retain their storage mode. The subscription
   URL is saved separately through Secret Service, never in NM profile data.
   **DNS and LAN for the next added profile** selects source/default, current-network plain
   IPv4 DNS outside VPN, or one public IPv4 resolver through VPN. CurrentNetwork
   rereads the primary uplink's DNS at activation and stores no DHCP address; it
   does not import OS DoT/IPv6 policy. Invalid choices reject before NM writes.
   Overrides never remove routing rules; legacy TCP-only Direct hostname rules plus
   manual DNS reject. Complete policy independently verifies public Direct answers
   through the selected resolver, without leaking verification to another resolver.
   These choices apply to new profiles or an explicitly confirmed replacement,
   not the current connection. They do not bypass full-configuration admission.
   The default-off **Keep private IPv4 networks outside VPN** option explicitly
   bypasses all RFC1918 destinations using existing physical routes, including
   networks behind the router, outside VPN and hostname rules. Enabled private DNS
   interception takes precedence. IPv6, CGNAT and link-local are excluded; old
   connected-only profiles are not widened automatically. It cannot combine with complete
   native policy, which already supplies ordered non-public Direct actions.
   See [ADR 0024](decisions/0024-private-ipv4-bypass.md); broader native acceptance is pending.
   **Intercept tunnel DNS** is an additional default-off opt-in for IPv4 UDP/TCP
   port 53 reaching TUN, not DoH/DoT or DNS outside the tunnel.
   **Persistent IPv4 FakeIP** additionally requires interception and returns durable
   synthetic A addresses with empty AAAA replies. Turn FakeIP off before disabling
   the interception opt-in. Required source modes, when admitted, are not disabled
   by these optional switches. Protection is installed automatically and removed
   on disconnect or terminal failure. Ordinary networking then resumes without VPN.
   No boot enablement is required.
   Cached FakeIP addresses are not protected outside VPN or after reboot;
   applications may need to retry. See [ADR 0022](decisions/0022-session-scoped-guards.md).
   These options
   do not bypass full-policy admission or recover omitted node-only routing rules.
4. Press **Save profile** on the desired node's row. NM may require standard desktop
   authorization. This
   saves a new profile with autoconnect off; it does not activate it. If disk storage
   is refused, adding fails instead of silently creating a temporary profile.
   Changing source/format or failing a load leaves old nodes visible but disables
   additions until a successful reload. Existing NM profiles remain unchanged.
5. Open **Connections** in the native navigation and press **Connect** on the saved profile's
   row under **Profiles**. An accepted request is not a successful VPN. Wait for the
   status read from NM to become **Connected**. A missing registered backend
   disables Connect; registration alone does not establish compatibility.

NM owns activation, routes and DNS. The backend creates the TUN and runs protocol
processing in an unprivileged worker. It does not launch an external proxy core.
The current policy is IPv4 full-tunnel with explicit IPv6 blocking. Profile DNS
can use VPN or a bounded plain-DNS uplink relay, according to the selected override.
There is no split routing, arbitrary ICMP forwarding or IPv6 tunnel support.
The first version deliberately remains IPv4-only: IPv6 literal VPN endpoints
cannot be added, and a hostname endpoint needs an A record at activation. Nodes
with IPv6 literal endpoints remain visible as unsupported in node-only imports.
The import page and saved details disclose the limitation. IPv6 FakeIP is deferred;
complete import still waits for checked IPv4 DNS/routing translation, without
silently falling back to node-only mode. See [ADR 0017](decisions/0017-ipv4-only-first-version.md).

## Later use and disconnect

The GUI can close without sending Disconnect. Reopen it to observe NM and connect
a saved profile; no subscription reload or secret lookup is necessary. Persistent
profiles are owned by NM rather than an app database. State is refreshed every
three seconds while the GUI is open; **Refresh** appears beside unavailable NM state.

Connections also shows read-only upload/download rates, totals and a 60-second
chart. Stale/missing rates display `—`, not zero. Backend statistics describe the
last observed attempt, not a selected profile: profile information actions show NM
metadata separately. TUN counters are not provider billing or proof of protection.

Connected means the configured server's secure transport and local data plane are
ready, not that every destination or DNS server is reachable. VLESS credentials may
be rejected when actual traffic starts, even after connection succeeds. Tunnel does
not contact a third-party control website or issue DNS test queries on connection
or during endpoint health checks. Configured endpoint hostname bootstrap, explicit
subscription requests and actual application/DNS traffic still use the network.

Press **Disconnect** for the single observed connection. NM performs teardown;
the backend closes its worker/TUN and removes its guard on clean disconnection.
The GUI observes NM state, not private firewall state, so it does not certify
completed cleanup from a method reply. To switch nodes, disconnect explicitly,
then use another saved profile's Connect action. There is no automatic switching,
startup activation, subscription refresh or reconnection loop in the GUI.

Manual protocol editing and a competing Tunnel secret agent are not implemented.
New COSMIC saves use the desktop's standard NM secret agent for credentials. An
available registered agent is required for keyring/prompt handling; there is no
silent system-storage fallback. Existing profiles keep their storage mode.
The real COSMIC applet 1:1.10.0-1 currently fails the isolated keyring-persistence
check: an unlocked keyring receives no item after Agent-owned profile save.
Do not rely on new Agent saves retaining credentials across sessions on this
desktop; registration and the synthetic agent test are not persistence acceptance.
A local COSMIC/nmrs patch candidate passes isolated save/reopen/delete checks;
it does not fix an installed, unpatched desktop automatically. See the
[candidate contract](../patches/cosmic-nm-agent/README.md) before considering deployment.
New profiles also use NM's persistent session lifetime: physical network loss
closes old flows and rebuilds endpoint/DNS/LAN authority while keeping protection.
Waiting has no overall network-loss timeout; explicit Disconnect cancels it and
permits ordinary networking without VPN. This is not a permanent boot guard or
protection against catastrophic backend shutdown. NM may still report Activated
while backend diagnostics report connecting. See
[ADR 0033](decisions/0033-persistent-network-lifetime-and-nm-agents.md).
Settings provides narrow network editing and confirmed deletion through NM.
Removing a subscription does not delete the profiles already saved in NM.
Old session-only profiles are not migrated automatically; re-add them explicitly
to save them permanently. Profiles already lost on restart must be imported again.

The network status applet controls its own VPN symbol (often a key). This is not
the application's desktop icon; recreating profiles does not change that symbol.

## Profile settings and deletion

Choose **Settings** on a saved row. The context shows stored configuration, not
proof of live enforcement. **Edit settings** opens a separate scrollable page;
Cancel and Save remain below the form. Name, DNS and supported LAN/DNS/FakeIP
choices are editable, but protocol fields are not. Required source modes stay locked.
Invalid DNS blocks Save, not Cancel/Back. Saving requires a versioned NM observation
(NM 1.44+) and preserves UUID, permissions, transport, IP settings and credentials.
The running VPN is not restarted; new settings apply on the next connection.

**Delete profile** opens a confirmation. An active profile uses **Disconnect and
delete**: NM disconnection must be observed before deletion is requested. Refusal,
unknown state, changed targets or a 45-second observation deadline stop the sequence
without requesting Delete. The subscription remains. Cancel/Escape before dispatch
writes nothing. NM owns profile/credential removal; native authorization and
concurrent-control acceptance are pending.

## Updating and removing subscriptions

Open a source and choose **Update subscription**. Download failure preserves its
previous servers. The candidate opens a review; **Apply update** is explicit.
When the provider supplies HTTP validators, updates can reuse the last accepted
in-memory document after a matching 304 response. Restarting the app or changing
source/format requires a full response; there is no persistent document cache.
Changed saved servers require explicit matching because names and row order do not
prove stable identity. Only that source's linked profiles can be mapped. Unmapped
and disappeared profiles remain; new servers are not saved automatically.
For an explicitly selected replacement, review distinguishes server/transport/security,
authentication and DNS/routing/protection changes against the previous downloaded
entry. This is not a comparison with locally edited NM settings. If the old document
is unavailable, review says so rather than claiming no changes.

**Provider information** shows optional traffic usage, quota, relative expiry,
suggested name and refresh interval from the accepted response (or the candidate
while reviewing). Values are advisory snapshots, not live local tunnel counters or
verified billing. Missing/invalid values do not mean unlimited. Provider hints never
rename sources, schedule updates or disconnect an expired subscription. They are
not restored between app sessions. Relative expiry depends on the local clock.

Mapped updates keep NM names, UUIDs, permissions, IP settings and compatible network
overrides; required source conflicts reject. Source credentials replace old ones
through NM using the retained credential-storage mode and persistent lifetime.
No VPN restart occurs. Multiple profile
writes are not atomic: a later error reports confirmed earlier changes without
claiming rollback or retrying them. Unknown writes block further profile mutations.

Subscription settings can rename, change the visible URL or remove a source.
A changed URL must pass a fresh check and explicit Apply; failure/cancellation keeps
the previous source and URL. Removing it forgets
its URL and associations from the next confirmed keyring catalog without removing
profiles or disconnecting VPN. Failed persistence leaves changes available for this
session but does not claim the keyring was changed. After restart, explicitly Update
to download servers; no node credentials or lists are cached. A second Tunnel writer
is refused; unknown writes are not automatically retried. See
[ADR 0028](decisions/0028-subscription-url-secret-service.md).

## Errors and automatic network recovery

If a save is not confirmed, the remote write may still have completed. The app
blocks further Add/Edit/Delete/Apply for that app session; inspect NM instead of retrying.
The frontend never retries ambiguous NM writes/control requests. Unknown/unavailable NM state
is shown as such, not as Disconnected or Connected. An accepted activation that
vanishes is reported as failed, not as a successful VPN recovery.

The backend retries initial preparation once within a bounded deadline. Transient
runtime health failures retain the session while probing; fatal failure ends it.
Resources and guards are then cleaned automatically, including by an independent
systemd helper after a backend crash. Ordinary traffic can resume **without VPN**.
If the backend hangs while retaining its bus name, the independent helper expires
its liveness lease, stops that exact process and confirms its exit before cleanup.
The connection summary separately shows observed cleanup/termination/retry progress.
Missing or stale helper status does not prove cleanup; confirmed guard cleanup is
not VPN readiness or a guarantee that NM has already removed its routes.
This is not permanent lockdown or automatic reactivation of another profile.
No manual guard command is required in the normal recovery contract. NM method
completion does not prove cleanup has finished; errors retry instead of being
reported as success. Synthetic legacy IPv4 VM crash/hang cleanup passed; broader
packet/source-policy and helper-restart acceptance remain pending; see
[ADR 0026](decisions/0026-automatic-session-recovery.md).

## Current limits

Live REALITY compatibility remains unresolved. Native authorization/recovery and
longer-running reliability remain product acceptance requirements, not source
publication gates. Complete synthetic name/URL entry passed on a private X11 display,
but AT-SPI registration failed and the pinned toolkit has input-accessibility and
focus-reveal blockers. Sporadic Wayland capture-process SIGSEGV remains unresolved.
Local Arch package build/update and bounded NM VM checks do not establish general
interoperability, desktop prompt/accessibility support or production certification.
Packaging generates notices, but actual outputs still need review.
See the [AUR installation direction](installation.md),
[service contract](../crates/nm-service/README.md) and
[frontend guide](../frontends/cosmic/README.md).
