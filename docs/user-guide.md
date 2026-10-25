# Experimental COSMIC user workflow

This is an experimental workflow, not a supported daily-driver privacy guarantee.
The backend must already be installed in an explicitly authorized evaluation
environment with a recovery plan. Arch/AUR and local-package limits are in
[installation](installation.md). Do not run the GUI as root. This guide describes
the current source UI; an older installed package may have different controls.

## First connection

1. Open **NetworkManager Tunnel**. It reads saved and active NM metadata; it does
   not fetch a subscription, retrieve credentials or connect automatically.
2. Open **Import subscription…** in the native header, paste your HTTPS
   subscription into the masked input and press **Load subscription**.
   The URL and downloaded list stay in memory. Unsupported entries remain visible
   with a safe explanation. Loading performs the requested HTTPS fetch but does not
   save or activate a profile or change routes/DNS.
3. Review or search the supported nodes. Storage defaults to **session only**, lost
   when NM restarts. To request persistence, enable **Remember added profiles**.
   This applies to the next added profile and also permits its credentials on disk in NM
   system storage, not a desktop keyring. The subscription URL is never saved.
4. Press **Add profile** on the desired node's row. NM may require standard desktop
   authorization. This
   saves a new profile with autoconnect off; it does not activate it. Changing
   Remember later does not migrate an already saved profile.
5. Return to Connections using Back and press **Connect** on the saved profile's
   row under **Profiles**. An accepted request is not a successful VPN. Wait for the
   status read from NM to become **Connected**. A missing registered backend
   disables Connect; registration alone does not establish compatibility.

NM owns activation, routes and DNS. The backend creates the TUN and runs protocol
processing in an unprivileged worker. It does not launch an external proxy core.
The current policy is IPv4 full-tunnel, tunneled DNS and explicit IPv6 blocking.
There is no split routing, arbitrary ICMP forwarding or IPv6 tunnel support.

## Later use and disconnect

The GUI can close without sending Disconnect. Reopen it to observe NM and connect
a saved profile; no subscription reload or secret lookup is necessary. Persistent
profiles are owned by NM rather than an app database. State is refreshed every
three seconds while the GUI is open; **Refresh** appears beside unavailable NM state.

Connections also shows read-only upload/download rates, totals and a 60-second
chart. Stale/missing rates display `—`, not zero. Backend statistics describe the
last observed attempt, not a selected profile: profile information actions show NM
metadata separately. TUN counters are not provider billing or proof of protection.

Press **Disconnect** for the single observed connection. NM performs teardown;
the backend closes its worker/TUN and removes its guard on clean disconnection.
The GUI observes NM state, not private firewall state, so it does not certify
completed cleanup from a method reply. To switch nodes, disconnect explicitly,
then use another saved profile's Connect action. There is no automatic switching,
startup activation, subscription refresh or reconnection loop in the GUI.

Existing-profile editing, deletion and secret-agent ownership are not implemented.
Use standard NM tools to manage saved profiles when necessary. Revoking a
subscription URL does not delete the profiles already saved in NM.

## Errors and retained network protection

If a save is not confirmed, the remote write may still have completed. The app
blocks further additions for that app session; inspect NM instead of retrying.
Connection requests are never automatically retried. Unknown/unavailable NM state
is shown as such, not as Disconnected or Connected. An accepted activation that
vanishes is reported as failed, with a retained-guard warning.

An activation/worker/service failure can intentionally leave the network guard
closed even when NM shows no active VPN. This prevents an unprotected fallback.
The GUI never clears that guard. In the explicitly authorized evaluation environment,
choose either a successful retry followed by a clean disconnect, or privileged recovery:

```sh
sudo /usr/libexec/nm-tunnel-service --clear-guard
```

Recovery restores the possibility of direct, unprotected traffic; it is not a VPN
reconnect. Do not put this command into automatic failure handling. Friendly
desktop-authorized recovery is still pending.

## Current limits

Live REALITY compatibility remains unresolved. Native authorization/recovery and
longer-running reliability remain product acceptance requirements, not source
publication gates. Native input and accessibility are unverified; the pinned toolkit
has known input-semantics and focus-reveal blockers documented in the frontend guide.
Owner-reported local Arch success is not general interoperability or production
certification. Packaging generates notices, but actual outputs still need review.
See the [AUR installation direction](installation.md),
[service contract](../crates/nm-service/README.md) and
[frontend guide](../frontends/cosmic/README.md).
