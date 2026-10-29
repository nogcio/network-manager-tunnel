# ADR 0033: Persistent network lifetime and standard NM credential agents

Status: owner-approved network-loss policy; experimental implementation with bounded
offline NM acceptance. Real desktop/network acceptance remains incomplete. No host
installation or existing-profile migration implied.

Additional disposable-VM acceptance verifies real DHCP address/router/DNS changes
and kernel suspend/resume with RTC wake. The genuine COSMIC applet 1:1.10.0-1
registers as an NM agent but the current save test creates no Secret Service item
in unlocked GNOME Keyring 1:51.1-1. Agent persistence and desktop prompts therefore
remain a deployment blocker, not a capability established by the synthetic agent.
An owner-authorized local COSMIC/nmrs patch pair now passes the bounded real-agent
save/reopen/delete VM scope, including not-saved policy and non-NM caller refusal.
It is not installed, published or upstream-approved; locked-provider native prompt
acceptance and independent review remain required. The
[patch contract](../../patches/cosmic-nm-agent/README.md) records exact bases/licenses.
See the [VM contract](../testing/vm-acceptance.md) for scopes and limitations.
The expanded 40-case offline composition passes with explicit local COSMIC/nmrs
and QEMU ICH9 S3 patch candidates, including post-resume ten-minute traffic and
terminal cleanup. Neither candidate is installed on the host; this does not close
physical-network, native prompt/accessibility or independent security acceptance.

## Ownership and recovery

An explicitly persistent NM VPN profile (`vpn.persistent=true`) retains its admitted
NM lifetime across loss/change of the physical uplink. The service reports the
standard `can-persist` capability. There is no competing activation controller,
dispatcher script, autoconnect change or mandatory frontend process. Existing
profiles without the option keep their previous nonpersistent lifetime.

The owner selected waiting without an overall network-recovery deadline. While
waiting/retrying, normal physical traffic remains blocked until an explicit
Disconnect cancels the intent. Each observation and setup still has a deadline;
attempts back off from two to thirty seconds. Failed setup does not silently
release session protection. This is an in-process persistent session, not a
permanent or boot-time kill switch: catastrophic backend/watchdog shutdown retains
the independent terminal-cleanup contract in ADR 0026.

The existing lifecycle checks a fresh, bounded NM physical-primary observation on
its two-second heartbeat. Interface, primary identity, selected IPv4 DNS, addresses
and gateway changes revoke the old capabilities. Source capture additionally
includes the relevant observed route prefixes. Observation uncertainty also revokes
authority rather than retaining a potentially stale uplink snapshot.

Recovery atomically removes physical LAN exceptions, stops the worker and joins
broker, relays and telemetry. The original TUN remains owned and configured by NM.
Every new attempt independently rebuilds endpoint bootstrap, selected resolver,
LAN/source plan and root socket authority from NM. The FakeIP journal reopens
without resetting identities; source DNS caches and old sockets do not migrate.
Application bytes are never replayed. The applied profile is kept memory-only;
editing the saved profile does not change a recovering connection.

The persistent NM session remains activated while its transport capabilities are
being replaced. Backend telemetry reports `connecting` during recovery; NM Active
is not a reachability certificate. Readiness updates use the standard Config and
Ip4Config signals. No fake configuration changes, NM reactivation or private route
writer are used to force an otherwise unchanged TUN configuration through another
activation cycle. Explicit Disconnect owns cancellation and confirmed teardown,
including during backoff or setup.

## Credential ownership

The shared schema exposes explicit creation options using NM's existing secret
flags: system storage (0), agent-owned (1), and not-saved/prompt (2). The VLESS
credential remains exclusively in `vpn.secrets.uuid`. Profiles and credentials are
never moved between modes automatically. Source updates and checked replacement
preserve the existing mode and persistent lifetime.

New COSMIC saves request a persistent lifetime and agent-owned credentials, with
disclosure before save. The existing `save_profile` API keeps legacy defaults;
`save_profile_with_options` has actual COSMIC and VM consumers. Saving does not
activate. It has the same total twenty-second write deadline and indeterminate
outcome semantics; no automatic retry or system-secret fallback is introduced.

The registered desktop NM agent owns keyring/prompt behavior. Tunnel does not
register a competing secret agent or directly access a VPN keyring. COSMIC's
network applet already implements standard VPN agent requests. An absent agent
cannot justify writing an agent-owned credential into NM system storage.

For agent-owned/not-saved profiles with missing credentials, NeedSecrets admits
the interactive handshake instead of provoking an unhinted generic password
prompt. ConnectInteractive validates public configuration and reserves one
credential-request slot before sending standard SecretsRequired with the exact
`uuid` hint. No TUN/worker/socket is created while the slot waits. Only the current
NM unique owner may supply NewSecrets or cancel. Replies must match the independent
NM connection UUID and admitted public configuration. Invalid, stale, other-profile
or late replies cannot replace that intent. A request expires after 120 seconds;
NM/user cancellation also drops it. A valid reply launches the existing checked
preparation path. Noninteractive Connect still requires complete credentials.

This adds no dependency or FFI. Existing locked zbus/Tokio implement the standard
NM interfaces. Reference behavior was inspected in NetworkManager 1.58.0
`src/core/vpn/nm-vpn-connection.c` and `src/core/nm-policy.c`; the desktop agent was
inspected in cosmic-applets revision
`dc252e34fd368a63981633075194e52b3f794f9a`. No upstream source is copied.

## Verification boundaries

Owner tests cover identity/configuration/deadline rejection without modifying the
pending request, secret/data separation, flag encoding and storage-mode/lifetime
preservation on updates. Resource tests exercise old relay closure through both
normal stop and persistent suspension. VM scenarios require retained NM/TUN/FakeIP
ownership, bootstrap on a second physical device/resolver, new traffic and explicit
cancellation without reactivation. A synthetic registered NM agent exercises
hinted credentials, user cancellation, absent-agent failure and absence of system
credential persistence. It is not a real desktop keyring and does not establish
desktop unlock/prompt UX or encrypted-at-rest behavior. Separate scopes verify
real DHCP renewal and guest kernel suspend/resume. Catastrophic backend death
during recovery wait is verified to release protection under the existing policy;
changing that policy still requires owner approval. Real Wi-Fi/hardware roaming,
physical-machine sleep and full desktop acceptance remain open.
