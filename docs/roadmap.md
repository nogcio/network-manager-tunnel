# Roadmap and acceptance

Current implementation status lives in the [project README](../README.md).
The service and COSMIC selector are implemented experimentally; this roadmap
describes remaining product work, not gates on publishing their source.
The initial target remains Linux, NetworkManager and VLESS + REALITY + Vision
through existing protocol libraries.

## Protocol and tunnel reliability

- Independently review the [security fixes](security-review.md): the external
  worker/broker/relay shutdown barrier before guard cleanup (SR-01), and safe new
  TUN allocation plus atomic name reservation (SR-02). Local owner-level and
  isolated-kernel regressions pass; deployed packet/coexistence acceptance remains.
  Production review remains incomplete; passing ordinary checks is not approval.
- Deliver the explicitly disclosed
  [IPv4-only first version](decisions/0017-ipv4-only-first-version.md).
  IPv6 endpoints/resolvers/payloads and IPv6 FakeIP are deferred, not prerequisites
  for the first joint test. Keep IPv6 leak blocking; complete import must still
  validate/preserve IPv4 policy and reject settings without a checked interpretation.
- Validate the implemented
  [foreign client exclusions](decisions/0019-source-client-integration-exclusions.md)
  with checked source schemas and disclosure, not arbitrary field omission. Review
  the owner-approved [signature exception](decisions/0021-bittorrent-signature-classifier.md).
- Validate the [bounded complete IPv4 contract](decisions/0020-native-ipv4-source-policy.md)
  against the exact private source and authorized native packet/boot acceptance.
  DNS/FakeIP, ordered actions, UDP/QUIC metadata and XUDP are implemented;
  arbitrary rule sets/general source shapes remain unsupported, not ignored.
  Root source-DNS protocol execution still needs production security review;
  an authorized experimental package installation does not complete that review.
- Validate [DNS overrides](decisions/0011-profile-dns-overrides.md) with real NM/DHCP,
  packet-level isolation, verified readiness and teardown in an authorized disposable
  VM. Validate [checked saved-profile replacement](decisions/0018-checked-profile-replacement.md)
  beyond the passed inactive NM 1.58.1 VM save/edit/stale-version/source-update/delete
  checks, especially active-session isolation, concurrent deletion and desktop Polkit.
  Source-policy selected-resolver Direct authorization needs native validation.
- Validate [connected RFC1918 bypass](decisions/0012-connected-lan-bypass.md) with
  NM route installation/removal, DNS, public/IPv6 isolation and uplink loss. This
  explicit narrow mode does not satisfy full subscription private-IP matching.
- Validate [combined LAN/DNS relays](decisions/0014-intercepted-lan-relays.md) for NM
  route precedence, strict physical blocking and netstack attribution. Broader
  ordered source policy remains work. Validate positive
  [endpoint/Direct relay](decisions/0015-root-owned-endpoint-relays.md) interoperability,
  TUN forwarding isolation and tunneled TCP/UDP DNS. FakeIP needs durable identity;
  default library cache eviction/best-effort persistence is insufficient.
- Resolve live REALITY compatibility. Isolated fork/engine probes
  established synthetic payload and Vision DIRECT behavior, not every provider's
  fingerprint or extension compatibility. See [REALITY research](research/reality-feasibility.md).
- Exercise longer-running TCP/UDP, half-close, bounded buffering, cancellation and
  resource cleanup. Document unsupported UDP/XUDP/mux behavior explicitly.
- Validate session-local health-probe recovery and isolated endpoint-dial refusal
  under sustained traffic. Fatal worker/broker crashes still need an explicit,
  NM-owned reconnection policy with cancellation; automatic terminal cleanup and an
  independent orphan-recovery helper with process-pinned liveness watchdog and
  independent UI progress now exist experimentally. Synthetic legacy IPv4 KVM checks
  passed actual TUN TCP echo, client-independent session lifetime, clean disconnect,
  SIGKILL cleanup and SIGSTOP watchdog cleanup. Broader deployed packet/failure
  coverage and helper-restart races remain required;
  retrying probes is not full automatic reactivation or uplink roaming.
- Extend endpoint-bypass, bootstrap DNS, multiple endpoint IPs, uplink-change,
  suspend/resume and MTU evidence. IPv6 must remain explicitly blocked until
  supported; no silent direct fallback is acceptable.
- Verify fail-closed behavior and idempotent cleanup under broader failure cases,
  including automatic terminal/orphan cleanup and interaction with other VPNs. A default
  route alone is not a kill switch.

The [service contract](../crates/nm-service/README.md) owns runtime limits and VM
acceptance requirements. Disposable scripts/logs under `target/native-acceptance/vm/`
provided the bounded evidence in ADR 0026, not a maintained portable VM test suite.
Local Arch build/package/update success is limited host evidence,
not a replacement for these acceptance categories. Ordinary repository checks
never mutate host networking.

## Profiles and native desktop use

COSMIC is the first frontend. Keep its subscription-first workflow and NM as the
only profile/activation owner. Saved network-setting edits and reviewed replacement
exist, but full native acceptance, a manual protocol editor, automatic schema
migration and desktop secret-agent
integration remain work rather than prerequisites for source release.

- Verify native input, accessibility, error feedback and desktop Polkit prompts on
  the supported COSMIC version. UI state tests and screenshots are insufficient.
  Synthetic complete name/URL keyboard entry passed on private X11; AT-SPI did not
  expose an app tree, and a sporadic Wayland capture-process SIGSEGV remains open.
  The pinned toolkit lacks text-input accessibility nodes and automatic offscreen
  focus reveal; see the
  [frontend blockers](../frontends/cosmic/README.md#outstanding-native-accessibility-limits).
- Exercise applet discovery/activation with the editor closed, credential prompts,
  agent-owned/not-saved/system-stored policies and reboot behavior without exposing
  credentials. Expand service interactive-secrets and error/cancellation coverage.
- Validate automatic ordinary-network restoration after terminal failure, including
  helper restart, cleanup refusal/retry and accurate UI diagnostics. No manual guard
  command is the ordinary contract; see [ADR 0026](decisions/0026-automatic-session-recovery.md).

GTK/libnm and KDE/plasma-nm adapters remain future consumers of shared logic.
Choose supported desktop releases and their editor/authentication ABIs before
implementation; any Rust/native FFI exception requires its own safety design.
See [desktop research](research/networkmanager-desktops.md).

## Distribution and supported releases

Use standard [AUR distribution](installation.md), not a project-specific installer.
Verify native package installation, updates, removal, service lifecycle and reboot
behavior before claiming supported host use. Preserve profiles and never silently
clear a retained guard to complete a package transaction.

Review generated Rust/native/certificate-data notices, supplementary font/lwIP
licenses and covered-source instructions before distributing executables.
[Dependency review](dependency-review.md) retains original license evidence and
coverage limitations. The standard dependency audit passes with
maintenance/duplicate warnings; there is no separate Git-source approval gate.

Hosted CI/branch protection and confidential reporting remain unverified. Before
supported releases, establish supported distributions, release authority, artifact
verification and signing. Source publication alone does not assert these exist.
Do not invent repository URLs, contacts or signing identities as placeholders.

## Later scope and open decisions

- Add protocols only on real demand, evaluating library APIs, extensions, maintenance,
  security and native cost rather than building a generic plugin framework.
- Publish a repository only with owner authorization, and establish minimum
  NM/Plasma/GTK versions. The product name is settled by
  [ADR 0005](decisions/0005-project-name.md).
  The technical service identity is `org.freedesktop.NetworkManager.tunnel`,
  without compatibility aliases; public namespace ownership is not asserted.
- Revisit IPv6 endpoints, payloads, DNS and FakeIP after the IPv4-only milestone;
  retain blocking until their complete runtime/lifecycle acceptance exists.
- Decide production netstack hardening, broader DNS policy and kill-switch
  persistence/ownership with other VPNs.
- Add documentation-site, API or release automation only when real consumers need it.
