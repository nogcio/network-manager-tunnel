# Roadmap and acceptance

Current implementation status lives in the [project README](../README.md).
The service and COSMIC selector are implemented experimentally; this roadmap
describes remaining product work, not gates on publishing their source.
The initial target remains Linux, NetworkManager and VLESS + REALITY + Vision
through existing protocol libraries.

## Protocol and tunnel reliability

- Resolve live REALITY compatibility. Isolated fork/engine probes
  established synthetic payload and Vision DIRECT behavior, not every provider's
  fingerprint or extension compatibility. See [REALITY research](research/reality-feasibility.md).
- Exercise longer-running TCP/UDP, half-close, bounded buffering, cancellation and
  resource cleanup. Document unsupported UDP/XUDP/mux behavior explicitly.
- Extend endpoint-bypass, bootstrap DNS, multiple endpoint IPs, uplink-change,
  suspend/resume and MTU evidence. IPv6 must remain explicitly blocked until
  supported; no silent direct fallback is acceptable.
- Verify fail-closed behavior and idempotent cleanup under broader failure cases,
  including retained-guard ownership and interaction with other VPNs. A default
  route alone is not a kill switch.

The [service contract](../crates/nm-service/README.md) owns runtime limits and VM
acceptance requirements; no automated VM harness is provided. Local Arch success
is limited host evidence,
not a replacement for these acceptance categories. Ordinary repository checks
never mutate host networking.

## Profiles and native desktop use

COSMIC is the first frontend. Keep its subscription-first workflow and NM as the
only profile/activation owner. Saved-profile editing, schema migration and desktop
secret-agent integration remain work rather than prerequisites for source release.

- Verify native input, accessibility, error feedback and desktop Polkit prompts on
  the supported COSMIC version. UI state tests and screenshots are insufficient.
  The pinned toolkit lacks text-input accessibility nodes and automatic offscreen
  focus reveal; see the
  [frontend blockers](../frontends/cosmic/README.md#outstanding-native-accessibility-limits).
- Exercise applet discovery/activation with the editor closed, credential prompts,
  agent-owned/not-saved/system-stored policies and reboot behavior without exposing
  credentials. Expand service interactive-secrets and error/cancellation coverage.
- Provide friendly desktop-authorized recovery without automatically clearing a
  retained network guard.

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
- Decide production netstack hardening, broader DNS/IPv6 policy and kill-switch
  persistence/ownership with other VPNs.
- Add documentation-site, API or release automation only when real consumers need it.
