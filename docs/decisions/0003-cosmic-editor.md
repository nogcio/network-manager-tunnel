# ADR 0003: COSMIC-first subscription selector

Status: accepted implementation direction, extended by ADR 0007.
Date: 2026-10-25.

## Context

The owner selected COSMIC first, with a subscription-only workflow rather than manual
protocol fields. Follow COSMIC toolkit and Linux desktop conventions, not a mobile
UI imitation. Subscription URLs must never be discovered, indexed, logged or
fetched automatically. Selection must not imply that a VPN connection is ready.

## Decision

- Use native libcosmic settings/list controls, system theme/spacing/typography,
  standard window and desktop entry. Embed no web UI or foreign core.
- Keep shared profile validation, bounded subscription fetching/decoding and the NM
  client independent of the UI toolkit. There are no manual fields or advanced settings.
- Use `url`, `uuid`, `base64` and `percent-encoding` for standard parsing, `secrecy`
  for owned credential fields, `reqwest` with verified Rustls for explicit HTTPS,
  and `zbus` for NM D-Bus serialization/calls.
- Support VLESS TCP with TLS/REALITY and optional Vision, plus WebSocket with
  verified TLS without Vision. Preserve WS path/query and Host independently of SNI.
  Reject unsupported
  link settings; do not silently strip transports, insecure flags or extensions.
- Never fetch, request secrets, save or activate at startup. Load only the URL the
  user explicitly submits, with no redirects, retries, caches or background refresh.
- Parse bounded plain/base64 URI lists; retain unsupported nodes visibly. A failed
  refresh keeps the previous list, and selection alone performs no NM I/O.
- Explicit preparation defaults to a session NM profile. [ADR 0007](0007-nm-profile-control.md)
  extends this to explicit NM persistent-storage consent and standard NM connection
  control, without automatic activation. Desktop secret agents remain unimplemented.
  Autoconnect is false; Connect requires an observed profile and registered backend.
- Keep GUI unprivileged and leave connections/routing/DNS to NM. No duplicate profile
  database. Future non-secret app persistence follows XDG paths; secrets need their
  own standard Linux storage design, never a casual app JSON config.
- Use `org.freedesktop.NetworkManager.tunnel` as an experimental local service
  identifier, not a claim of public namespace ownership or installed backend support.
- Keep our Rust safe; no FFI/privilege exception is required for this editor.
- Visual design uses a bounded responsive content column and native toolkit controls,
  not fixed-width inputs or a repeated panel for every piece of state. Optional
  debug-only `preview` fixtures may capture the app's own actual rendered window;
  they disable HTTP/NM actions, use only synthetic data, write under `target/ui/`
  and are not compiled into release behavior. No desktop capture or input-injection
  API is introduced. Screenshots prove layout, not complete interaction acceptance.

## Dependencies and review

libcosmic is not published on crates.io. It is pinned to
`430f3d48a97d8779f9c1985473912e594ccca1ae`; its source carries MPL-2.0.
Requested features are winit, wgpu, Tokio, Wayland, D-Bus configuration and accessibility,
without default features. Upstream Wayland dependencies still bring rendering,
X11 clipboard/windowing paths and multiple Git forks. Disabling our own defaults
is not proof these native dependencies disappear.

Cargo.lock identifies the resolved graph. Dependency checks use locked resolution;
there is no separate source-approval gate. Original license evidence and remaining
binary distribution notices are maintained in [dependency review](../dependency-review.md).

## Consequences and acceptance

The app selects subscription nodes and prepares NM profiles. Explicit connection
control requires a registered service; experimental runtime evidence is separate
from native desktop acceptance. A timeout can leave a remotely
completed NM save; further additions are disabled for that app session. Tests use
synthetic lists, not real subscriptions or host mutations.
Native display/input/accessibility, provider compatibility, NM creation and authorization need
separate acceptance. Enabling the toolkit's accessibility feature does not resolve
its missing text-input accessibility nodes or offscreen focus reveal. Current
Connections/row actions, import task and native blockers live in the
[frontend guide](../../frontends/cosmic/README.md).
