# Architecture

Current implementation status lives in the [project README](../README.md);
pending product work lives in the [roadmap](roadmap.md).
See [ADR 0001](decisions/0001-foundation.md) for foundational boundaries.

## Objective and non-goals

Build a Linux NetworkManager VPN integration using Rust protocol libraries, with
separate KDE, GTK and COSMIC frontends. The first protocol target is client-side
VLESS + REALITY + Vision. No external sing-box/Xray core is shipped or launched.
Rust application code may depend on native libraries such as BoringSSL; a pure-Rust
transitive graph is not currently a requirement. Native KDE adapters may need C++.

No server implementation, mobile support, generic rule-engine clone, subscription
service, web dashboard or custom dynamic protocol-plugin ABI is in the initial scope.

## Control plane

```text
KDE editor      GTK editor      COSMIC editor      CLI
     \              |                |             /
             shared profile/validation logic
                         |
             NetworkManager settings/activation
                         |
              our NM VPN D-Bus service
                         |
              engine and protocol libraries
```

NetworkManager is the source of truth for connection profiles and activation.
The VPN service owns TUN/runtime resources and reports generic/IP configuration
and lifecycle through the standard VPN API. NM applies normal IP routes and DNS;
the service must not race it with an independent route manager.

The COSMIC editor creates NM profiles and explicitly requests activation through NM.
Existing-profile editing and other desktop frontends remain planned. Editors are
unprivileged and may close while a connection runs. No mandatory tray app or
parallel persisted profile database is introduced. The service exposes a bounded,
read-only usage snapshot/history over a separate D-Bus telemetry interface; only
that observation method is available to ordinary clients. See the
[telemetry contract](../crates/nm-service/README.md#read-only-usage-telemetry).

## Data plane

```text
application → Linux IP stack → TUN
  → userspace TCP/IP → TCP streams / UDP datagrams
  → protocol adapter → transport/security → remote proxy
```

VLESS is a stream/datagram proxy, not arbitrary IP encapsulation. TUN access alone
does not supply userspace TCP termination. The owner-selected pinned `meow-lwip`
provides experimental IPv4 TCP/UDP adaptation in a single-stack worker process;
`netstack-smoltcp 0.2.4` was rejected for an unsound Send implementation.
IPv6 support, longer-running TCP semantics, MTU and performance need evidence.
Do not promise arbitrary ICMP forwarding through VLESS.

The selected library candidates are `meow-proxy` and `meow-transport` through the
[maintained nogcio fork](decisions/0004-maintained-meow-fork.md). The experimental
engine pins a fork revision and uses them as
libraries without their application's config loader, web API, listeners or daemon.
See [research](research/rust-protocol-libraries.md). Our adapters must account for
library-owned dialers, DNS, socket options and Vision raw-passthrough semantics.

The current [stream/datagram engine](../crates/engine/README.md) only wraps host-supplied
connected sockets, checks their approved peer and denies implicit redial. It does not
own TUN or the NM lifecycle. REALITY/Vision payloads have passed
an isolated pinned-peer probe through the shared profile adapter, not a host VPN test.

## Configuration and secrets

- The experimental editor uses `org.freedesktop.NetworkManager.tunnel`.
  The experimental backend owns it when running; public namespace and installation
  paths are not reserved. One service type is intended for multiple protocols.
- `vpn.data`: versioned, validated non-secret protocol/transport parameters.
- `vpn.secrets`: credentials, including VLESS UUID as authentication material.
- NM secret flags and secret agents govern persistence/prompting. Do not bypass
  them by writing directly to KWallet, Secret Service or a custom keyring store.
- Use standard NM IP/routing/DNS settings where possible. No opaque copy of a
  foreign engine's entire JSON/YAML profile as the canonical configuration.
- Model protocol, transport, security and flow separately, validating combinations.
  Vision is not an interchangeable wrapper over every transport.
- Unknown or unsupported security/transport options fail validation, never silently
  downgrade to direct access or weaker protection.

The shared model imports VLESS TCP/TLS/REALITY with optional Vision, plus WebSocket
over verified TLS without Vision. WebSocket path/query, HTTP Host and SNI remain
distinct validated fields and survive conversion to NM settings.
The COSMIC UI loads a single HTTPS URI-list subscription into memory and selects
nodes; it exposes no manual protocol fields. The NM client implements experimental
schema v1 with session-only storage by default and explicit opt-in NM persistent
storage, including system-stored credentials. It reads saved/active metadata without
secret lookup and uses standard NM control APIs. See its
[contract](../crates/nm-client/README.md). There is no stable API,
schema migration, existing-profile editing or desktop secret-agent implementation yet.

## Responsibility and dependency layers

Each package declares `package.metadata.nm-tunnel.layer`. Production dependencies
(including build/optional/target-specific edges) must follow this table:

| Layer | Allowed workspace dependencies | Intended responsibility |
| --- | --- | --- |
| `model` | `model` | Validated configuration, domain errors, import representation |
| `engine` | `model`, `engine` | Packet/stream adaptation, protocol sessions, cancellation |
| `integration` | `model`, `engine`, `integration` | NM VPN service, Linux resource lifecycle |
| `client` | `model`, `client` | Profile editing, NM settings/activation client |
| `frontend` | `model`, `client`, `frontend` | Desktop editors and UI adapters |
| `tooling` | all layers | Repository checks and build/test tools |

The checker covers workspace dependencies; it is not an external-dependency or
privilege sandbox. External toolkit admission still needs review. In particular,
engine code must not acquire GTK/Qt/NM dependencies through third-party features.
Create packages when they have real code/consumers, not to populate this table.

## Lifecycle and safety requirements

1. Validate profile and secret requirements without allocating tunnel resources.
2. Resolve the endpoint using an explicit bootstrap policy before DNS changes.
3. Ensure every upstream/reconnect socket bypasses TUN. The experimental supervisor
   marks and binds IPv4 sockets to the selected uplink; endpoint rotation, IPv6
   endpoints and uplink changes remain unsupported rather than silently redialled.
4. Establish required runtime resources and report configuration in NM API order.
   Design readiness around VLESS's limited authentication acknowledgement semantics;
   opening a TCP socket alone cannot prove the VPN is usable.
5. On cancellation/failure, stop tasks, close sockets/TUN and report state to NM.
   Teardown must be idempotent and leave no stale configuration owned by us.

The experimental [service contract](../crates/nm-service/README.md) implements root
setup/socket brokering, authenticated NM callers and an unprivileged worker.
Synthetic VM probes cover teardown and worker/supervisor crashes; neither these nor
owner-reported local host use establish production hardening. See
[ADR 0006](decisions/0006-experimental-nm-runtime.md).
Workspace Rust still forbids unsafe code; dependency FFI is reviewed separately.

IPv6 must be supported or explicitly prevented from bypassing the tunnel. DNS leak
policy, UDP/XUDP compatibility and kill-switch behavior need distinct acceptance
tests. A default VPN route is not a kill switch. The experimental output guard
drops unmarked physical IPv4 and non-loopback IPv6, and survives unexpected failure;
successful retry or explicit lab recovery controls its ownership.

## Desktop-specific integration

- GTK: libnm VPN editor-plugin ABI; verify GTK version/host and authentication UI.
- KDE: plasma-nm's own plugin API, potentially a thin C++/Qt bridge to Rust logic;
  assess the supported Plasma release and its editor transition before implementation.
- COSMIC: native libcosmic editor initially; embedding in settings requires a
  separately reviewed/upstream integration, not an assumed plugin ABI.

The native COSMIC UI uses libcosmic's system theme, grouped rows and context drawer.
Connections is the primary page, with per-profile controls and read-only traffic
rates/history. A separate import page explicitly adds individual subscription nodes
to NM without activation. Saved profiles, explicit Connect/Disconnect and periodic
NM/usage observation are independent of subscription loading and GUI lifetime.
See [ADR 0007](decisions/0007-nm-profile-control.md). Subscription URLs are sensitive,
masked and memory-only;
there is no duplicate persisted connection database or private keyring. Future local
persistence must follow XDG paths and review secret storage independently. Connection switching,
editor availability and credential prompts remain separate native acceptance
categories; compiling and state tests do not establish desktop compatibility.
