# NetworkManager and desktop research

Inspection date: 2026-10-25. This historical source-only research informed the
implemented experimental service and COSMIC frontend. It does not describe current
test coverage; see the [service contract](../../crates/nm-service/README.md) and
[frontend guide](../../frontends/cosmic/README.md).

## NetworkManager

The
[official VPN plugin API](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.VPN.Plugin.html)
is a system D-Bus service contract, separate from the desktop editor.

- Methods include `Connect`, `ConnectInteractive`, `NeedSecrets`, `NewSecrets`
  and `Disconnect`.
- Signals include `StateChanged`, `SecretsRequired`, `Config`, `Ip4Config`,
  `Ip6Config` and `Failure`.
- `Connect` does not allow interactive secret requests; `ConnectInteractive` does.
- Generic config precedes IP configuration. Implement the service contract rather
  than treating `SetConfig` as an unrelated NM route-management client method.
- The
  [OpenVPN service descriptor](https://github.com/NetworkManager/NetworkManager-openvpn/blob/main/nm-openvpn-service.name.in)
  illustrates service identity, executable, editor and auth-dialog registration.

The Rust service uses `zbus` directly. For each supported distribution, verify
registration metadata, activation, D-Bus sender authorization, object path, NM
minimum version and exact config keys against the distribution and source headers.
A successful build does not prove this contract works.

## GTK / GNOME

libnm's VPN editor/plugin interface is a native ABI, not the service D-Bus ABI.
We need a host-compatible editor and potentially an authentication-dialog adapter.
Determine the GTK generation and editor host on supported distributions first.
Using gtk-rs alone does not establish plugin loading or secret-agent compatibility.

## KDE Plasma

plasma-nm uses its own Qt plugin interface. Inspected sources:

- [`VpnUiPlugin`](https://github.com/KDE/plasma-nm/blob/master/libs/editor/vpnuiplugin.h)
  defines editing/auth widgets and import/export hooks.
- [OpenVPN plugin build](https://github.com/KDE/plasma-nm/blob/master/vpn/openvpn/CMakeLists.txt)
  builds a native module installed under `plasma/network/vpn`.
- Current upstream also contains QML editor paths; select a target Plasma release
  before choosing the adapter ABI. Do not promise the inspected master API is stable.

Plan: minimal desktop-specific C++/Qt adapter where required, shared Rust profile
logic behind a narrow reviewed boundary. Workspace Rust currently forbids unsafe;
an FFI design and exception policy must precede implementation.

## COSMIC

The inspected
[VPN settings implementation](https://github.com/pop-os/cosmic-settings/blob/master/cosmic-settings/src/pages/networking/vpn/mod.rs)
lists and activates NM connections, imports OpenVPN/WireGuard profiles and delegates editing through
an external editor helper. Generic VPN handling exists, but there is no demonstrated general-purpose
dynamically loaded libcosmic editor ABI there.

Plan: separate native libcosmic editor sharing NM profiles. Embedded settings
integration is a future upstream/desktop integration task. Listing/activation and
credential prompting for our service still need acceptance tests; known generic
secret-agent behavior must not be assumed to understand arbitrary secret names.

## Separate acceptance categories

For each supported desktop/version, independently verify profile discovery,
activation/deactivation, editor loading/launch, import, secret flags/prompting,
errors, reconnect and operation with the editor closed. Existing system applets
must be tested rather than replaced with a mandatory project tray application.
