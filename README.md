# NetworkManager Tunnel

NetworkManager Tunnel is a Linux VPN application that brings VLESS connections
into NetworkManager, with a native COSMIC interface for importing subscriptions,
connecting saved profiles and viewing traffic.

It is for users who want proxy-based VPN connections managed alongside their other
network connections, rather than by a separate proxy daemon or a mandatory tray app.
NetworkManager stores profiles and controls activation, routes and DNS. The desktop
app can close without disconnecting the VPN.

**Experimental: the COSMIC app and VPN backend are implemented, but there is no
supported stable release yet.** KDE and GTK frontends are planned, not implemented.
This is an independent project, not an official NetworkManager or COSMIC component.

## What you can do now

- Import an HTTPS subscription containing plain or base64-encoded VLESS URI lists.
  Search its nodes, see unsupported entries and add individual profiles to NetworkManager.
- Connect and disconnect saved profiles without loading the subscription again.
  Connections are explicit; importing never connects and autoconnect is off.
- View upload/download rates, totals, a 60-second traffic graph and backend diagnostics.
- Save profiles and credentials to disk in NetworkManager so they survive restart,
  with autoconnect off.

The backend uses Rust protocol libraries, not an external sing-box or Xray process.
The supported configuration model covers VLESS over TCP with TLS or REALITY,
optional Vision, and WebSocket over verified TLS without Vision. Configuration
support is not a guarantee of compatibility with every server.

## Current limits

- The experimental tunnel carries IPv4 TCP/UDP traffic. VPN DNS is currently fixed
  to `1.1.1.1`; IPv6 traffic is blocked rather than tunnelled. Endpoint/uplink changes
  and broader routing/DNS customization are not supported.
- Live REALITY compatibility and long-running reliability remain unresolved.
  Local runtime checks do not establish production security or interoperability.
- An unexpected failure can leave an output-blocking network guard in place.
  The app does not automatically clear it; read the
  [recovery instructions](docs/installation.md#update-remove-and-recover) before testing.
- There is no profile editing UI, automatic subscription refresh, YAML subscription
  support or desktop secret-agent implementation.
- Native keyboard, screen-reader and Polkit acceptance is incomplete. The pinned
  toolkit has known input-accessibility and offscreen-focus limitations; see the
  [frontend guide](frontends/cosmic/README.md#outstanding-native-accessibility-limits).

See the [roadmap](docs/roadmap.md) for remaining reliability, desktop and release work.

## Try it

The intended distribution is a standard Arch Linux/AUR package. A package recipe
exists in [`packaging/aur/`](packaging/aur/), but no public AUR entry or stable release is
available yet. See [installation and recovery](docs/installation.md) for packaging
details and current limits.

To run the frontend from this source checkout, install the
[native build prerequisites](frontends/cosmic/README.md#run-and-verify), then run:

```sh
cargo run --locked -p nm-tunnel-cosmic
```

This starts only the unprivileged UI: it does not install or register the VPN
backend. Connecting requires the backend to be installed and registered with
NetworkManager. Running Cargo does not update an existing installed package.

Open **Import subscription…**, load your source and choose **Add profile** for a
node. Return to Connections to connect it. Subscription URLs and credentials are
sensitive: never include real ones in screenshots, issues or test fixtures.
See the [user guide](docs/user-guide.md) for storage choices and connection behavior.

## Development

The workspace uses the pinned Rust toolchain and locked dependencies. Ordinary
checks require native build libraries and `dbus-daemon`, but no root, live VPN,
running NetworkManager or graphical session:

```sh
cargo xtask check --non-interactive
cargo xtask features --non-interactive
```

Checks print progress and save logs under `target/xtask/logs/`. Passing them does
not verify a live VPN or native desktop accessibility.

- [Contributing](CONTRIBUTING.md) and [repository instructions](AGENTS.md)
- [Architecture and component boundaries](docs/architecture.md)
- [Quality and verification](docs/quality.md)
- [Dependency and license review](docs/dependency-review.md)
- [Full documentation map](docs/README.md)

## License

Workspace code, documentation and original icons: MIT OR Apache-2.0. Adapted Kedra material retains
its attribution; dependency licenses must be reviewed before adoption/distribution.
See [LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE) and
[third-party provenance](docs/third-party.md).
