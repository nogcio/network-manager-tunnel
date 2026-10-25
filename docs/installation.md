# Arch Linux and AUR

The distribution direction is a normal source-built AUR package,
`network-manager-tunnel-git`, not a custom installer. Upstream source is at
<https://github.com/nogcio/network-manager-tunnel>. The AUR entry is not yet published.

## Build and install

After the AUR entry is published:

```sh
git clone https://aur.archlinux.org/network-manager-tunnel-git.git
cd network-manager-tunnel-git
less PKGBUILD
makepkg -si
```

Build as a regular user. Only pacman installation requests privileges; never run
Cargo or makepkg under sudo. An AUR helper is optional, not part of the application.
Dependencies are listed in the recipe under `packaging/aur/`.

Installed binaries are built with `cargo build --locked --release`, without the
development `preview` feature. The workspace release profile uses optimization
level 3, one codegen unit and thin LTO. Cargo.lock fixes dependency versions/commits;
the AUR recipe owns its build output directory and installs only that build's artifacts.
The UI enables libcosmic's wgpu renderer with the upstream software fallback.

Pacman owns binaries, desktop entry, NM/D-Bus descriptors, worker account metadata,
notices and documentation. Arch's standard transaction hooks handle registration;
there is no custom install script, broad NM/DNS reload, service enablement or
installation-time VPN activation. NetworkManager launches the VPN plugin directly;
there is no separate systemd unit to start or stop.

## Update, remove and recover

Close the app and disconnect this VPN before replacing or removing its executables.
Use normal AUR rebuilds for updates and `sudo pacman -R network-manager-tunnel-git`
for removal. Existing NM profiles and the worker account are preserved; manage
unwanted profiles through NM. No installer owns a second profile database.

An unexpected VPN failure can intentionally retain its output-blocking guard.
Neither package transactions nor the GUI clear it automatically. Explicit recovery
allows direct, unprotected networking:

```sh
sudo /usr/libexec/nm-tunnel-service --clear-guard
```

Do not remove the executable while relying on it for recovery. See
[the user guide](user-guide.md) for profile storage and connection control.

## Current limits

The AUR package is not yet published. The owner reports a working
experimental local Arch installation built from a local source snapshot; that is
not a clean Arch build/install/update/removal or reboot acceptance cycle. The
installed snapshot can lag source frontend changes; launching the source frontend
separately does not update the installed package or backend.

The recipe generates dependency notices and ships supplementary licenses and
covered-source instructions. Review the actual package outputs before distribution;
see [dependency review](dependency-review.md).
The runtime remains experimental: real desktop/Polkit acceptance, long-running
reliability and live REALITY compatibility are not established by package creation.
