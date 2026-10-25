# ADR 0008: Standard Arch/AUR distribution

Status: accepted owner direction; replaces the custom xtask installer.
Date: 2026-10-25.

## Decision

Use the normal AUR source-package workflow: makepkg builds, pacman installs and
tracks files, and standard Arch hooks register system metadata. Do not maintain a
second Rust/Python/shell installer, duplicate package transaction hooks or invoke
NetworkManager reload/activation during installation.

The initial VCS package is `network-manager-tunnel-git`, sourced from the planned
`nogcio/network-manager-tunnel` GitHub repository. This decision does not claim
either repository has been published. A stable package can follow actual tagged
releases; no invented release URL or source checksum is needed now.

Installed binaries must be locked, optimized release builds, without developer
preview features. Keep the UI unprivileged. NetworkManager directly launches the
plugin; its root supervisor supplies TUN/upstream resources and drops privileges
for the protocol worker. Do not advertise an unused systemd-unit sandbox.

Normal package manager updates/removal preserve NM profiles and do not clear
fail-closed guards. Users explicitly disconnect before replacement and recover any
retained guard before removing the recovery executable.

## Acceptance

Validate packaging by actual makepkg builds, package inspection and authorized
installation/update/removal, not tests of PKGBUILD text or another installer
framework. Complete notices/source availability and runtime/desktop acceptance are
separate from source publication. Commands and current limits are maintained in
[the installation guide](../installation.md).
