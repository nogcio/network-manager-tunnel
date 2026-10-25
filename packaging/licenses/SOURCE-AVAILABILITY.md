# Covered-source availability

The generated `cosmic-notices.txt` and `service-notices.txt` list the exact package
versions and Cargo source identities used for each executable. The accompanying
license texts apply to their respective components, not to the entire application.

For the locked MPL-2.0 components, source is available without charge from:

- `libcosmic`, `cosmic-config`, `cosmic-config-derive`, `cosmic-theme`:
  <https://github.com/pop-os/libcosmic/tree/430f3d48a97d8779f9c1985473912e594ccca1ae>.
  Clone that repository at the recorded revision and initialize its submodules
  recursively to retrieve the complete toolkit checkout. Iced's separate MIT
  license is not replaced by the parent toolkit's MPL.
- `cosmic-settings-daemon`:
  <https://github.com/pop-os/dbus-settings-bindings/tree/eed01dd3609e90e3c8cd043656734c500956c793>,
  directory `cosmic-settings-daemon`.
- `option-ext` 0.2.0:
  <https://crates.io/api/v1/crates/option-ext/0.2.0/download>.

The AUR recipe builds these dependency sources without patching them. If a
distributor modifies covered files, it must also make the corresponding modified
source available under MPL-2.0 and update this information. Review these links and
the generated inventory when changing Cargo.lock; this document is not permission
to ship an unrelated future dependency graph under stale source instructions.

The workspace's planned upstream is
<https://github.com/nogcio/network-manager-tunnel>. This names the intended
repository, not a claim that it or an AUR package has already been published.
