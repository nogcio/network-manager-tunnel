# QEMU ICH9 S3 reset candidate

This is a local, unsubmitted emulator fix for offline VM acceptance, not a Tunnel
runtime dependency or a host installation. The installed QEMU remains unchanged.

## Source and license

- Repository: <https://github.com/qemu/qemu>
- Tag: `v11.1.2`
- Commit: `4fc49f46dc95d4a27de2509e7fceb2931e91faeb`
- Patch: `qemu.patch`, including a failure-path regression in the upstream-owned
  `tests/qtest/tco-test.c`.

Original `LICENSE`, `COPYING` and `COPYING.LIB` are retained without alteration.
QEMU as a whole is GPL-2.0; individual file notices remain authoritative. LPC code
retains its permissive notice, the PM implementation has historical LGPL-2.1 and
GPL-2.0-or-later contribution notices, the PM header is LGPL-2.1-or-later, and the
TCO tests retain their GPL-2.0-or-later notice. The workspace license does not
replace these licenses. No emulator binary or firmware is distributed here.

## Demonstrated failure and change

On the unmodified Q35 emulator, real S3/RTC wake resets LPC `PMBASE`, `ACPI_CTRL`
and `RCBA` while the ICH9 TCO timer keeps running. Linux `iTCO_wdt` keeps returning
successful watchdog pings, but the removed I/O decode prevents them reaching the
device. Two 30-second TCO expiries produce QMP `WATCHDOG action=reset`.

The control reproduces without Tunnel, peer, desktop, keyring or network interface
under both KVM and TCG; a one-vCPU contrast also fails. The no-S3 KVM control
survives 180 seconds with continued hardware reloads.

The patch moves PM reset ownership into the LPC reset hold phase and preserves
both LPC and PM state on `RESET_TYPE_WAKEUP`. Ordinary resets still reset these
registers. It does not disable the watchdog, change its timeout/action, remove S3,
or modify the guest kernel or host configuration.

The added qtest fails on the unmodified emulator at the PMBASE preservation
assertion. With the candidate it verifies register/timeout preservation, keepalive
delivery beyond the expiry window, watchdog expiry when keepalives stop, and
ordinary reset restoring default decode registers. Existing TCO and LPC tests also
pass. This is not comprehensive emulator regression or upstream review.

The corrected emulator also passes the full 40-case offline Tunnel composition
with the explicit COSMIC/nmrs candidate (`run-vdxk1_vj`), including ten-minute
post-S3 traffic and terminal cleanup. Plain post-S3 controls pass on KVM and TCG.
The installed-emulator failures remain retained; the correction is not installed
on the host. Acceptance limits remain in the owning VM contract.

## Rebuild and use without installation

Apply `qemu.patch` to a clean checkout of the pinned commit, then configure and
build in that checkout:

```sh
git apply /absolute/path/to/patches/qemu-ich9-s3/qemu.patch
./configure --target-list=x86_64-softmmu --enable-kvm --enable-tcg \
  --disable-docs --disable-gtk --disable-sdl --disable-vnc --disable-spice \
  --disable-curses --disable-opengl --disable-virglrenderer --disable-rutabaga-gfx
ninja -C build -j 8 qemu-system-x86_64 tests/qtest/tco-test tests/qtest/lpc-ich9-test
```

From `build/`, run each test with `QTEST_QEMU_BINARY=./qemu-system-x86_64`:

```sh
env QTEST_QEMU_BINARY=./qemu-system-x86_64 ./tests/qtest/tco-test
env QTEST_QEMU_BINARY=./qemu-system-x86_64 ./tests/qtest/lpc-ich9-test
```

No `make install`, system package replacement or privileged setup is needed.
Configure may download its declared build dependencies into this external checkout;
this is not a new dependency in the Tunnel workspace.

Supply the resulting executable to `scripts/check_vm.py` with explicit
`--qemu /absolute/path/to/build/qemu-system-x86_64 --firmware-dir /usr/share/qemu`
in addition to the ordinary checksum-pinned inputs. The firmware directory must
match the comparison baseline; the manifest records the emulator hash/version,
candidate marker, firmware hashes, accelerator and CPU count. Omitting `--qemu`
continues to exercise the installed, failing baseline. See the
[VM contract](../../docs/testing/vm-acceptance.md) for acceptance limits and results.
