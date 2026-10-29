# Offline NetworkManager VM acceptance

The maintained entry point is `scripts/check_vm.py`. This is explicit native
integration testing, **not** part of `cargo xtask check`, a production installation
tool, full native desktop acceptance, or a promise of complete VPN security. No
host root is needed.

## Isolation and ownership

Each invocation creates a private directory below `target/vm-acceptance/`, a fresh
qcow2 overlay over a checksum-verified standalone image, a read-only payload ISO,
and one owned QEMU process. There is **no QEMU NIC**, user networking, TAP, bridge,
forwarded port, SSH, writable host share or guest-agent command endpoint. Neither
the runner nor guest traffic changes host NM, DNS, routes, firewall or services.
The base image is opened through the overlay, not booted writable. Do not modify
input images/binaries concurrently with a run.

The launcher uses systemd >=256's documented SMBIOS system credentials to mask
only `systemd-networkd-wait-online.service`, `systemd-time-wait-sync.service`
and `systemd-timesyncd.service`
for this boot: an offline VM cannot satisfy external-network/NTP boot waits.
This does not mask NetworkManager, Tunnel, its recovery service or their checks.
NM and actual positive packet probes establish test readiness. See
`systemd-debug-generator(8)`'s `systemd.extra-unit.*` credential contract.
The disposable guest disables distro NM connectivity checking and verifies the
effective D-Bus property. Its physical default retains metric 10: VPN forwarding
must not depend on connectivity-check route penalties. Host NM settings are unchanged.
Guest resolved LLMNR/mDNS discovery is disabled: automatic hostname announcements
on new links would legitimately enter source DNS recognition. Explicit DNS traffic
still exercises the production data plane; packets/events are not filtered out.

Cloud-init boots the one-shot guest entry point from NoCloud media. Authorization
requires root inside QEMU/KVM, a fresh per-run marker matching the VM DMI UUID, and
only loopback before fixture creation. Results flow over a dedicated virtio-serial
port, independent of routing and VPN failure. The host validates the run identity,
limits evidence size and accepts no guest-provided host commands or paths. Guest
results are observations, not remote attestation against a malicious guest image.

Inside the VM, an NM-managed veth connects the client to an internal peer namespace.
All addresses, credentials, certificates and payloads are synthetic. Xray is a
**test peer only**, pinned to the same executable SHA-256 as
`scripts/check_source_peer.py` (26.10.21). It is never a production backend. Its
outbound allowlist contains only the internal echo/DNS addresses. DNS fixtures reuse
dnslib rather than implementing DNS wire parsing. No real subscription/server or
external Internet traffic is used.

The host always terminates/waits its own VM on suite failure, timeout or Ctrl-C;
an unresponsive VM is killed after a second bounded wait. Guest cleanup failures
fail the run, independently of scenario results. No manual firewall-clearing command
is used to make a failed production teardown appear successful. Fault injection uses
pidfds, not an unpinned numeric PID. All observations and native commands have
deadlines; a missing prerequisite/case is failure, never a skipped pass.

Packet capture completion uses a unique experimental-EtherType L2 observation
barrier on the internal veth, after the application probes finish. The barrier
must appear in the dump before tcpdump is stopped; SIGINT alone does not drain
libpcap's kernel ring. The beacon is not an IP socket/mark exception and cannot
substitute for the required positive application/endpoint witnesses. Kernel drops
still fail the run. Cleanup also waits for the backend's terminal lifecycle
acknowledgement: external route/guard absence alone does not mean its cleanup
result has already been consumed.

## Prepared image contract

Supply a trusted **standalone x86_64 Arch qcow2 cloud image** with these packages
already installed: `cloud-init`, `python`, `python-dnslib`, `networkmanager`,
`nftables`, `tcpdump`, `polkit`, `openssl`, `iproute2`, `util-linux`, `dbus`, `systemd`
and the runtime libraries of the supplied binaries. systemd >=256 and D-Bus
ProcessFD support are required.
The full platform scope additionally needs `dnsmasq`, RTC/kernel mem-suspend,
`gnome-keyring`, `cosmic-applets`, `cosmic-comp`, `xorg-server-xvfb`, `gdbus`,
software Mesa/EGL support, X keyboard data and `libxkbcommon-x11`. These are test
image tools, not production Tunnel dependencies. Desktop tests use a fresh private
HOME, session bus and nested compositor inside the guest, never the host desktop.
Cloud-init must discover fresh NoCloud media and run final modules without an
Internet connection. Enable cloud-init at image preparation time. Do not put user
profiles, subscriptions, credentials, custom boot scripts or personal keys in it.
No active VPN, retained guard or preconfigured external network is allowed at boot.

Image preparation is separate from acceptance: in an explicitly authorized
disposable image-building VM, verify the upstream cloud image's signature/hash,
install the above packages, record the exact versions and source image provenance,
then shut it down. The acceptance runner performs **no package download or update**.
An image with a backing file must be flattened offline first, for example:

```sh
qemu-img convert -O qcow2 path/to/build-overlay.qcow2 target/prepared-vm.qcow2
sha256sum target/prepared-vm.qcow2
```

Review/trust that digest before passing it to the runner; computing a digest alone
does not authenticate an image. Reuse the same prepared bytes for comparable runs.
Use a new image/digest to upgrade the test OS deliberately, not a rolling pacman
update during tests. The report records guest kernel/package/dnslib versions.
Prepared synthetic images may retain the published fixture NM profiles
`NMT client contract`, `NMT storage contract`, `nmt-uplink`, `nmt-vm-uplink`;
setup removes only those fixture handles in the disposable clone, not host profiles.

Host prerequisites: Python 3.11+, QEMU (`qemu-system-x86_64`, `qemu-img`),
`genisoimage`, and user access to `/dev/kvm`. No Python host package is required.
`--accel tcg` is an explicit slower alternative, never a silent fallback. The peer
and compiled client/backend must be x86_64 Linux binaries compatible with the guest.

## Build and run

Build as an ordinary user; no service installation or host activation:

```sh
cargo build --locked -p nm-tunnel-service
cargo build --locked -p nm-tunnel-client --example lab_control
cargo build --locked -p nm-tunnel-client --example lab_profiles
python3 scripts/check_vm.py \
  --image target/prepared-vm.qcow2 \
  --image-sha256 REVIEWED_PREPARED_IMAGE_SHA256 \
  --peer target/research/xray-26.10.21/xray \
  --backend target/debug/nm-tunnel-service \
  --client target/debug/examples/lab_control \
  --profiles target/debug/examples/lab_profiles
```

The same commands accept release artifacts. There is no implicit build, download,
sudo, host dependency installation, interactive prompt or arbitrary remote command
option. The default whole-VM deadline is 1200 seconds; explicit `--deadline` accepts
120–1800 seconds. Native operations and readiness have shorter internal bounds.

`--suite full` is the default and requires every declared scenario. Explicit
`core`, `dhcp`, `power`, `desktop`, `soak` and `terminal` scopes permit independent
investigation of platform failures; omitted cases are not counted as passed. The
scope and exact required cases are recorded in the payload/input manifest and
validated by both host and guest. Missing prerequisites still fail their selected
scope, never become a skipped success. The ten-minute soak prints bounded progress
every thirty seconds and compares every returned payload; its UDP flow must then
idle-reap and public active-flow counters must drain.
The `power-soak` and `desktop-soak` compositions isolate post-suspend workload
behavior from desktop-process lifecycle effects without reordering or excluding
cases from `full`. QEMU uses `-no-reboot`: an unexpected guest reset must fail
promptly, not silently boot a new lifetime and wait until the overall deadline.

`--suite platform-power` is a diagnostic control, not a substitute for `power-soak`
or `full`: it bypasses Tunnel installation and peer/network fixture setup, checks
that no Tunnel/COSMIC/keyring/peer process or Tunnel guard exists, performs the
same real deep-S3/RTC cycle and observes the plain guest for 180 seconds. Both
vCPUs must keep scheduling deadline-bounded operations. Periodic kernel-journal
artifacts survive a later reset. The usual image/binary arguments remain required
by the common launcher, but no supplied test binary is executed in this control.
Run it separately with explicit `--accel kvm` and `--accel tcg`; different virtual
CPU models (`host` versus `max`) are recorded, not treated as identical hardware.
`--suite platform-idle` is the matching no-S3 control. `--vcpus 1` is permitted only
for platform diagnostic scopes; normal acceptance keeps the original two CPUs.
Platform diagnostics also record the kernel watchdog trace, worker stack, interrupt
counters and read-only LPC decode registers. They do not acquire `/dev/watchdog`.

An explicit `--qemu PATH --firmware-dir PATH` selects a local emulator candidate
without replacing the installed binary or implicitly substituting its firmware.
The [ICH9 S3 patch](../../patches/qemu-ich9-s3/README.md) and original failing runs
remain distinct from corrected-emulator acceptance. Without these options the
launcher still tests the installed emulator.

The launcher additionally retains bounded local QMP lifecycle/status/vCPU
observations and ICH9 TCO timer/register traces. Its private local monitor accepts
only capability negotiation, `query-status` and `query-cpus-fast`; it never resets,
wakes, pauses or injects commands into the guest. This host-owned diagnostic
endpoint is not a guest-agent command path or an external listener. Emulator
version/hash and host kernel enter the manifest. No watchdog is disabled or
reconfigured by these observations.

`--desktop-agent PATH` explicitly supplies an uninstalled COSMIC applet candidate
only for a scope containing `real-desktop-keyring`. Its checksum enters the input
manifest, and a verified private copy runs in the guest without modifying the
image's packaged executable. Without the flag the packaged applet is always used.
This is not a fixture agent or an automatic replacement of a failing peer. The
[local upstream patch pair](../../patches/cosmic-nm-agent/README.md) has exact source,
license, build and independent-review boundaries.

## Required baseline scenarios

| Scenario | Evidence required |
| --- | --- |
| Baseline paths | Working ordinary IPv4 TCP/UDP/DNS and IPv6, with positive physical packet witnesses before VPN |
| Storage | Real NM persistent save/edit, stale-version rejection, source-override preservation and delete via the existing client example |
| Native traffic | Real TUN TCP payload comparison, UDP size cases and DNS transaction/answer check despite the physical default's metric 10; NM installs both /1 captures; client exit leaves NM active; worker has reduced privilege and the parent's image |
| Physical isolation | Successful proxied traffic and positive endpoint packets; no direct test destinations, physical DNS or test-destination IPv6; capture has zero kernel drops |
| Clean disconnect | Worker exit, TUN disappearance, NM VPN/route removal and guard absence; ordinary IPv4/IPv6 work again |
| Worker/backend crash | SIGKILL exact process; NM/TUN/routes/guards/process cleanup |
| Backend hang | SIGSTOP exact backend; independent watchdog confirms exit and cleanup |
| Recovery restart | SIGKILL helper; systemd restarts it while active session and echo survive |
| Endpoint refusal | Local peer unavailable; protected session remains, no direct fallback; restarting the same peer restores new flow success |
| Active image replacement | Atomic installed-image replacement preserves active processes/traffic; old backend retires after disconnect; next parent and worker use replacement inode |
| TUN collision | Activation refuses a pre-existing persistent TUN without changing its interface identity, flags or addresses |
| Vision | Native TCP/UDP through the fixed REALITY/Vision peer; endpoint packets and no direct destination/DNS packets |
| Explicit DNS | The selected manual resolver receives actual queries through the tunnel |
| DNS interception | UDP/TCP DNS reaching TUN uses the selected resolver; no physical port-53 traffic |
| LAN modes | Connected-only and all-RFC1918 modes distinguish connected/routed private TCP/UDP; combined mode handles DNS before LAN relays |
| Domain actions | HTTP Host Direct receives independent NM-uplink DNS authorization; Block closes without reaching the echo peer |
| FakeIP | UDP/TCP DNS identity agreement, empty AAAA, actual synthetic-destination TCP/UDP, unknown-owner rejection, stable identity after parent exit/journal reopen |
| Authentication/TLS rejection | Invalid VLESS credential refuses actual flows while the verified transport session remains protected; untrusted TLS/WS endpoint certificates refuse activation and release resources |
| Source DNS rejection | Untrusted DoT/DoH resolver certificates refuse actual Direct flows without alternate DNS/destination traffic; activation remains destination-free |
| Active profile edits | Native save changes the stored profile without replacing active processes or DNS configuration |
| Uplink loss | NM ends the session and cleanup completes; restoring the base network does not reconnect the VPN |
| Preparation cancellation | A paused local peer holds preparation; explicit NM cancellation releases the owned worker/TUN/routes/guards |
| Deployed bus boundary | The dedicated unprivileged UID can observe telemetry/recovery but cannot call Disconnect; rejection leaves the session unchanged |
| Current-network DNS | Activation makes no resolver/destination request; real DNS uses the selected NM uplink resolver and TCP still forwards through the proxy |
| Traffic telemetry | The unprivileged public client observes fresh nonzero TCP/UDP/TUN counters and bounded history after actual packet traffic |
| Source DNS/routes | Complete native UDP/TCP DNS with Direct/Proxy resolver detours, persistent FakeIP TCP/UDP Proxy/Direct forwarding, fresh peer-confirmed original TCP/XUDP names, Block/sniff/BitTorrent rejection and declared physical packet predicates |
| Endpoint-only health | Initial activation and a fresh periodic endpoint handshake generate no DNS/application-peer events, even with an untrusted resolver; session protection remains active |
| Persistent uplink/source recovery | Loss of one physical NM uplink retains the active session, guard and TUN identity; a second device/resolver gets fresh endpoint bootstrap, traffic and stable FakeIP; source routes and Direct DNS authority rebuild; explicit Disconnect cancels waiting without later reactivation |
| Desktop secret-agent flow | A registered synthetic standard NM agent receives the exact UUID hint; Agent and Ask modes carry real traffic without system credential persistence; user cancellation and absent-agent failure leave no session resources |
| Real DHCP lease recovery | dnsmasq supplies a new address, router and DNS to NM's internal DHCP client without editing/reapplying the client profile; the persistent VPN retains TUN/FakeIP and bootstraps through the new resolver/source address |
| Kernel suspend/resume | systemd/logind suspends the guest kernel, RTC wakes it, the kernel success counter and BOOTTIME/MONOTONIC gap witness real sleep; the same admitted session/TUN and real TCP/UDP traffic survive |
| Genuine desktop keyring | The packaged COSMIC applet (or an explicitly supplied, identified candidate) and GNOME Keyring, not a fixture NM agent, must save through NM, reopen their processes and carry TUN traffic; lack of real persistence is failure |
| Steady traffic | Two TCP streams and one UDP association carry compared payloads for ten minutes, including periodic endpoint health; a zero-drop full-window physical capture and public flow draining are required; memory/FD observations are retained without claiming a capacity benchmark |
| Persistent terminal policy | Ordinary network loss retains protection, then pidfd-targeted backend SIGKILL ends the session and independent recovery removes protection; ordinary unprotected echo succeeds, explicitly witnessing the current crash-policy boundary |

An unrelated sentinel nft table must remain unchanged after every scenario. Cases
run in declared order, stop at first failure and never fabricate downstream results.
Adding a case requires a concrete observable contract, bounded setup/action/cleanup,
and an entry in the shared contract and the scenario owner, not a new plugin layer.

## Evidence and limits

### Current acceptance status

| Scope | Result and boundary |
| --- | --- |
| Core | 35/35 offline cases pass; no real-user desktop or physical-machine acceptance |
| DHCP | Real isolated dnsmasq renewal passes; not arbitrary physical-network DHCP or Wi-Fi roaming |
| S3 on installed QEMU 11.1.2 | Immediate resume passes, sustained post-resume platform control fails with ICH9 TCO reset on KVM and TCG |
| Desktop on packaged COSMIC 1:1.10.0-1 | VPN keyring persistence fails despite an unlocked provider |
| Explicit local candidates | Full 40/40 composition passes with both QEMU and COSMIC/nmrs patches; no host installation or upstream approval |
| Still open | Positive trusted TLS/WebSocket/DoT/DoH, full foreign-document deployment, physical sleep/Wi-Fi, reboot/coexistence, multi-hour load, native prompts/accessibility and independent security review |

`full` means every case in this versioned offline contract, not every product
acceptance category. The passing candidate result does not supersede the installed
component failures or certify a production release. Scope rows are not additive.

### Verified fixtures and component requirements

The core suite's 35-case contract passes offline with NetworkManager 1.58.1-2,
systemd 262.1-1, Linux 7.2.11-arch1-1, dnslib 0.9.26 and the pinned Xray 26.10.21
peer. This includes positive native source-policy UDP/TCP DNS with both resolver
detours, FakeIP TCP/UDP Proxy/Direct traffic and Block rejection. The source UDP
proxy path carries the original name in XUDP; the peer resolves only fixed fixture
hosts. Initial readiness and a fresh periodic endpoint handshake produce no
DNS/application-peer events. All results describe these fixtures, not arbitrary
providers or every supported policy combination.

Additional offline DHCP and kernel suspend/resume scopes pass with dnsmasq 2.93
and the same NM/kernel. The DHCP fixture pins its synthetic client MAC for a
deterministic server reservation and obtains all address/router/DNS changes over
real DHCP. Guest sleep is witnessed by the kernel and RTC; virtual sleep duration
is not a physical machine's wall-clock sleep or Wi-Fi roaming acceptance.
The persistent terminal scope confirms that backend death restores ordinary
networking without VPN even during recovery wait. These isolated results alone do
not establish the expanded composition; its explicit candidate requirements and
full result are recorded below.

The steady-traffic scope also passes: 600 seconds, two retained TCP streams and
one UDP association, 600 compared payload rounds (1,800 exchanges). The complete
physical capture passes the declared egress assertions with no capture drops;
public TCP/UDP active-flow counters drain afterward. Worker FD count is unchanged
in the before/after observations; these two snapshots are not a memory-leak proof
or a throughput/capacity benchmark. Multi-hour load remains unverified.

The genuine desktop scope currently **fails**: COSMIC applet 1:1.10.0-1 registers
with NM, but saving an Agent-owned VPN profile creates no Secret Service item.
The same isolated desktop has a running, unlocked GNOME Keyring 1:51.1-1 and
an available default collection. This is not equivalent to the passing synthetic
agent handshake. Save/reopen, locked-keyring prompts and cancellation therefore
remain unaccepted; new Agent-owned saves must not be presented as verified durable
credential storage on this desktop. No System/plaintext fallback or competing
Tunnel credential agent is introduced to conceal the failure.
Versioned upstream inspection is consistent with the observation: the applet's
[epoch-1.10.0 agent task][cosmic-agent-source] consumes requests/cancellations but
not store events; its locked nmrs 3.5.5
[SaveSecrets implementation][nmrs-agent-source] acknowledges and forwards a store
event rather than writing a keyring itself. This identifies a consumer gap, not
authorization to patch the installed desktop or implement a second VPN store.
The fixture runs as guest root in a private nested desktop to isolate the agent
contract; it does not establish real-user login, Polkit or native input behavior.

With the explicitly supplied local COSMIC/nmrs candidate, the strengthened desktop
scope passes: real Secret Service persistence, no system-keyfile credential,
encrypted-keyring evidence, actual applet/keyring process reopen, NM activation
with real TUN echo, profile deletion removing the stored item, and not-saved policy.
Non-NM Get/Save/Delete/Cancel calls reach the standard interface and are explicitly
refused without keyring mutation. This does not change the packaged applet's
failure or establish locked-keyring prompt input/cancellation and real-user UX.

The original combined full desktop-candidate run **failed**: its core, DHCP, suspend and
desktop cases complete, but the guest unexpectedly reboots early in the following
steady-traffic case. The retained serial stream shows a second GRUB/kernel boot
and an ACPI RTC error at the earlier resume. The overall deadline catches the
missing result. This is not a steady-traffic pass, proof of an applet defect, or
proof of harmless virtualization noise; it required the independent diagnosis
below. Passing isolated scopes does not certify their composition.
The same early termination reproduces in `power-soak` without launching COSMIC,
GNOME Keyring or the candidate at all; the applet patch is not a necessary condition
for this failure. `-no-reboot` now detects it promptly. The shorter power scope
establishes immediate resumed traffic only, not sustained post-resume reliability.
Offline examination of the unchanged failed overlay's original boot journal also
finds `clocksource: Watchdog remote CPU 1 read timed out` after S3. No host/KVM
workaround is applied. Subsequent controls localize the reset to QEMU's ICH9 LPC/PM
reset on S3 wakeup, not to Tunnel or COSMIC: `platform-power` fails under KVM
(`run-_hy53izt`, repeated in `run-xsap8l2h`) and TCG (`run-bc8pid9y`) without
launching any supplied test binary. QMP records `WATCHDOG action=reset`; TCO traces
record two 30-second expiries. A one-vCPU KVM control (`run-ouuhtjin`) also fails,
while no-S3 `platform-idle` (`run-99_kqf5l`) passes all 180 seconds.
Kernel watchdog traces (`run-ea4qznkn`) show successful pings continuing after S3
without matching device reloads. Read-only LPC snapshots (`run-ycgdu089`) establish
that `PMBASE=0x601`, `ACPI_CTRL=0x80`, `RCBA=0xfed1c001` become `0x1`, `0x0`, `0x0`
on wakeup: the timer runs but its I/O decode disappears. The separate clocksource
warning is not by itself established as the cause of that watchdog reset.
The original installed-emulator composition remains failed; it is not silently
reclassified as passing or replaced with another machine configuration.
The explicit local QEMU candidate preserves LPC/PM state on wakeup without
disabling or reconfiguring the watchdog. Its new qtest fails against the unmodified
emulator, passes with the fix, and checks both keepalive survival and subsequent
watchdog expiry plus ordinary cold reset. All 12 TCO cases and the existing LPC
case pass; this is not a full QEMU regression run. With unchanged guest image and
explicit installed firmware, corrected-emulator `platform-power` survives all
180 post-S3 seconds under KVM (`run-67uzyimp`) and TCG (`run-biybjzbb`).
The final platform-scope reporting path also passes under KVM (`run-jhha0cs0`).
The complementary `desktop-soak` composition passes with the candidate: genuine
keyring save/reopen/delete followed by all 600 seconds of compared TCP/UDP traffic
and public flow draining. This separates the passing desktop lifecycle/workload
path from the reproducing post-S3 failure; it is not full-suite acceptance.

With both explicit local candidates, the complete `full` scope now passes **40/40**
in `target/vm-acceptance/run-vdxk1_vj/`. The original two-vCPU Q35/KVM configuration,
guest image and installed firmware are retained. Core and real-DHCP cases are
followed by real S3/RTC resume, the genuine desktop/keyring lifecycle, all 600
seconds of TCP/UDP traffic (600 rounds, 1,800 compared exchanges), public flow
draining and persistent terminal cleanup. The steady-traffic case takes 660.294
seconds including its subsequent drain assertions. This establishes the declared
offline composition on the corrected emulator, not passing behavior of the
installed QEMU or packaged COSMIC, physical-machine sleep, complete native UX or
the unimplemented acceptance scenarios below. No host package is replaced.

[cosmic-agent-source]: https://github.com/pop-os/cosmic-applets/blob/epoch-1.10.0/cosmic-applet-network/src/app.rs#L940
[nmrs-agent-source]: https://github.com/freedesktop-rs/nmrs/blob/ae2166e0658aadde16b133afa20f7285c5ef2d9d/nmrs/src/agent/iface.rs

Each run retains `manifest.json` (input/payload hashes, image identity, required
cases and selected scope), `result.json`, `events.jsonl`, QEMU command/log, serial console, selected
guest state/journals, peer logs and bounded synthetic packet captures. Files are
private by default. Fixture keys/configuration, NM secrets and FakeIP journals are
not exported as diagnostic artifacts. Retain a failed run for offline examination;
delete its exact directory explicitly when no longer needed. The runner never
removes a previous run or silently resumes an old overlay.
Individual packet artifacts are bounded at 512 KiB, except the complete ten-minute
steady-traffic witness at 4 MiB. Host and guest share these bounds; the aggregate
result channel remains limited to 16 MiB. No ring rotation or truncated-capture pass
is used to fit a longer test into the short-case evidence limit.

The suite uses fixed native profiles built through the public model/client API,
not an importer bypass that writes NM dictionaries or an opaque provider document.
Activation uses the configured endpoint only; see
[ADR 0032](../decisions/0032-destination-free-readiness.md). Positive source-policy
traffic and negative TLS tests are separate contracts. The production library
embeds its trust roots; no root injection, verification bypass or external
networking is enabled by this runner.

The suite does **not** establish complete foreign-document import/deployment, trusted
TLS/WebSocket/DoT/DoH end-to-end operation beyond REALITY, arbitrary source semantics,
simultaneous VPN coexistence, real Wi-Fi/hardware roaming, physical-machine suspend,
long-duration capacity, native accessibility, Polkit interaction, reboot behavior,
or arbitrary provider compatibility. Image replacement tests the runtime boundary,
not an actual pacman transaction or compatibility between arbitrary releases.
Packet absence covers the declared synthetic destinations during bounded capture
windows, not every possible leak or the exact temporal ordering of every crash
packet and guard transaction. These are explicit future acceptance scenarios, not
tests silently treated as passed by the baseline.
