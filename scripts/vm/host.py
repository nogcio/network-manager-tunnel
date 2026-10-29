"""Own one offline VM, immutable inputs, bounded result channel and host cleanup."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
import uuid

from .contract import MAX_EVENT_BYTES, MAX_EVIDENCE_BYTES, PEER_SHA256, SUITES, VERSION, packet_limit
from .machine_events import MachineEvents


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while data := stream.read(1024 * 1024):
            value.update(data)
    return value.hexdigest()


def checked(*args, **kwargs):
    return subprocess.run(args, check=True, timeout=kwargs.pop("timeout", 30), **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True, help="Standalone prepared Arch cloud image; never modified")
    parser.add_argument("--image-sha256", required=True, help="Explicitly trusted prepared image digest")
    parser.add_argument("--peer", type=Path, required=True, help="Pinned Xray 26.10.21 test executable")
    parser.add_argument("--backend", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True, help="Built nm-tunnel-client lab_control example")
    parser.add_argument("--profiles", type=Path, required=True, help="Built nm-tunnel-client lab_profiles example")
    parser.add_argument("--desktop-agent", type=Path,
                        help="Explicit candidate COSMIC applet for desktop scope only; hash recorded, never installed on host")
    parser.add_argument("--qemu", type=Path, help="Explicit local emulator candidate; never replaces the installed QEMU")
    parser.add_argument("--firmware-dir", type=Path, help="Explicit QEMU data directory; required with a candidate to control firmware provenance")
    parser.add_argument("--accel", choices=["kvm", "tcg"], default="kvm")
    parser.add_argument("--vcpus", type=int, choices=[1, 2], default=2,
                        help="Explicit diagnostic CPU-count contrast; normal acceptance retains two CPUs")
    parser.add_argument("--suite", choices=sorted(SUITES), default="full",
                        help="Explicit verification scope; omitted cases are not reported as passed")
    parser.add_argument("--deadline", type=int, default=1200, help="Whole VM deadline, seconds (120..1800)")
    args = parser.parse_args()
    cases = SUITES[args.suite]
    if args.vcpus != 2 and args.suite not in ["platform-power", "platform-idle"]:
        parser.error("CPU-count contrasts are platform diagnostics, not alternate acceptance configurations")
    if os.geteuid() == 0:
        parser.error("Run as an ordinary user; the runner never needs host root")
    if not 120 <= args.deadline <= 1800 or not re.fullmatch(r"[0-9a-f]{64}", args.image_sha256):
        parser.error("Invalid deadline or image SHA-256")
    for tool in ["qemu-img", "genisoimage"] + ([] if args.qemu else ["qemu-system-x86_64"]):
        if not shutil.which(tool):
            parser.error("Missing prerequisite: " + tool)
    if args.accel == "kvm" and not os.access("/dev/kvm", os.R_OK | os.W_OK):
        parser.error("KVM unavailable; select --accel tcg explicitly if intended")
    inputs = {name: getattr(args, name).resolve(strict=True) for name in ["image", "peer", "backend", "client", "profiles"]}
    inputs["emulator"] = (args.qemu or Path(shutil.which("qemu-system-x86_64"))).resolve(strict=True)
    firmware = args.firmware_dir.resolve(strict=True) if args.firmware_dir else None
    if args.qemu and firmware is None:
        parser.error("--qemu requires an explicit --firmware-dir to avoid an implicit BIOS change")
    if firmware and (not firmware.is_dir() or "," in str(firmware) or not (firmware / "bios-256k.bin").is_file()):
        parser.error("Invalid firmware directory or missing Q35 BIOS")
    if args.desktop_agent:
        if "real-desktop-keyring" not in cases:
            parser.error("--desktop-agent requires a scope containing real-desktop-keyring")
        inputs["desktop_agent"] = args.desktop_agent.resolve(strict=True)
    if any(not path.is_file() or "," in str(path) for path in inputs.values()):
        parser.error("Inputs must be regular files with comma-free paths")
    hashes = {name: digest(path) for name, path in inputs.items()}
    if hashes["image"] != args.image_sha256 or hashes["peer"] != PEER_SHA256:
        parser.error("Prepared image or pinned peer checksum mismatch")
    info = json.loads(checked("qemu-img", "info", "--output=json", str(inputs["image"]), capture_output=True, text=True).stdout)
    if info.get("backing-filename") or info.get("format") != "qcow2":
        parser.error("Prepared image must be standalone qcow2; flatten and verify it first")
    root = Path(__file__).resolve().parents[2]
    output = root / "target/vm-acceptance"
    output.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    directory = Path(tempfile.mkdtemp(prefix="run-", dir=output))
    token = str(uuid.uuid4())
    print("Evidence:", directory, flush=True)
    payload = directory / "seed/payload"
    payload.mkdir(parents=True)
    for name, filename in [("backend", "nm-tunnel-service"), ("client", "lab_control"), ("profiles", "lab_profiles"), ("peer", "xray")]:
        shutil.copyfile(inputs[name], payload / filename)
        if digest(payload / filename) != hashes[name]:
            raise RuntimeError("Input changed while copying: " + name)
    for path in Path(__file__).parent.glob("*.py"):
        if path.name != "host.py":
            shutil.copyfile(path, payload / path.name)
    if "desktop_agent" in inputs:
        shutil.copyfile(inputs["desktop_agent"], payload / "cosmic-applet-network")
        if digest(payload / "cosmic-applet-network") != hashes["desktop_agent"]:
            raise RuntimeError("Desktop candidate changed while copying")
    for directory_name in ["networkmanager", "dbus", "systemd", "sysusers"]:
        shutil.copytree(root / "packaging" / directory_name, payload / "packaging" / directory_name)
    manifest = {"version": VERSION, "token": token, "inputs": hashes, "image_info": info,
                 "accel": args.accel, "vcpus": args.vcpus, "suite": args.suite, "required_cases": list(cases),
                 "payload": {str(p.relative_to(payload)): digest(p) for p in sorted(payload.rglob("*")) if p.is_file()}}
    manifest["emulator"] = {"version": checked(str(inputs["emulator"]), "--version", capture_output=True, text=True).stdout.splitlines()[0],
                            "sha256": hashes["emulator"], "candidate": args.qemu is not None,
                            "host_kernel": os.uname().release}
    if firmware:
        manifest["emulator"]["firmware"] = {"directory": str(firmware),
            "files": {name: digest(firmware / name) for name in ["bios-256k.bin", "kvmvapic.bin"] if (firmware / name).is_file()}}
    manifest["source_revision"] = None
    manifest["source_dirty"] = None
    if shutil.which("git"):
        revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, timeout=5)
        if revision.returncode == 0:
            manifest["source_revision"] = revision.stdout.strip()
            manifest["source_dirty"] = bool(checked("git", "status", "--porcelain", cwd=root, capture_output=True, text=True).stdout)
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (payload / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    seed = directory / "seed"
    (seed / "meta-data").write_text(f"instance-id: {token}\nlocal-hostname: nmt-vm\n")
    # No networking, downloads, SSH keys, host shares or interactive login. The
    # one-shot suite uses only the read-only ISO and outbound result serial port.
    commands = [["mkdir", "-p", "/run/nmt-seed"],
                ["mount", "-o", "ro", "/dev/disk/by-label/cidata", "/run/nmt-seed"],
                ["python3", "/run/nmt-seed/payload/guest.py", "--token", token, "--payload", "/run/nmt-seed/payload"]]
    (seed / "user-data").write_text("#cloud-config\n" + json.dumps({
        "write_files": [{"path": "/run/nmt-lab-authorized", "permissions": "0600", "content": token}],
        "runcmd": commands}) + "\n")
    checked("genisoimage", "-quiet", "-o", str(directory / "seed.iso"), "-V", "cidata", "-J", "-r", str(seed))
    checked("qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", str(inputs["image"]),
            str(directory / "overlay.qcow2"))
    vm = None
    final = None
    error = None
    # Unix sockets have a short path limit; keep this control endpoint in the
    # approved temporary directory, never expose a TCP listener on the host.
    temporary_root = Path("/tmp/opencode") if Path("/tmp/opencode").is_dir() else None
    with tempfile.TemporaryDirectory(prefix="nmt-vm-", dir=temporary_root) as temporary:
        endpoint = str(Path(temporary) / "result.sock")
        with socket.socket(socket.AF_UNIX) as listener, (directory / "qemu.log").open("w") as log, \
                MachineEvents(Path(temporary) / "qmp.sock", directory) as machine:
            listener.bind(endpoint)
            listener.listen(1)
            command = [str(inputs["emulator"]), "-no-user-config", "-nodefaults", "-machine", f"q35,accel={args.accel}",
                       "-cpu", "host" if args.accel == "kvm" else "max", "-smp", str(args.vcpus), "-m", "3072",
                       "-uuid", token, "-display", "none", "-monitor", "none", "-nic", "none", "-no-reboot",
                       "-serial", "file:" + str(directory / "serial.log"),
                       "-drive", f"file={directory / 'overlay.qcow2'},format=qcow2,if=virtio",
                       "-device", "virtio-scsi-pci", "-drive", f"file={directory / 'seed.iso'},format=raw,if=none,id=seed,readonly=on",
                       "-device", "scsi-cd,drive=seed", "-device", "virtio-serial-pci",
                       "-chardev", f"socket,id=result,path={endpoint}",
                        "-device", "virtserialport,chardev=result,name=org.nmtunnel.lab"]
            trace_events = directory / "trace-events"
            trace_events.write_text("tco_timer_reload\ntco_timer_expired\ntco_io_read\ntco_io_write\nich9_cc_read\nich9_cc_write\n")
            command += ["-qmp", f"unix:{machine.endpoint},server=off",
                        "-trace", f"events={trace_events},file={directory / 'qemu-tco.log'}"]
            if firmware:
                command += ["-L", str(firmware)]
            # Supported systemd >=256 boot credentials: these cloud-image wait
            # services require an external network/time server that intentionally
            # does not exist in this topology. Runtime readiness is tested by NM
            # and actual positive packet controls, not network-online.target.
            for unit in ["systemd-networkd-wait-online.service", "systemd-time-wait-sync.service",
                         "systemd-timesyncd.service"]:
                command += ["-smbios", f"type=11,value=io.systemd.credential:systemd.extra-unit.{unit}="]
            (directory / "qemu-command.json").write_text(json.dumps(command, indent=2) + "\n")
            try:
                vm = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
                deadline = time.monotonic() + args.deadline
                listener.settimeout(min(args.deadline, 30))
                channel, _ = listener.accept()
                machine.connect()
                with channel, (directory / "events.jsonl").open("w") as events:
                    buffer = b""
                    total = 0
                    seen = []
                    while final is None:
                        machine.drain()
                        if (directory / "qemu-tco.log").stat().st_size > MachineEvents.LIMIT:
                            raise RuntimeError("Oversized QEMU timer trace")
                        if vm.poll() is not None:
                            raise RuntimeError("QEMU exited before suite completion")
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError("Whole VM deadline")
                        channel.settimeout(min(remaining, 2))
                        try:
                            data = channel.recv(65536)
                        except socket.timeout:
                            continue
                        if not data:
                            raise RuntimeError("Result channel closed before summary")
                        total += len(data)
                        buffer += data
                        if total > MAX_EVIDENCE_BYTES or len(buffer) > MAX_EVENT_BYTES:
                            raise RuntimeError("Oversized guest evidence")
                        while b"\n" in buffer:
                            line, buffer = buffer.split(b"\n", 1)
                            event = json.loads(line)
                            if event.get("token") != token or event.get("version") != VERSION:
                                raise RuntimeError("Guest result identity mismatch")
                            events.write(line.decode() + "\n")
                            events.flush()
                            kind = event.get("kind")
                            if kind == "started":
                                print("RUN ", event["case"], flush=True)
                            elif kind == "progress":
                                if (event.get("case") not in cases or not isinstance(event.get("seconds"), (int, float))
                                        or not 0 <= event["seconds"] <= args.deadline
                                        or not isinstance(event.get("operations"), int) or not 0 <= event["operations"] <= 10**9):
                                    raise RuntimeError("Invalid guest progress")
                                print("PROGRESS", event["case"], f"{event['seconds']}s", f"operations={event['operations']}", flush=True)
                            elif kind == "case":
                                if event["status"] != "passed":
                                    raise RuntimeError("Nonpassing required guest case")
                                seen.append(event["case"])
                                print("PASS", event["case"], f"({event['seconds']}s)", flush=True)
                            elif kind == "failure":
                                print("FAIL", event["error"], flush=True)
                                error = "Guest reported a failure"
                            elif kind == "artifact":
                                name = event["name"]
                                if not re.fullmatch(r"[a-z0-9.-]{1,80}", name):
                                    raise RuntimeError("Invalid artifact name")
                                (directory / ("guest-" + name + ".txt")).write_text(event["text"])
                            elif kind == "packet-artifact":
                                name = event["name"]
                                if not re.fullmatch(r"[a-z0-9-]{1,40}\.pcap", name):
                                    raise RuntimeError("Invalid packet artifact name")
                                packet = base64.b64decode(event["data"], validate=True)
                                if len(packet) > packet_limit(name):
                                    raise RuntimeError("Oversized packet artifact")
                                (directory / ("guest-" + name)).write_bytes(packet)
                            elif kind == "summary":
                                final = event
                                if (event["status"] != "passed" or seen != list(cases)
                                        or [r["case"] for r in event["cases"]] != list(cases)):
                                    raise RuntimeError("Required VM cases failed or missing; no skipped success")
                            elif kind == "environment":
                                if event["cases"] != list(cases):
                                    raise RuntimeError("Guest case contract mismatch")
                                print("Guest kernel:", event["kernel"], flush=True)
                            elif kind == "booted":
                                print("Guest authorized; offline setup started.", flush=True)
                            else:
                                raise RuntimeError("Unknown guest event kind")
            except (Exception, KeyboardInterrupt) as failure:
                error = f"{type(failure).__name__}: {failure}"
                print("FAIL", error, flush=True)
            finally:
                if vm is not None and vm.poll() is None:
                    vm.terminate()
                    try:
                        vm.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        vm.kill()
                        vm.wait(timeout=5)
                try:
                    machine.drain()
                except Exception as failure:
                    if error is None:
                        error = f"QMP evidence: {type(failure).__name__}: {failure}"
                # A writable overlay is retained for offline diagnosis; the base
                # and synthetic private inputs are never modified/deleted.
                base_unchanged = digest(inputs["image"]) == hashes["image"]
                if not base_unchanged:
                    error = "Prepared base image changed during acceptance"
                result = {"status": "failed" if error else "passed", "error": error, "guest": final,
                          "qemu_exit": None if vm is None else vm.returncode, "manifest": "manifest.json",
                          "base_unchanged": base_unchanged}
                (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print("Summary:", "FAIL" if error else f"PASS {len(cases)} required cases (suite {args.suite})", "—", directory, flush=True)
    return int(error is not None)
