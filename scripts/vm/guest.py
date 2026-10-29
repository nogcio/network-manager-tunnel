"""Guest-only acceptance entry point. No host network or SSH control path."""
import argparse
import base64
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import socket
import sys
import time
import traceback

from support import LAB, PROFILE, active, assert_clean, disconnect, guards_present, run
from contract import SUITES, VERSION, packet_limit


class Reporter:
    def __init__(self, token):
        self.token = token
        self.stream = open("/dev/virtio-ports/org.nmtunnel.lab", "w", buffering=1)

    def emit(self, kind, **fields):
        self.stream.write(json.dumps({"version": VERSION, "token": self.token, "kind": kind, **fields}) + "\n")


def authorize(token):
    if os.geteuid() != 0 or run("systemd-detect-virt", "--vm").stdout.strip() not in ["kvm", "qemu"]:
        raise RuntimeError("Disposable QEMU VM required")
    if Path("/sys/class/dmi/id/product_uuid").read_text().strip().lower() != token:
        raise RuntimeError("Per-run VM identity mismatch")
    if Path("/run/nmt-lab-authorized").read_text().strip() != token:
        raise RuntimeError("Per-run guest authorization missing")
    if {name for _, name in socket.if_nameindex()} != {"lo"}:
        raise RuntimeError("Expected an offline VM with no external network interfaces")
    LAB.mkdir(mode=0o700)
    (LAB / "authorized").write_text(token)


def verify_payload(payload):
    manifest = json.loads((payload / "manifest.json").read_text())
    if manifest["version"] != VERSION or manifest["required_cases"] != list(SUITES.get(manifest.get("suite"), ())):
        raise RuntimeError("Host/guest contract mismatch")
    for name, expected in manifest["payload"].items():
        if hashlib.sha256((payload / name).read_bytes()).hexdigest() != expected:
            raise RuntimeError("Payload checksum mismatch: " + name)
    return manifest


def install(payload):
    manifest = verify_payload(payload)
    for binary in ["nm-tunnel-service", "lab_control", "lab_profiles", "xray"]:
        shutil.copyfile(payload / binary, LAB / binary)
        (LAB / binary).chmod(0o755)
    if "desktop_agent" in manifest["inputs"]:
        shutil.copyfile(payload / "cosmic-applet-network", LAB / "cosmic-applet-network")
        (LAB / "cosmic-applet-network").chmod(0o755)
    # The observation probe must be executable by the unprivileged test UID;
    # keep private fixture data in the root-only lab directory instead of
    # weakening that directory's permissions for this one consumer.
    public_probe = Path("/usr/local/libexec/nmt-vm-profiles")
    public_probe.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(LAB / "lab_profiles", public_probe)
    public_probe.chmod(0o755)
    shutil.copyfile(LAB / "nm-tunnel-service", "/usr/libexec/nm-tunnel-service")
    Path("/usr/libexec/nm-tunnel-service").chmod(0o755)
    pairs = [("networkmanager/nm-tunnel.name", "/usr/lib/NetworkManager/VPN/nm-tunnel.name"),
             ("sysusers/nm-tunnel.conf", "/usr/lib/sysusers.d/nm-tunnel.conf")]
    for directory, target in [("dbus", "/usr/share/dbus-1"), ("systemd", "/usr/lib/systemd/system")]:
        for source in (payload / "packaging" / directory).iterdir():
            dest = Path(target)
            if directory == "dbus":
                dest /= "system.d" if source.suffix == ".conf" else "system-services"
            pairs.append((str(source.relative_to(payload / "packaging")), str(dest / source.name)))
    for source, target in pairs:
        Path(target).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(payload / "packaging" / source, target)
        Path(target).chmod(0o644)
    run("systemd-sysusers", "/usr/lib/sysusers.d/nm-tunnel.conf")
    run("systemctl", "daemon-reload")
    run("systemctl", "reload", "dbus")
    # The distribution's NM connectivity URL is unrelated to Tunnel and would
    # generate DNS/HTTP traffic on every synthetic default-route change. Disable
    # that independent service only in this disposable test OS, and verify the
    # effective property instead of filtering its packets out of evidence.
    nm_config = Path("/etc/NetworkManager/conf.d/90-nmt-vm.conf")
    nm_config.parent.mkdir(parents=True, exist_ok=True)
    nm_config.write_text("[connectivity]\nenabled=false\nuri=\ninterval=0\n[main]\nno-auto-default=*\n")
    run("systemctl", "start", "NetworkManager", timeout=30)
    run("nmcli", "general", "reload", "conf")
    connectivity = run("busctl", "--system", "get-property", "org.freedesktop.NetworkManager",
                       "/org/freedesktop/NetworkManager", "org.freedesktop.NetworkManager",
                       "ConnectivityCheckEnabled").stdout.strip()
    if connectivity != "b false":
        raise RuntimeError("Test OS connectivity service is still enabled")
    # New links otherwise trigger resolved's multicast hostname announcements.
    # Source DNS recognition legitimately handles those packets too. Disable
    # unrelated discovery traffic in this fixture OS, not in the VPN data plane.
    resolved_config = Path("/etc/systemd/resolved.conf.d/90-nmt-vm.conf")
    resolved_config.parent.mkdir(parents=True, exist_ok=True)
    resolved_config.write_text("[Resolve]\nLLMNR=no\nMulticastDNS=no\n")
    run("systemctl", "restart", "systemd-resolved", timeout=20)
    for property_name in ["LLMNR", "MulticastDNS"]:
        value = run("busctl", "--system", "get-property", "org.freedesktop.resolve1",
                    "/org/freedesktop/resolve1", "org.freedesktop.resolve1.Manager", property_name).stdout.strip()
        if value != 's "no"':
            raise RuntimeError("Test OS discovery service is still enabled: " + property_name)
    # Prepared images may retain only these published synthetic fixtures from a
    # previous experiment. Delete their NM handles in this disposable clone only.
    if active() or guards_present():
        raise RuntimeError("Prepared image booted an active VPN or retained guards")
    for name in [PROFILE, "NMT storage contract", "nmt-uplink", "nmt-vm-uplink"]:
        exists = run("nmcli", "-g", "connection.uuid", "connection", "show", "id", name, check=False)
        if exists.returncode == 0:
            run("nmcli", "connection", "delete", "uuid", exists.stdout.strip())
    run("nft", "add", "table", "inet", "nmt_vm_sentinel")
    run(str(LAB / "lab_control"), "inspect")


def diagnostics(report):
    commands = {
        "links": ["ip", "-j", "addr"],
        "routes": ["ip", "-j", "route", "show", "table", "all"],
        "guards": ["nft", "-j", "list", "ruleset"],
        "nm-state": ["nmcli", "-t", "-f", "TYPE,STATE", "connection", "show", "--active"],
        "journal": ["journalctl", "-b", "--no-pager", "-n", "160", "-u", "NetworkManager",
                     "-u", "nm-tunnel-guard-recovery", "-u", "dbus"],
        "resolver-journal": ["journalctl", "-b", "--no-pager", "-n", "200", "-u", "systemd-resolved"],
        "power-journal": ["journalctl", "-b", "--no-pager", "-n", "140", "-u", "systemd-logind",
                          "-u", "systemd-suspend", "-u", "systemd-suspend-then-hibernate"],
    }
    for name, command in commands.items():
        try:
            result = run(*command, check=False)
            report.emit("artifact", name=name, text=(result.stdout + result.stderr)[-24000:])
        except Exception as error:
            report.emit("artifact", name=name, text=type(error).__name__)
    if LAB.exists():
        peer_events = LAB / "peer-events.jsonl"
        if peer_events.exists():
            if peer_events.stat().st_size > 256 * 1024:
                raise RuntimeError("Oversized protocol event evidence")
            report.emit("artifact", name="peer-events", text=peer_events.read_text())
        for path in sorted(LAB.glob("*.log")) + sorted(LAB.glob("*-packets.txt")):
            report.emit("artifact", name=path.name, text=path.read_text(errors="replace")[-24000:])
        for path in sorted(LAB.glob("*.pcap")):
            if path.stat().st_size > packet_limit(path.name):
                raise RuntimeError("Oversized packet evidence; refusing truncated success")
            report.emit("packet-artifact", name=path.name, data=base64.b64encode(path.read_bytes()).decode())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--token", required=True)
    parser.add_argument("--payload", type=Path, required=True)
    args = parser.parse_args()
    report = Reporter(args.token)
    results = []
    peers = suite = None
    failed = False
    platform_only = False
    try:
        authorize(args.token)
        manifest = json.loads((args.payload / "manifest.json").read_text())
        cases = SUITES[manifest["suite"]]
        report.emit("booted")
        if manifest["suite"] in ["platform-power", "platform-idle"]:
            platform_only = True
            verify_payload(args.payload)
            report.emit("environment", kernel=run("uname", "-r").stdout.strip(), cases=list(cases))
            from platform_power import observe
            case = cases[0]
            report.emit("started", case=case)
            start = time.monotonic()
            observe(report, manifest["suite"] == "platform-power", manifest["vcpus"])
            result = {"case": case, "status": "passed", "seconds": round(time.monotonic() - start, 3)}
            results.append(result)
            report.emit("case", **result)
        else:
            # Missing native tools/libraries fail setup, never become skipped passes.
            for tool in ["nmcli", "nft", "ip", "openssl", "tcpdump", "busctl", "systemd-sysusers"]:
                if shutil.which(tool) is None:
                    raise RuntimeError("Missing guest prerequisite: " + tool)
            from fixture import Peers
            from scenarios import Suite
            from features import Features
            from source_scenarios import SourceScenarios
            from roaming_scenarios import RoamingScenarios
            from secret_scenarios import SecretScenarios
            from dhcp_scenarios import DhcpScenarios
            from power_scenarios import PowerScenarios
            from desktop_scenarios import DesktopScenarios
            from soak_scenarios import SoakScenarios
            from terminal_scenarios import TerminalScenarios
            report.emit("environment", kernel=run("uname", "-r").stdout.strip(),
                        packages=run("pacman", "-Q", "networkmanager", "nftables", "dbus", "systemd",
                                     "openssl", "tcpdump", "python").stdout,
                        dnslib=importlib.metadata.version("dnslib"), cases=list(cases))
            install(args.payload)
            peers = Peers()
            peers.start()
            suite = Suite(peers)
            features = Features(suite, peers)
            sources = SourceScenarios(features)
            roaming = RoamingScenarios(features)
            secrets = SecretScenarios(features)
            dhcp = DhcpScenarios(features)
            power = PowerScenarios(features, report)
            desktop = DesktopScenarios(features)
            soak = SoakScenarios(features, report)
            terminal = TerminalScenarios(features)
            for name in cases:
                report.emit("started", case=name)
                start = time.monotonic()
                method = name.replace("-", "_")
                owners = [owner for owner in [suite, features, sources, roaming, secrets, dhcp, power, desktop, soak, terminal] if hasattr(owner, method)]
                if len(owners) != 1:
                    raise RuntimeError("Scenario has no unique owner: " + name)
                getattr(owners[0], method)()
                suite.unchanged()
                result = {"case": name, "status": "passed", "seconds": round(time.monotonic() - start, 3)}
                results.append(result)
                report.emit("case", **result)
    except Exception as error:
        failed = True
        report.emit("failure", error=f"{type(error).__name__}: {error}"[:4000], traceback=traceback.format_exc()[-8000:])
    finally:
        # Diagnosis/teardown stages are independent: a failed observation cannot
        # suppress peer termination or turn a cleanup failure into a green suite.
        def cleanup():
            if platform_only:
                from platform_power import assert_plain_guest
                assert_plain_guest()
                return
            if LAB.exists():
                if active():
                    disconnect()
                assert_clean()
        stages = [lambda: diagnostics(report), cleanup]
        if peers:
            stages.append(peers.close)
        if suite:
            stages.append(suite.close)
        for stage in stages:
            try:
                stage()
            except Exception as error:
                failed = True
                report.emit("failure", error=f"Evidence/cleanup: {type(error).__name__}: {error}"[:4000])
        report.emit("summary", status="failed" if failed else "passed", cases=results)
        report.stream.close()
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
