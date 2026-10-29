"""Real guest lifecycle and packet assertions, using only synthetic fixtures."""
import os
import json
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess

from fixture import IPV6, tcp_echo, udp_dns
from support import (LAB, NAME, PROFILE, Process, activate, active, assert_clean, bus,
                     disconnect, guards_present, owner_pid, run, stop, wait, worker)

class Suite:
    def __init__(self, peers):
        self.peers = peers
        self.handles = []
        self.sentinel = run("nft", "-j", "list", "table", "inet", "nmt_vm_sentinel").stdout

    def pinned(self):
        backend = Process(owner_pid())
        self.handles.append(backend)
        child = worker(backend)
        self.handles.append(child)
        return backend, child

    def unchanged(self):
        if run("nft", "-j", "list", "table", "inet", "nmt_vm_sentinel").stdout != self.sentinel:
            raise RuntimeError("Unrelated firewall table changed")

    def storage(self):
        run(str(LAB / "lab_control"), "storage", timeout=40)
        assert_clean()

    def baseline_paths(self):
        def action():
            tcp_echo()
            tcp_echo(IPV6, 32)
            udp_dns()
        self.capture("baseline", action, protected=False)

    def native_tcp_udp_dns(self):
        env = dict(os.environ, NM_TUNNEL_LAB_PUBLIC_KEY=self.peers.public_key)
        run(str(LAB / "lab_control"), "192.0.2.2", env=env, timeout=65)
        if not active() or guards_present() != {"nm_tunnel"}:
            raise RuntimeError("Client exit ended VPN or guard missing")
        routes = json.loads(run("ip", "-j", "-4", "route", "show").stdout)
        if not any(r.get("dst") == "default" and r.get("dev") == "uplink0"
                   and r.get("metric") == 10 for r in routes):
            raise RuntimeError("Low-metric physical default regression precondition missing")
        for prefix in ["0.0.0.0/1", "128.0.0.0/1"]:
            if not any(r.get("dst") == prefix and r.get("dev") == "nmtun0" for r in routes):
                raise RuntimeError("NM did not install metric-independent VPN capture: " + prefix)
        backend, child = self.pinned()
        if backend.inode != child.inode:
            raise RuntimeError("Parent and worker image mismatch")
        status = dict(line.split(":", 1) for line in Path(f"/proc/{child.pid}/status").read_text().splitlines() if ":" in line)
        if (any(int(value, 16) for value in [status[k].strip() for k in ["CapEff", "CapPrm", "CapInh", "CapAmb"]])
                or status["NoNewPrivs"].strip() != "1" or "0" in status["Uid"].split()):
            raise RuntimeError("Worker privilege reduction missing")
        tcp_echo()
        udp_dns()

    def capture(self, label, action, protected=True, required=None, forbidden=None, interface="uplink0"):
        path = LAB / (label + ".pcap")
        with (LAB / (label + "-capture.log")).open("w") as log:
            child = subprocess.Popen(["tcpdump", "--immediate-mode", "-B", "16384", "-U", "-n", "-i", interface, "-w", str(path)],
                                     stdout=log, stderr=log)
            try:
                def ready():
                    if child.poll() is not None:
                        raise RuntimeError("Packet witness exited")
                    return "listening on" in (LAB / (label + "-capture.log")).read_text()
                wait(ready, 5, "Physical packet witness readiness")
                action()
                # SIGINT does not drain libpcap's kernel ring. A unique L2
                # observation barrier, queued after the completed probes, must
                # reach the dump before we stop it. No fixed drain sleep and no
                # privileged marked-IP bypass are used for this witness.
                marker = os.urandom(4)
                source = bytes.fromhex(Path(f"/sys/class/net/{interface}/address").read_text().strip().replace(":", ""))
                with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x88B5)) as witness:
                    witness.bind((interface, 0))
                    witness.send(b"\xff" * 6 + source + b"\x88\xb5" + marker + bytes(42))
                expression = "ether proto 0x88b5 and ether[14:4] = 0x" + marker.hex()
                def drained():
                    if child.poll() is not None:
                        raise RuntimeError("Packet witness exited before observation barrier")
                    observed = run("tcpdump", "-n", "-r", str(path), "-c", "1", expression, check=False)
                    return observed.returncode == 0 and bool(observed.stdout.strip())
                wait(drained, 5, "Packet capture observation barrier")
            finally:
                if child.poll() is None:
                    child.send_signal(signal.SIGINT)
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        stop(child)
        if child.returncode != 0:
            raise RuntimeError("Packet witness did not exit cleanly")
        if not re.search(r"(?m)^0 packets dropped by kernel$", (LAB / (label + "-capture.log")).read_text()):
            raise RuntimeError("Packet witness dropped traffic or lacks drop statistics")
        def packets(expression):
            return run("tcpdump", "-n", "-r", str(path), expression).stdout.strip()
        if required is not None:
            if not required or forbidden is None:
                raise RuntimeError("Explicit packet contract requires positive and negative predicates")
            for expression in required:
                if not packets(expression):
                    raise RuntimeError("Required packet witness missing: " + expression)
            for expression in forbidden:
                if packets(expression):
                    raise RuntimeError("Forbidden packet witness: " + expression)
        elif protected:
            if not packets("tcp and dst host 192.0.2.2 and dst port 24444"):
                raise RuntimeError("No positive endpoint traffic witness")
            if packets("dst net 198.51.100.0/24 or dst net 198.18.0.0/15 or (ip6 and dst host 2001:db8::10) or dst port 53"):
                raise RuntimeError("Forbidden destination/DNS/IPv6 traffic on physical uplink")
        else:
            for expression in ["tcp and dst host 198.51.100.10", "udp and dst host 198.51.100.10",
                               "ip6 and dst host 2001:db8::10", "dst port 53"]:
                if not packets(expression):
                    raise RuntimeError("Baseline packet witness missing: " + expression)
        (LAB / (label + "-packets.txt")).write_text(packets("ip or ip6") + "\n")

    def physical_isolation(self):
        def action():
            tcp_echo()
            udp_dns()
            try:
                tcp_echo(IPV6, 32)
            except OSError:
                pass
            else:
                raise RuntimeError("IPv6 unexpectedly passed during VPN")
        self.capture("active", action)

    def clean_disconnect(self):
        _, child = self.pinned()
        disconnect()
        assert_clean([child])
        # Positive ordinary-network controls: policy is session-scoped, not lockdown.
        tcp_echo()
        tcp_echo(IPV6, 32)

    def worker_crash(self):
        activate()
        _, child = self.pinned()
        child.send(signal.SIGKILL)
        assert_clean([child])

    def backend_crash(self):
        activate()
        backend, child = self.pinned()
        backend.send(signal.SIGKILL)
        assert_clean([backend, child])

    def backend_hang(self):
        activate()
        backend, child = self.pinned()
        backend.send(signal.SIGSTOP)
        assert_clean([backend, child])

    def recovery_restart(self):
        activate()
        backend, child = self.pinned()
        recovery = Process(owner_pid(NAME + ".Recovery"))
        self.handles.append(recovery)
        recovery.send(signal.SIGKILL)
        wait(lambda: recovery.exited() and owner_pid(NAME + ".Recovery") not in [None, recovery.pid],
             15, "Independent systemd recovery restart")
        if owner_pid() != backend.pid or guards_present() != {"nm_tunnel"}:
            raise RuntimeError("Recovery restart disturbed active session")
        tcp_echo()
        disconnect()
        assert_clean([child])

    def endpoint_refusal(self):
        activate()
        backend, child = self.pinned()
        stop(self.peers.proxy)
        def action():
            try:
                tcp_echo(size=32)
            except OSError:
                pass
            else:
                raise RuntimeError("Unavailable proxy unexpectedly carried traffic")
            if owner_pid() != backend.pid or not active() or guards_present() != {"nm_tunnel"}:
                raise RuntimeError("Endpoint refusal removed session protection")
        self.capture("refused", action)
        self.peers.start_proxy()
        tcp_echo()
        disconnect()
        assert_clean([child])

    def active_image_replacement(self):
        activate()
        backend, child = self.pinned()
        installed = Path("/usr/libexec/nm-tunnel-service")
        replacement = installed.with_suffix(".vm-replacement")
        shutil.copyfile(LAB / "nm-tunnel-service", replacement)
        replacement.chmod(0o755)
        os.replace(replacement, installed)
        inode = installed.stat().st_ino
        if inode == backend.inode:
            raise RuntimeError("Replacement did not change installed image identity")
        tcp_echo()
        udp_dns()
        if backend.exited() or child.exited() or owner_pid() != backend.pid or not active():
            raise RuntimeError("Image replacement disturbed active session")
        disconnect()
        assert_clean([backend, child])
        wait(lambda: bus("NameHasOwner") == "b false", 10, "Replaced backend bus retirement")
        activate()
        fresh, fresh_child = self.pinned()
        if fresh.inode != inode or fresh_child.inode != inode:
            raise RuntimeError("Next activation did not use the new parent/worker image")
        tcp_echo()
        disconnect()
        assert_clean([fresh_child])

    def tun_collision(self):
        run("ip", "tuntap", "add", "dev", "nmtun0", "mode", "tun")
        try:
            run("ip", "addr", "add", "203.0.113.7/32", "dev", "nmtun0")
            run("ip", "link", "set", "nmtun0", "up")
            before = run("ip", "-j", "addr", "show", "dev", "nmtun0").stdout
            result = run("nmcli", "--wait", "55", "connection", "up", "id", PROFILE, timeout=60, check=False)
            if result.returncode == 0:
                raise RuntimeError("Activation adopted an unrelated TUN")
            wait(lambda: not active() and not guards_present(), 15, "Rejected activation cleanup")
            after = run("ip", "-j", "addr", "show", "dev", "nmtun0").stdout
            if before != after:
                raise RuntimeError("Rejected activation changed the unrelated TUN")
        finally:
            run("ip", "tuntap", "del", "dev", "nmtun0", "mode", "tun")
        assert_clean()

    def close(self):
        for handle in self.handles:
            handle.close()
