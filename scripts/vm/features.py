"""Native profile capabilities: fixed fixtures, protocol evidence, no secret reads."""
from contextlib import contextmanager
import ipaddress
import json
import os
import socket
import struct
import signal

from dnslib import DNSRecord

from fixture import ECHO, tcp_echo, udp_dns
from support import LAB, NAME, active, assert_clean, bus, disconnect, guards_present, owner_pid, release_protection, run, wait


def events():
    path = LAB / "peer-events.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def query(name, *, kind="A", destination="198.18.0.2", tcp=False):
    request = DNSRecord.question(name, kind)
    data = request.pack()
    if tcp:
        with socket.create_connection((destination, 53), timeout=4) as stream:
            stream.settimeout(4)
            stream.sendall(struct.pack("!H", len(data)) + data)
            size = struct.unpack("!H", read_exact(stream, 2))[0]
            if size > 4096:
                raise RuntimeError("Oversized DNS fixture response")
            response = DNSRecord.parse(read_exact(stream, size))
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
            stream.settimeout(4)
            stream.connect((destination, 53))
            stream.send(data)
            response = DNSRecord.parse(stream.recv(4096))
    if response.header.id != request.header.id or response.q != request.q or not response.header.qr:
        raise RuntimeError("Unbound DNS response")
    return response


def read_exact(stream, count):
    result = bytearray()
    while len(result) < count:
        data = stream.recv(count - len(result))
        if not data:
            raise RuntimeError("Truncated DNS frame")
        result.extend(data)
    return result


def udp_echo(address):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.settimeout(4)
        stream.connect((address, 12345))
        payload = b"synthetic native UDP capability"
        stream.send(payload)
        if stream.recv(4096) != payload:
            raise RuntimeError("Native UDP echo mismatch")


def rejected_stream(address, payload):
    # A reset/EOF is refusal. An arbitrary timeout is not evidence of the
    # documented close-the-flow Block action, and must fail the case.
    try:
        with socket.create_connection((address, 12345), timeout=4) as stream:
            stream.settimeout(4)
            stream.sendall(payload)
            if stream.recv(4096):
                raise RuntimeError("Blocked flow returned application data")
    except (ConnectionResetError, BrokenPipeError, ConnectionRefusedError):
        pass


class Features:
    def __init__(self, suite, peers):
        self.suite = suite
        self.peers = peers

    @contextmanager
    def profile(self, mode, *, rejects=False, start=True):
        name = "NMT VM " + mode
        env = dict(os.environ, NM_TUNNEL_LAB_PUBLIC_KEY=self.peers.public_key)
        run(str(LAB / "lab_profiles"), mode, env=env, timeout=20)
        identifier = run("nmcli", "-g", "connection.uuid", "connection", "show", "id", name).stdout.strip()
        try:
            if start:
                result = run("nmcli", "--wait", "55", "connection", "up", "uuid", identifier,
                             timeout=60, check=False)
                if rejects:
                    if result.returncode == 0:
                        raise RuntimeError("Rejected fixture activated: " + mode)
                    release_protection()
                    assert_clean()
                elif result.returncode != 0 or not active() or not guards_present():
                    raise RuntimeError("Fixture activation failed: " + mode + ": " + result.stderr)
            yield identifier
        finally:
            if active():
                disconnect(identifier, "uuid")
            release_protection()
            assert_clean()
            run("nmcli", "connection", "delete", "uuid", identifier)

    def vision_transport(self):
        with self.profile("vision"):
            self.suite.capture("vision", lambda: (tcp_echo(), udp_dns()),
                               required=["tcp and dst port 24449"],
                               forbidden=["dst net 198.51.100.0/24 or dst port 53"])

    def manual_dns(self):
        before = len(events())
        with self.profile("manual-dns"):
            self.suite.capture("manual-dns", lambda: (tcp_echo(), query("manual.fixture.invalid", destination="9.9.9.9")))
            if not any(e["kind"] == "dns" and e["server"] == "9.9.9.9" for e in events()[before:]):
                raise RuntimeError("Explicit resolver was not used")

    def active_profile_isolation(self):
        with self.profile("manual-dns"):
            backend, child = self.suite.pinned()
            before = run("nmcli", "-t", "-f", "IP4.DNS", "device", "show", "nmtun0").stdout
            run(str(LAB / "lab_profiles"), "edit-manual-dns", timeout=20)
            if (not active() or owner_pid() != backend.pid or child.exited()
                    or run("nmcli", "-t", "-f", "IP4.DNS", "device", "show", "nmtun0").stdout != before):
                raise RuntimeError("Saving edits reapplied or restarted an active session")
            tcp_echo()

    def dns_interception(self):
        with self.profile("intercept"):
            def check():
                for tcp in [False, True]:
                    # Interception-only owns DNS reaching TUN. A connected LAN
                    # destination follows its more-specific physical route and
                    # must remain blocked without the explicit combined mode.
                    reply = query("intercept.fixture.invalid", destination="9.9.9.9", tcp=tcp)
                    if not reply.rr or str(reply.rr[0].rdata) != ECHO:
                        raise RuntimeError("Intercepted DNS answer mismatch")
            self.suite.capture("intercept", check)

    def lan(self, mode, routed_direct):
        with self.profile(mode):
            def check():
                for address in ["10.77.0.2", "10.88.0.2"]:
                    tcp_echo(address)
                    udp_echo(address)
                if mode == "combined-lan":
                    query("combined.fixture.invalid", destination="10.77.0.2")
            required = ["dst host 10.77.0.2 and dst port 12345"]
            forbidden = ["ip6 and dst host 2001:db8::10", "dst port 53"]
            if routed_direct:
                required.append("dst host 10.88.0.2 and dst port 12345")
            else:
                required.append("tcp and dst port 24444")
                forbidden.append("dst host 10.88.0.2")
            self.suite.capture(mode, check, required=required, forbidden=forbidden)

    def connected_lan(self):
        self.lan("connected-lan", False)

    def private_lan(self):
        self.lan("private-lan", True)

    def combined_lan(self):
        self.lan("combined-lan", False)

    def domain_rule_actions(self):
        with self.profile("domain-rules"):
            def check():
                tcp_echo(payload=b"GET / HTTP/1.1\r\nHost: direct.fixture.invalid\r\n\r\n")
                before = len(events())
                rejected_stream(ECHO, b"GET / HTTP/1.1\r\nHost: block.fixture.invalid\r\n\r\n")
                if any(e["kind"] == "echo" for e in events()[before:]):
                    raise RuntimeError("Blocked hostname reached an echo peer")
            self.suite.capture("domain-rules", check,
                               required=["dst host 198.51.100.10 and dst port 12345",
                                         "dst host 192.0.2.2 and dst port 53"],
                               # ADR 0010 intentionally revalidates a Direct
                               # name with the selected NM uplink resolver.
                               forbidden=["dst port 53 and not dst host 192.0.2.2"])

    def fakeip_persistence(self):
        identities = []
        with self.profile("fakeip") as identifier:
            for iteration in range(2):
                reply = query("echo.fixture.invalid")
                address = str(reply.rr[0].rdata)
                if ipaddress.ip_address(address) not in ipaddress.ip_network("198.18.0.0/16"):
                    raise RuntimeError("FakeIP allocation escaped its admitted pool")
                identities.append(address)
                if query("echo.fixture.invalid", kind="AAAA").rr:
                    raise RuntimeError("FakeIP published an IPv6 answer")
                if str(query("echo.fixture.invalid", tcp=True).rr[0].rdata) != address:
                    raise RuntimeError("TCP/UDP FakeIP identities differ")
                self.suite.capture("fakeip-" + str(iteration), lambda: (tcp_echo(address), udp_echo(address)))
                before = len(events())
                rejected_stream("198.18.250.250", b"unknown synthetic owner")
                if any(e["kind"] == "echo" for e in events()[before:]):
                    raise RuntimeError("Unknown FakeIP reached an outbound")
                if iteration == 0:
                    backend, child = self.suite.pinned()
                    disconnect(identifier, "uuid")
                    assert_clean([child])
                    # Retire the confirmed-idle parent, so identity reuse depends
                    # on durable journal reopen, not an in-memory allocation.
                    wait(backend.exited, 10, "Idle FakeIP parent exit")
                    wait(lambda: bus("NameHasOwner") == "b false", 10, "FakeIP parent bus release")
                    def recovered():
                        if owner_pid(NAME + ".Recovery") is None:
                            return True
                        return '"cleaned"' in run("busctl", "--system", "--auto-start=no", "call",
                            NAME + ".Recovery", "/org/freedesktop/NetworkManager/tunnel/Recovery",
                            NAME + ".Recovery", "GetStatus").stdout
                    wait(recovered, 10, "Old FakeIP parent lease retired")
                    run("nmcli", "--wait", "55", "connection", "up", "uuid", identifier, timeout=60)
            if identities[0] != identities[1]:
                raise RuntimeError("FakeIP identity changed after session restart")

    def invalid_auth_flow_refusal(self):
        with self.profile("invalid-auth"):
            backend, child = self.suite.pinned()
            before = len(events())
            self.suite.capture("invalid-auth", lambda: rejected_stream(ECHO, b"synthetic rejected credential"))
            if any(e["kind"] == "echo" for e in events()[before:]):
                raise RuntimeError("Rejected VLESS credential reached a destination")
            if backend.exited() or child.exited() or not active() or not guards_present():
                raise RuntimeError("Flow-local authentication failure removed session protection")

    def network_dns(self):
        before = len(events())
        with self.profile("network-dns"):
            if events()[before:]:
                raise RuntimeError("Current-network readiness generated destination/DNS traffic")
            reply = query("network.fixture.invalid")
            if not reply.rr or str(reply.rr[0].rdata) != ECHO:
                raise RuntimeError("Current-network DNS answer mismatch")
            tcp_echo()
            observed = events()[before:]
            dns = [e for e in observed if e["kind"] == "dns"]
            if not dns or any(e["server"] != "192.0.2.2" for e in dns):
                raise RuntimeError("Current-network DNS was absent or fell back to another resolver")
            if any(e["kind"] == "tls-sni" for e in observed):
                raise RuntimeError("Unrequested destination TLS probe")

    def tls_certificate_refusal(self):
        with self.profile("tls-untrusted", rejects=True):
            pass

    def websocket_certificate_refusal(self):
        with self.profile("ws-untrusted", rejects=True):
            pass

    def uplink_loss_retention(self):
        with self.profile("intercept"):
            _, child = self.suite.pinned()
            run("nmcli", "--wait", "20", "connection", "down", "id", "nmt-vm-uplink", timeout=25)
            try:
                wait(lambda: child.exited() and not active(), 55, "Nonpersistent NM uplink loss")
                if guards_present() != {"nm_tunnel"}:
                    raise RuntimeError("Automatic NM deactivation released protection")
            finally:
                run("nmcli", "--wait", "20", "connection", "up", "id", "nmt-vm-uplink", timeout=25)
            # Restoration of the base network is not authorization to reconnect
            # the VPN. A new explicit NM activation remains the control owner.
            if active() or guards_present() != {"nm_tunnel"}:
                raise RuntimeError("Base restoration automatically reactivated the VPN")
            try:
                tcp_echo(size=32)
            except OSError:
                pass
            else:
                raise RuntimeError("Base restoration bypassed retained protection")
            release_protection()
            assert_clean([child])
            tcp_echo()

    def preparation_cancellation(self):
        from pathlib import Path
        with self.profile("intercept", start=False) as identifier:
            self.peers.proxy.send_signal(signal.SIGSTOP)
            try:
                run("nmcli", "--wait", "0", "connection", "up", "uuid", identifier)
                def preparing_worker():
                    pid = owner_pid()
                    if pid is None or not guards_present():
                        return False
                    children = Path(f"/proc/{pid}/task/{pid}/children").read_text().split()
                    return any(Path(f"/proc/{child}/cmdline").read_bytes().endswith(b"--worker\0") for child in children)
                wait(preparing_worker, 8, "Paused-peer preparation owns worker and guard")
                _, child = self.suite.pinned()
                observed = run("nmcli", "-t", "-f", "TYPE,STATE", "connection", "show", "--active").stdout
                if "vpn:activating" not in observed.splitlines():
                    raise RuntimeError("Cancellation did not target pending preparation")
                disconnect(identifier, "uuid")
                assert_clean([child])
            finally:
                if self.peers.proxy.poll() is None:
                    self.peers.proxy.send_signal(signal.SIGCONT)

    def unprivileged_bus_boundary(self):
        with self.profile("intercept"):
            backend, child = self.suite.pinned()
            prefix = ["setpriv", "--reuid=nm-tunnel", "--regid=nm-tunnel", "--clear-groups",
                      "--no-new-privs", "--", "busctl", "--system", "--auto-start=no", "call"]
            path = "/org/freedesktop/NetworkManager/VPN/Plugin"
            for name, target, interface, method in [
                (NAME, path, NAME + ".Telemetry", "GetSnapshot"),
                (NAME + ".Recovery", "/org/freedesktop/NetworkManager/tunnel/Recovery", NAME + ".Recovery", "GetStatus")]:
                run(*prefix, name, target, interface, method)
            refused = run(*prefix, NAME, path, "org.freedesktop.NetworkManager.VPN.Plugin", "Disconnect", check=False)
            if refused.returncode == 0 or "Access denied" not in refused.stderr:
                raise RuntimeError("Unprivileged control was not rejected by deployed bus policy")
            if backend.exited() or child.exited() or owner_pid() != backend.pid or not active():
                raise RuntimeError("Rejected bus request changed session ownership")
            tcp_echo()

    def traffic_telemetry(self):
        with self.profile("intercept"):
            tcp_echo()
            udp_dns()
            run("setpriv", "--reuid=nm-tunnel", "--regid=nm-tunnel", "--clear-groups",
                "--no-new-privs", "--", "/usr/local/libexec/nmt-vm-profiles", "observe-traffic", timeout=12)
