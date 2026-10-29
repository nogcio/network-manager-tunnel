"""Real dnsmasq leases drive NM changes; the client never gets static test edits."""
from pathlib import Path
import subprocess

from features import events, query, udp_echo
from fixture import tcp_echo
from support import LAB, active, guards_present, run, stop, wait


class DhcpServer:
    def __init__(self, mac):
        self.mac = mac
        self.process = None
        self.log = (LAB / "dhcp-server.log").open("w")

    def configure(self, address, gateway, resolver):
        if self.process:
            stop(self.process)
        config = LAB / "dhcp-server.conf"
        config.write_text(
            "port=0\ninterface=peer2\nbind-interfaces\nuser=root\ngroup=root\n"
            "dhcp-authoritative\nlog-dhcp\nlog-facility=-\n"
            f"dhcp-leasefile={LAB / ('dhcp-' + address + '.leases')}\n"
            "dhcp-range=192.0.4.10,192.0.4.60,255.255.255.0,120s\n"
            f"dhcp-host={self.mac},{address}\n"
            f"dhcp-option=option:router,{gateway}\ndhcp-option=option:dns-server,{resolver}\n"
            "dhcp-option-force=option:T1,8\ndhcp-option-force=option:T2,16\n"
        )
        self.process = subprocess.Popen(
            ["ip", "netns", "exec", "nmt-peer", "dnsmasq", "--keep-in-foreground", "--conf-file=" + str(config)],
            stdout=self.log, stderr=self.log,
        )
        def ready():
            if self.process.poll() is not None:
                raise RuntimeError("DHCP fixture exited")
            listeners = run("ip", "netns", "exec", "nmt-peer", "ss", "-H", "-lunp", "sport = :67").stdout
            return f"pid={self.process.pid}," in listeners
        wait(ready, 8, "Owned dnsmasq DHCP server readiness")

    def close(self):
        if self.process:
            stop(self.process)
        self.log.close()


def lease_matches(address, gateway, resolver):
    result = run("nmcli", "-t", "-f", "IP4.ADDRESS,IP4.GATEWAY,IP4.DNS", "device", "show", "uplink2").stdout
    return (address + "/24" in result and "IP4.GATEWAY:" + gateway in result
            and "IP4.DNS[1]:" + resolver in result)


class DhcpScenarios:
    def __init__(self, features):
        self.features = features
        self.suite = features.suite

    def dhcp_lease_recovery(self):
        if not Path("/usr/bin/dnsmasq").is_file():
            raise RuntimeError("Prepared image lacks the required real DHCP peer")
        run("ip", "link", "add", "uplink2", "type", "veth", "peer", "name", "peer2", "netns", "nmt-peer")
        server = DhcpServer(Path("/sys/class/net/uplink2/address").read_text().strip())
        try:
            for address in ["192.0.4.2/24", "192.0.4.3/24"]:
                run("ip", "-n", "nmt-peer", "addr", "add", address, "dev", "peer2")
            run("ip", "-n", "nmt-peer", "link", "set", "peer2", "up")
            server.configure("192.0.4.10", "192.0.4.2", "192.0.2.2")
            run("nmcli", "connection", "add", "type", "ethernet", "ifname", "uplink2",
                "con-name", "nmt-vm-dhcp", "connection.autoconnect", "no", "ipv4.method", "auto",
                "802-3-ethernet.cloned-mac-address", server.mac,
                "ipv4.dhcp-timeout", "30", "ipv4.route-metric", "9", "ipv6.method", "disabled")
            run("nmcli", "--wait", "35", "connection", "up", "id", "nmt-vm-dhcp", timeout=40)
            wait(lambda: lease_matches("192.0.4.10", "192.0.4.2", "192.0.2.2"), 10, "NM observed initial DHCP lease")
            run("nmcli", "--wait", "20", "connection", "down", "id", "nmt-vm-uplink")
            with self.features.profile("roaming"):
                backend, old_worker = self.suite.pinned()
                tun = Path("/sys/class/net/nmtun0/ifindex").read_text()
                identity = str(query("dhcp.fixture.invalid").rr[0].rdata)
                tcp_echo(identity)
                before = len(events())
                def renew():
                    # Restart only the server with a new offer. NM owns its
                    # renewal/NAK/DORA and route/DNS application; no client edit,
                    # reapply, deactivation or fabricated DHCP dictionary.
                    server.configure("192.0.4.20", "192.0.4.3", "10.77.0.2")
                    wait(lambda: lease_matches("192.0.4.20", "192.0.4.3", "10.77.0.2"),
                         95, "Real DHCP changed address, gateway and DNS under VPN protection")
                    wait(old_worker.exited, 15, "DHCP change revoked old flow capabilities")
                    run(str(LAB / "lab_profiles"), "observe-running", timeout=75)
                    if not active() or guards_present() != {"nm_tunnel", "nm_tunnel_fakeip"}:
                        raise RuntimeError("DHCP change released session protection")
                    if backend.exited() or Path("/sys/class/net/nmtun0/ifindex").read_text() != tun:
                        raise RuntimeError("DHCP recovery replaced the admitted parent/TUN")
                    if str(query("dhcp.fixture.invalid").rr[0].rdata) != identity:
                        raise RuntimeError("DHCP recovery changed FakeIP identity")
                    tcp_echo(identity)
                    udp_echo(identity)
                mac = Path("/sys/class/net/uplink2/address").read_text().strip()
                self.suite.capture("dhcp-renewal", renew, interface="uplink2",
                    required=["udp and (port 67 or port 68)", "src host 192.0.4.20 and dst port 24444",
                              "src host 192.0.4.20 and dst host 10.77.0.2 and dst port 53"],
                    forbidden=["dst host 198.51.100.10", "dst net 198.18.0.0/15", "ip6 and ether src " + mac])
                if not any(e["kind"] == "dns" and e["name"] == "endpoint.fixture.invalid."
                           and e["server"] == "10.77.0.2" and e["client"] == "192.0.4.20"
                           for e in events()[before:]):
                    raise RuntimeError("DHCP recovery retained old endpoint-bootstrap authority")
                (LAB / "dhcp-nm-observation.log").write_text(
                    run("nmcli", "-f", "GENERAL.STATE,IP4", "device", "show", "uplink2").stdout)
        finally:
            server.close()
            run("nmcli", "connection", "delete", "id", "nmt-vm-dhcp", check=False)
            run("ip", "link", "delete", "uplink2", check=False)
            run("nmcli", "--wait", "20", "connection", "up", "id", "nmt-vm-uplink")
