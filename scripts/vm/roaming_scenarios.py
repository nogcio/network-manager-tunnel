"""Persistent NM lifetime: no reactivation from a frontend or a test helper."""
from pathlib import Path
import json
from features import events, query
from fixture import tcp_echo
from support import LAB, active, assert_clean, disconnect, guards_present, run, wait


class RoamingScenarios:
    def __init__(self, features):
        self.features = features
        self.suite = features.suite

    def persistent_uplink_recovery(self):
        self.recover("roaming")

    def persistent_source_recovery(self):
        self.recover("roaming-source")

    def recover(self, mode):
        with self.features.profile(mode):
            backend, old_worker = self.suite.pinned()
            before = len(events())
            hostname = "proxy.fixture.invalid" if mode == "roaming-source" else "roaming.fixture.invalid"
            identity = str(query(hostname).rr[0].rdata)
            tcp_echo(identity)
            direct_identity = None
            if mode == "roaming-source":
                direct_identity = str(query("direct.fixture.invalid").rr[0].rdata)
                tcp_echo(direct_identity)
            tun = Path("/sys/class/net/nmtun0/ifindex").read_text()
            run("nmcli", "--wait", "20", "connection", "down", "id", "nmt-vm-uplink")
            wait(old_worker.exited, 15, "Old network flow authority revoked")
            if not active() or guards_present() != {"nm_tunnel", "nm_tunnel_fakeip"}:
                raise RuntimeError("Network loss released the admitted protected NM lifetime")
            if Path("/sys/class/net/nmtun0/ifindex").read_text() != tun:
                raise RuntimeError("Recovery replaced NM's packet-device identity")
            # A second physical device, resolver and source address. This only
            # exists in the guest and does not attach any QEMU/host networking.
            run("ip", "link", "add", "uplink1", "type", "veth", "peer", "name", "peer1")
            try:
                run("ip", "link", "set", "peer1", "netns", "nmt-peer")
                run("ip", "-n", "nmt-peer", "addr", "add", "192.0.3.2/24", "dev", "peer1")
                run("ip", "-n", "nmt-peer", "link", "set", "peer1", "up")
                run("ip", "link", "set", "uplink1", "up")
                run("nmcli", "connection", "add", "type", "ethernet", "ifname", "uplink1",
                    "con-name", "nmt-vm-roaming-uplink", "connection.autoconnect", "no",
                    "ipv4.method", "manual", "ipv4.addresses", "192.0.3.1/24",
                    "ipv4.gateway", "192.0.3.2", "ipv4.dns", "10.77.0.2",
                    "ipv4.route-metric", "9", "ipv6.method", "disabled")
                def recover():
                    run("nmcli", "--wait", "20", "connection", "up", "id", "nmt-vm-roaming-uplink")
                    run(str(LAB / "lab_profiles"), "observe-running", timeout=75)
                    state = run("nmcli", "-g", "GENERAL.STATE", "connection", "show", "id", "NMT VM " + mode).stdout.strip()
                    (LAB / "roaming-observation.log").write_text(state + "\n")
                    if state != "activated":
                        raise RuntimeError("NM persistent session did not remain activated: " + state)
                    if str(query(hostname).rr[0].rdata) != identity:
                        raise RuntimeError("Network recovery changed durable FakeIP identity")
                    tcp_echo(identity)
                mac = Path("/sys/class/net/uplink1/address").read_text().strip()
                self.suite.capture(mode + "-uplink1", recover, interface="uplink1",
                                   required=["tcp and dst host 192.0.2.2 and dst port 24444",
                                             "dst host 10.77.0.2 and dst port 53"],
                                   forbidden=["dst host 198.51.100.10", "dst net 198.18.0.0/15", "ip6 and ether src " + mac])
                if backend.exited() or Path("/sys/class/net/nmtun0/ifindex").read_text() != tun:
                    raise RuntimeError("Recovery lost its original process/device ownership")
                if mode == "roaming-source":
                    routes = json.loads(run("ip", "-j", "-4", "route", "show", "dev", "nmtun0").stdout)
                    destinations = {route["dst"] for route in routes}
                    if not {"192.0.3.0/25", "192.0.3.128/25"} <= destinations:
                        raise RuntimeError("NM did not install the new source connected-prefix captures")
                    if {"192.0.2.0/25", "192.0.2.128/25"} & destinations:
                        raise RuntimeError("NM retained the obsolete source connected-prefix captures")
                    checkpoint = len(events())
                    self.suite.capture("roaming-source-direct-uplink1", lambda: tcp_echo(direct_identity),
                                       interface="uplink1",
                                       required=["dst host 198.51.100.10 and dst port 12345",
                                                 "tcp and dst host 192.0.2.2 and dst port 24444"],
                                       forbidden=["dst port 53", "dst net 198.18.0.0/15", "ip6 and ether src " + mac])
                    if not any(e["kind"] == "dns" and e["name"] == "direct.fixture.invalid."
                               and e["server"] == "1.1.1.1" and e["client"] == "1.1.1.1"
                               for e in events()[checkpoint:]):
                        raise RuntimeError("Source Direct reused old DNS authority instead of resolving in the new generation")
                if not any(e["kind"] == "dns" and e["name"] == "endpoint.fixture.invalid."
                           and e["server"] == "10.77.0.2" and e["client"] == "192.0.3.1"
                           for e in events()[before:]):
                    raise RuntimeError("Recovery did not bootstrap the endpoint on the new resolver/uplink")
                # Explicit disconnect during another outage must cancel all
                # future attempts; restoring the network must not reactivate.
                _, recovered_worker = self.suite.pinned()
                run("nmcli", "--wait", "20", "connection", "down", "id", "nmt-vm-roaming-uplink")
                wait(recovered_worker.exited, 15, "Second outage entered protected recovery")
                if not active() or guards_present() != {"nm_tunnel", "nm_tunnel_fakeip"}:
                    raise RuntimeError("Waiting for explicit Disconnect released protection")
                disconnect("NMT VM " + mode)
                assert_clean()
            finally:
                run("nmcli", "connection", "delete", "id", "nmt-vm-roaming-uplink", check=False)
                run("ip", "link", "delete", "uplink1", check=False)
                run("nmcli", "--wait", "20", "connection", "up", "id", "nmt-vm-uplink")
            if active() or guards_present():
                raise RuntimeError("Explicit disconnect did not retire the recovery intent")
