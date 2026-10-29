"""Actual guest kernel sleep via logind/systemd and a hardware RTC wake alarm."""
from pathlib import Path
import json

from features import query, udp_echo
from fixture import tcp_echo
from support import LAB, active, guards_present, run
from power_support import suspend_kernel


class PowerScenarios:
    def __init__(self, features, report):
        self.features = features
        self.suite = features.suite
        self.report = report

    def suspend_resume(self):
        with self.features.profile("roaming"):
            backend, _ = self.suite.pinned()
            tun = Path("/sys/class/net/nmtun0/ifindex").read_text()
            identity = str(query("suspend.fixture.invalid").rr[0].rdata)
            tcp_echo(identity)
            def cycle():
                observation = suspend_kernel(self.report)
                if not active() or guards_present() != {"nm_tunnel", "nm_tunnel_fakeip"}:
                    raise RuntimeError("System sleep released the persistent admitted VPN lifetime/protection")
                run(str(LAB / "lab_profiles"), "observe-running", timeout=75)
                if backend.exited() or Path("/sys/class/net/nmtun0/ifindex").read_text() != tun:
                    raise RuntimeError("Resume replaced the admitted backend/TUN")
                if str(query("suspend.fixture.invalid").rr[0].rdata) != identity:
                    raise RuntimeError("Suspend changed durable FakeIP identity")
                tcp_echo(identity)
                udp_echo(identity)
                (LAB / "suspend-observation.log").write_text(json.dumps(observation, indent=2) + "\n")
            mac = Path("/sys/class/net/uplink0/address").read_text().strip()
            self.suite.capture("suspend-resume", cycle,
                required=["tcp and dst port 24444"],
                forbidden=["dst host 198.51.100.10", "dst net 198.18.0.0/15", "ip6 and ether src " + mac])
