"""Ten-minute persistent TCP/UDP traffic, bounded evidence and public flow draining."""
from contextlib import ExitStack
import json
from pathlib import Path
import select
import socket
import time

from features import query, read_exact
from support import LAB, active, guards_present, run


def resources(process):
    return {"fd_count": len(list(Path(f"/proc/{process.pid}/fd").iterdir())),
            "status": "\n".join(line for line in Path(f"/proc/{process.pid}/status").read_text().splitlines()
                                if line.startswith(("VmRSS:", "Threads:")))}


class SoakScenarios:
    def __init__(self, features, report):
        self.features = features
        self.suite = features.suite
        self.report = report

    def steady_traffic(self):
        with self.features.profile("roaming"):
            backend, child = self.suite.pinned()
            identity = str(query("soak.fixture.invalid").rr[0].rdata)
            before = {"backend": resources(backend), "worker": resources(child)}
            observed = {}
            def traffic():
                start = time.monotonic()
                end = start + 600
                next_send = start
                next_report = start
                rounds = 0
                with ExitStack() as stack:
                    streams = [stack.enter_context(socket.create_connection((identity, 12346), timeout=5))
                               for _ in range(2)]
                    udp = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                    udp.settimeout(5)
                    udp.connect((identity, 12345))
                    while time.monotonic() < end:
                        payload = rounds.to_bytes(8, "big") + bytes(range(256))
                        for stream in streams:
                            stream.sendall(payload)
                            if read_exact(stream, len(payload)) != payload:
                                raise RuntimeError("Long-lived TCP payload mismatch")
                        udp.send(payload)
                        if udp.recv(4096) != payload:
                            raise RuntimeError("Long-lived UDP payload mismatch")
                        rounds += 1
                        if backend.exited() or child.exited() or not active():
                            raise RuntimeError("Steady traffic lost its admitted process/session")
                        if time.monotonic() >= next_report:
                            self.report.emit("progress", case="steady-traffic",
                                seconds=round(time.monotonic() - start, 1), operations=rounds * 3)
                            next_report = time.monotonic() + 30
                        # Deliberate workload rate, not a sleep used to infer
                        # readiness. Socket I/O and the whole VM have deadlines.
                        next_send += 1
                        select.select([], [], [], max(0, min(end, next_send) - time.monotonic()))
                observed.update(seconds=round(time.monotonic() - start, 3), rounds=rounds,
                                compared_bytes=rounds * 3 * (8 + 256))
            mac = Path("/sys/class/net/uplink0/address").read_text().strip()
            self.suite.capture("steady-traffic", traffic,
                required=["tcp and dst host 192.0.2.2 and dst port 24444"],
                forbidden=["dst host 198.51.100.10", "dst net 198.18.0.0/15", "ip6 and ether src " + mac])
            # UDP is intentionally idle-reaped, not closed by a pretend FIN.
            run(str(LAB / "lab_profiles"), "observe-drained", timeout=80)
            if guards_present() != {"nm_tunnel", "nm_tunnel_fakeip"}:
                raise RuntimeError("Flow draining removed the session guard")
            observed["resources_before"] = before
            observed["resources_after"] = {"backend": resources(backend), "worker": resources(child)}
            (LAB / "steady-traffic-observation.log").write_text(json.dumps(observed, indent=2) + "\n")
