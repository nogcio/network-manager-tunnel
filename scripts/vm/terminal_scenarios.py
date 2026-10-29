"""Backend death must retain blocking until explicit scenario-owned Disconnect."""
import signal

from fixture import tcp_echo
from support import LAB, active, assert_clean, guards_present, release_protection, run, wait


class TerminalScenarios:
    def __init__(self, features):
        self.features = features
        self.suite = features.suite

    def persistent_terminal_retention(self):
        with self.features.profile("roaming"):
            backend, child = self.suite.pinned()
            try:
                run("nmcli", "--wait", "20", "connection", "down", "id", "nmt-vm-uplink")
                wait(child.exited, 15, "Protected network-recovery wait")
                if not active() or guards_present() != {"nm_tunnel", "nm_tunnel_fakeip"}:
                    raise RuntimeError("Ordinary network loss unexpectedly ended protection")
                backend.send(signal.SIGKILL)
                wait(lambda: backend.exited() and child.exited(), 45, "Failed backend and worker exit")
                if guards_present() != {"nm_tunnel", "nm_tunnel_fakeip"}:
                    raise RuntimeError("Backend death released protection")
            finally:
                run("nmcli", "--wait", "20", "connection", "up", "id", "nmt-vm-uplink")
            try:
                tcp_echo(size=32)
            except OSError:
                pass
            else:
                raise RuntimeError("Ordinary traffic escaped without explicit Disconnect")
            release_protection()
            assert_clean([backend, child])
            tcp_echo()
            if active() or guards_present():
                raise RuntimeError("Catastrophic cleanup was misreported as VPN recovery")
            (LAB / "terminal-policy-observation.log").write_text(
                "Network loss and backend SIGKILL retained protection.\n"
                "Ordinary traffic was refused until explicit authorized Disconnect.\n"
                "Post-Disconnect cleanup and ordinary IPv4 echo succeeded.\n")
