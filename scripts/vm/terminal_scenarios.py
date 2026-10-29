"""Verify, not alter, the disclosed catastrophic-failure cleanup policy."""
import signal

from fixture import tcp_echo
from support import LAB, active, assert_clean, guards_present, run, wait


class TerminalScenarios:
    def __init__(self, features):
        self.features = features
        self.suite = features.suite

    def persistent_terminal_cleanup(self):
        with self.features.profile("roaming"):
            backend, child = self.suite.pinned()
            try:
                run("nmcli", "--wait", "20", "connection", "down", "id", "nmt-vm-uplink")
                wait(child.exited, 15, "Protected network-recovery wait")
                if not active() or guards_present() != {"nm_tunnel", "nm_tunnel_fakeip"}:
                    raise RuntimeError("Ordinary network loss unexpectedly ended protection")
                backend.send(signal.SIGKILL)
                assert_clean([backend, child])
            finally:
                run("nmcli", "--wait", "20", "connection", "up", "id", "nmt-vm-uplink")
            tcp_echo()
            if active() or guards_present():
                raise RuntimeError("Catastrophic cleanup was misreported as VPN recovery")
            (LAB / "terminal-policy-observation.log").write_text(
                "Network loss retained protection; exact backend SIGKILL ended the NM lifetime.\n"
                "Independent recovery removed the guards; ordinary unprotected IPv4 echo succeeded.\n"
                "This is the existing terminal-cleanup policy, NOT until-Disconnect crash protection.\n")
