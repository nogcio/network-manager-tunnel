"""Real NM AgentManager routing; the fixture agent stores no real credentials."""
import subprocess

from credential_storage import assert_no_system_secret
from fixture import tcp_echo
from support import LAB, assert_clean, run, stop, wait


class SecretScenarios:
    def __init__(self, features):
        self.features = features

    def desktop_secret_agent(self):
        log_path = LAB / "secret-agent.log"
        with log_path.open("w") as log:
            agent = subprocess.Popen([str(LAB / "lab_profiles"), "serve-secret-agent"], stdout=log, stderr=log)
            try:
                def ready():
                    if agent.poll() is not None:
                        raise RuntimeError("Synthetic NM agent exited")
                    return "READY synthetic NM agent registered" in log_path.read_text()
                wait(ready, 8, "Registered standard NM secret-agent peer")
                for mode in ["agent-secret", "ask-secret"]:
                    before = len(log_path.read_text())
                    with self.features.profile(mode) as identifier:
                        tcp_echo()
                        persistence_event = ("EVENT agent-save-request" if mode == "agent-secret"
                                             else "EVENT not-saved-persistence-ignored")
                        if persistence_event not in log_path.read_text()[before:]:
                            raise RuntimeError("NM agent did not receive the expected credential-storage policy")
                        if "EVENT hinted-credential-request" not in log_path.read_text()[before:]:
                            raise RuntimeError("NM did not route the exact UUID-hinted interactive request")
                        assert_no_system_secret(identifier)
                    marker = LAB / "agent-cancel"
                    marker.touch()
                    try:
                        with self.features.profile(mode, rejects=True):
                            if "EVENT user-cancelled" not in log_path.read_text()[before:]:
                                raise RuntimeError("User cancellation did not pass through NM")
                    finally:
                        marker.unlink()
            finally:
                stop(agent)
        # No desktop agent is not permission to save or reuse a system secret.
        with self.features.profile("ask-secret", rejects=True):
            assert_clean()
