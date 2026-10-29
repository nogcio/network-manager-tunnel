"""Bounded guest commands, readiness and evidence; not imported by production."""
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import time

NAME = "org.freedesktop.NetworkManager.tunnel"
PROFILE = "NMT client contract"
LAB = Path("/run/nmt-vm")


def run(*args, timeout=15, check=True, **kwargs):
    kwargs["env"] = dict(kwargs.get("env", os.environ), LC_ALL="C", LANG="C")
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, **kwargs)
    if check and result.returncode:
        # Only fixed synthetic commands run here. Never dump NM settings/secrets.
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): "
                           f"{result.stdout[-2000:]}{result.stderr[-2000:]}")
    return result


def wait(predicate, seconds, description):
    deadline = time.monotonic() + seconds
    while True:
        value = predicate()
        if value:
            return value
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(description)
        # Poll a real condition on a bounded cadence; never sleep to assert readiness.
        select.select([], [], [], min(0.1, remaining))


def bus(member, *args, name=NAME):
    return run("busctl", "--system", "--auto-start=no", "call",
               "org.freedesktop.DBus", "/org/freedesktop/DBus",
               "org.freedesktop.DBus", member, "s", name, *args).stdout.strip()


def owner_pid(name=NAME):
    if bus("NameHasOwner", name=name) == "b false":
        return None
    return int(bus("GetConnectionUnixProcessID", name=name).split()[1])


class Process:
    """Pin fault injection and exit observation to the exact guest process."""
    def __init__(self, pid):
        self.pid = pid
        self.fd = os.pidfd_open(pid)
        try:
            self.inode = os.stat(f"/proc/{pid}/exe").st_ino
        except BaseException:
            os.close(self.fd)
            raise

    def send(self, sig):
        signal.pidfd_send_signal(self.fd, sig)

    def exited(self):
        return bool(select.select([self.fd], [], [], 0)[0])

    def close(self):
        os.close(self.fd)


def worker(backend):
    children = Path(f"/proc/{backend.pid}/task/{backend.pid}/children").read_text().split()
    pids = [int(pid) for pid in children
            if Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")[-2:] == [b"--worker", b""]]
    if len(pids) != 1:
        raise RuntimeError("Expected exactly one owned worker")
    return Process(pids[0])


def tables():
    return json.loads(run("nft", "-j", "list", "tables").stdout)["nftables"]


def guards_present():
    return {e["table"]["name"] for e in tables() if "table" in e
            and e["table"]["family"] == "inet"} & {"nm_tunnel", "nm_tunnel_fakeip"}


def active():
    return "vpn" in run("nmcli", "-t", "-f", "TYPE", "connection", "show", "--active").stdout.splitlines()


def backend_idle():
    if bus("NameHasOwner") == "b false":
        return True
    state = run("busctl", "--system", "--auto-start=no", "get-property", NAME,
                "/org/freedesktop/NetworkManager/VPN/Plugin",
                "org.freedesktop.NetworkManager.VPN.Plugin", "State", check=False)
    # External resources can disappear before the lifecycle loop consumes the
    # cleanup result. Absence alone is not that owner's completion acknowledgement.
    return state.returncode == 0 and state.stdout.strip() in ["u 1", "u 6"]


def assert_clean(processes=()):
    def cleaned():
        routes = json.loads(run("ip", "-j", "-4", "route", "show", "table", "all").stdout)
        return (not active() and not guards_present() and backend_idle()
                and not Path("/sys/class/net/nmtun0").exists()
                and not any(r.get("dev") == "nmtun0" for r in routes)
                and all(p.exited() for p in processes))
    wait(cleaned, 55, "Confirmed NM/TUN/routes/guards/process cleanup")


def activate():
    run("nmcli", "--wait", "55", "connection", "up", "id", PROFILE, timeout=60)
    if not active() or guards_present() != {"nm_tunnel"}:
        raise RuntimeError("NM activation or legacy session guard missing")


def release_protection():
    # Explicit scenario-owned Disconnect, never a production automatic recovery.
    if guards_present():
        run(str(LAB / "lab_control"), "release-protection", timeout=155)


def disconnect(identifier=PROFILE, selector="id"):
    run("nmcli", "--wait", "25", "connection", "down", selector, identifier, timeout=30)
    release_protection()


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
