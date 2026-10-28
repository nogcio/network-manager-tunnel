#!/usr/bin/env python3
"""Explicit Secret Service acceptance using a pinned, isolated local keyring peer."""
import argparse
import hashlib
import os
from pathlib import Path
import select
import shutil
import subprocess
import tempfile

# GNOME Keyring 51.1 test-enabled Linux peer. Not a production backend dependency.
PEER_SHA256 = "29cb44793218cbda04694fc11d6cdd8bac6cc69f2347be03e5c356c5455f9c00"


def stop(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--peer", type=Path, default=Path("/usr/bin/gnome-keyring-daemon"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    peer = args.peer.resolve(strict=True)
    if hashlib.sha256(peer.read_bytes()).hexdigest() != PEER_SHA256:
        raise RuntimeError("Pinned keyring peer checksum mismatch; refusing execution")
    for tool in ["dbus-daemon", "gdbus", "timeout", "cargo"]:
        if shutil.which(tool) is None:
            raise RuntimeError(f"Required isolated test tool is unavailable: {tool}")
    print("[1/3] Build project-owned vault probe (locked dependencies)", flush=True)
    subprocess.run(["timeout", "--kill-after=3s", "180s", "cargo", "build", "--locked", "-p", "nm-tunnel-cosmic", "--example", "vault_lab"], cwd=root, check=True)
    target = Path(os.environ.get("CARGO_TARGET_DIR", root / "target"))
    if not target.is_absolute():
        target = root / target
    binary = (target / "debug/examples/vault_lab").resolve(strict=True)
    lab_root = root / "target/vault-lab"
    lab_root.mkdir(parents=True, exist_ok=True)
    lab = Path(tempfile.mkdtemp(prefix="run-", dir=lab_root))
    home = lab / "home"
    home.mkdir(mode=0o700)
    runtime = lab / "runtime"
    runtime.mkdir(mode=0o700)
    address = f"unix:path={lab / 'bus'}"
    env = os.environ.copy()
    for key in ["DISPLAY", "WAYLAND_DISPLAY", "GNOME_KEYRING_CONTROL", "GNOME_KEYRING_PID", "DBUS_STARTER_ADDRESS", "DBUS_STARTER_BUS_TYPE"]:
        env.pop(key, None)
    env.update(HOME=str(home), XDG_DATA_HOME=str(home / "data"), XDG_CONFIG_HOME=str(home / "config"),
               XDG_CACHE_HOME=str(home / "cache"), XDG_STATE_HOME=str(home / "state"),
               XDG_RUNTIME_DIR=str(runtime), DBUS_SESSION_BUS_ADDRESS=address, NM_TUNNEL_ISOLATED_VAULT="1")
    bus = keyring = None
    print(f"[2/3] Start pinned private bus/keyring; synthetic artifacts: {lab}", flush=True)
    with (lab / "bus.log").open("w") as bus_log, (lab / "keyring.log").open("w") as keyring_log:
        try:
            bus = subprocess.Popen(["dbus-daemon", "--session", "--nofork", "--print-address=1", f"--address={address}"], env=env, stdout=subprocess.PIPE, stderr=bus_log, text=True)
            if not select.select([bus.stdout], [], [], 5)[0] or not bus.stdout.readline().startswith(address):
                raise RuntimeError("Private bus did not become ready before its deadline")
            keyring = subprocess.Popen([str(peer), "--foreground", "--unlock", "--components=secrets", f"--control-directory={runtime / 'keyring'}"], env=env, stdin=subprocess.PIPE, stdout=keyring_log, stderr=keyring_log)
            keyring.stdin.write(b"synthetic-fixture-password\n")
            keyring.stdin.close()
            subprocess.run(["gdbus", "wait", f"--address={address}", "--timeout=10", "org.freedesktop.secrets"], env=env, check=True, timeout=12)
            print("[3/3] Save/reopen/remove through the real encrypted Secret Service adapter", flush=True)
            subprocess.run(["timeout", "--kill-after=3s", "120s", str(binary)], cwd=root, env=env, check=True, timeout=125)
        finally:
            stop(keyring)
            stop(bus)
    print("PASS isolated source-store integration; no desktop keyring, HTTP, NM or host networking changes", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"FAIL isolated source-store integration: {error}", flush=True)
        raise SystemExit(1) from None
