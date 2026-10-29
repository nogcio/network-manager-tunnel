"""Platform-only S3 survival: no Tunnel install, peer, veth, desktop or keyring."""
from pathlib import Path
import json
import os
import select
import socket
import sys
import time

from power_support import snapshot, suspend_kernel
from support import run


def assert_plain_guest():
    if {name for _, name in socket.if_nameindex()} != {"lo"}:
        raise RuntimeError("Platform-only probe acquired a network interface")
    for process in Path("/proc").iterdir():
        if not process.name.isdecimal():
            continue
        try:
            executable = (process / "exe").readlink().name
        except FileNotFoundError:
            continue
        if executable.startswith(("nm-tunnel-", "cosmic-", "gnome-keyring")) or executable == "xray":
            raise RuntimeError("Platform-only probe found an excluded runtime: " + executable)
    tables = json.loads(run("nft", "-j", "list", "tables").stdout)
    if any(entry.get("table", {}).get("name") in ["nm_tunnel", "nm_tunnel_fakeip"]
           for entry in tables.get("nftables", [])):
        raise RuntimeError("Platform-only probe found Tunnel guards")


def observe(report, suspend, vcpus):
    assert_plain_guest()
    report.emit("artifact", name="plain-platform", text=json.dumps(snapshot(), indent=2))
    cpus = set(range(vcpus))
    if set(os.sched_getaffinity(0)) != cpus:
        raise RuntimeError("Platform control lacks the declared online CPU set")
    tracing = Path("/sys/kernel/tracing")
    if not (tracing / "events").is_dir():
        run("mount", "-t", "tracefs", "tracefs", str(tracing))
    instance = tracing / "instances/nmt-platform-power"
    instance.mkdir()
    (instance / "buffer_size_kb").write_text("64\n")
    for event in ["watchdog_ping", "watchdog_start", "watchdog_stop"]:
        (instance / "events/watchdog" / event / "enable").write_text("1\n")
    report.emit("artifact", name="plain-cpu-model", text="\n".join(
        line for line in Path("/proc/cpuinfo").read_text().splitlines()
        if line.startswith(("processor", "vendor_id", "model name", "cpu family", "model\t"))))
    if suspend:
        suspend_kernel(report)
    case = "platform-s3-idle" if suspend else "platform-idle"
    boot = Path("/proc/sys/kernel/random/boot_id").read_text()
    start = time.monotonic()
    end = start + 180
    rounds = 0
    while time.monotonic() < end:
        assert_plain_guest()
        if Path("/proc/sys/kernel/random/boot_id").read_text() != boot:
            raise RuntimeError("Platform lifetime rebooted during post-S3 observation")
        # Verify every configured CPU can still schedule a bounded userspace
        # operation; the external host deadline covers stalled guest timers too.
        for cpu in sorted(cpus):
            run("taskset", "--cpu-list", str(cpu), sys.executable, "-c", "import time; print(time.monotonic_ns())", timeout=5)
        rounds += 1
        report.emit("progress", case=case, seconds=round(time.monotonic() - start, 1), operations=rounds * vcpus)
        report.emit("artifact", name=f"plain-interrupts-{rounds:03}", text=Path("/proc/interrupts").read_text()[-16000:])
        report.emit("artifact", name=f"plain-watchdog-trace-{rounds:03}", text=(instance / "trace").read_text()[-16000:])
        for process in Path("/proc").iterdir():
            if not process.name.isdecimal():
                continue
            try:
                if (process / "comm").read_text().strip() == "watchdogd":
                    report.emit("artifact", name=f"plain-watchdog-stack-{rounds:03}",
                                text=(process / "stack").read_text()[-8000:])
            except FileNotFoundError:
                continue
        report.emit("artifact", name=f"plain-kernel-{rounds:03}",
                    text=run("journalctl", "-b", "-k", "--no-pager", "-n", "35").stdout[-12000:])
        # Observation cadence, not a readiness inference or replacement for S3.
        select.select([], [], [], max(0, min(end, start + rounds * 15) - time.monotonic()))
    assert_plain_guest()
    for event in ["watchdog_ping", "watchdog_start", "watchdog_stop"]:
        (instance / "events/watchdog" / event / "enable").write_text("0\n")
    instance.rmdir()
