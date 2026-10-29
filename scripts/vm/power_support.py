"""Shared real S3/RTC fixture and nonsecret kernel/platform observations."""
from pathlib import Path
import json
import time

from support import run, wait


def snapshot():
    paths = ["/sys/power/state", "/sys/power/mem_sleep", "/sys/power/suspend_stats/success",
             "/sys/class/rtc/rtc0/wakealarm", "/sys/devices/system/cpu/online",
             "/sys/devices/system/clocksource/clocksource0/current_clocksource",
             "/sys/devices/system/clocksource/clocksource0/available_clocksource",
             "/proc/sys/kernel/watchdog", "/proc/sys/kernel/nmi_watchdog",
             "/proc/sys/kernel/watchdog_thresh", "/proc/sys/kernel/panic"]
    for device in Path("/sys/class/watchdog").glob("watchdog*"):
        paths.extend(str(device / field) for field in ["identity", "state", "status", "timeout", "bootstatus", "nowayout"])
    paths.extend(str(path) for path in Path("/sys/devices/system/clockevents").glob("clockevent*/current_device"))
    result = {}
    for path in paths:
        if Path(path).is_file():
            try:
                result[path] = Path(path).read_text().strip()
            except OSError as error:
                result[path] = {"unavailable_errno": error.errno}
    result["watchdog-modules"] = "\n".join(line for line in Path("/proc/modules").read_text().splitlines()
                                            if any(name in line for name in ["iTCO", "wdat", "watchdog"]))
    # Read only documented Q35 LPC configuration registers, not guest memory.
    config = Path("/sys/bus/pci/devices/0000:00:1f.0/config")
    if config.is_file():
        with config.open("rb") as stream:
            registers = stream.read(256)
        result["ich9-lpc-config"] = {name: hex(int.from_bytes(registers[offset:offset + width], "little"))
                                     for name, offset, width in [("PMBASE", 0x40, 4), ("ACPI_CTRL", 0x44, 1), ("RCBA", 0xf0, 4)]}
    result["watchdog-owners"] = []
    for process in Path("/proc").iterdir():
        if not process.name.isdecimal():
            continue
        try:
            for fd in (process / "fd").iterdir():
                try:
                    target = str(fd.readlink())
                    if target.startswith("/dev/watchdog"):
                        result["watchdog-owners"].append({"pid": process.name, "device": target})
                except FileNotFoundError:
                    continue
        except FileNotFoundError:
            continue
    return result


def suspend_kernel(report=None):
    before_state = snapshot()
    success = Path("/sys/power/suspend_stats/success")
    if ("mem" not in before_state.get("/sys/power/state", "").split()
            or "[deep]" not in before_state.get("/sys/power/mem_sleep", "")
            or not success.is_file() or not Path("/dev/rtc0").exists()):
        raise RuntimeError("Guest lacks selected deep S3/counter/RTC; no simulated-pause or s2idle pass")
    boot = Path("/proc/sys/kernel/random/boot_id").read_text()
    before = int(success.read_text())
    offset = time.clock_gettime(time.CLOCK_BOOTTIME) - time.monotonic()
    if report:
        report.emit("artifact", name="s3-platform-before", text=json.dumps(before_state, indent=2))
    run("rtcwake", "--mode", "no", "--seconds", "10", "--device", "/dev/rtc0")
    run("systemctl", "--no-block", "suspend", timeout=20)
    wait(lambda: int(success.read_text()) > before, 35, "Completed real guest kernel S3/RTC cycle")
    if Path("/proc/sys/kernel/random/boot_id").read_text() != boot:
        raise RuntimeError("A reboot is not suspend/resume")
    slept = time.clock_gettime(time.CLOCK_BOOTTIME) - time.monotonic() - offset
    if slept < 0.5:
        raise RuntimeError("Kernel sleep counter changed without an observable sleep interval")
    observation = dict(kernel_success_before=before, kernel_success_after=int(success.read_text()),
                       boottime_minus_monotonic_increase=round(slept, 3), platform_after=snapshot())
    if report:
        report.emit("artifact", name="s3-platform-after", text=json.dumps(observation, indent=2))
        report.emit("artifact", name="s3-kernel-resume", text=run("journalctl", "-b", "-k", "--no-pager", "-n", "100").stdout[-24000:])
    return observation
