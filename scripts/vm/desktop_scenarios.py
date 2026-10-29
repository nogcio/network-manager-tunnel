"""Genuine packaged COSMIC agent and GNOME Secret Service in a private guest desktop.

This verifies the real programs' NM/keyring contract, not native accessibility or
Polkit prompts. No test agent, credential-store shim or direct secret retrieval.
"""
import os
import hashlib
from pathlib import Path
import re
import select
import shutil
import subprocess

from fixture import tcp_echo
from credential_storage import assert_no_system_secret
from support import LAB, assert_clean, run, stop, wait


class Desktop:
    def __init__(self):
        self.children = []
        self.logs = []
        self.agent = self.keyring = None
        self.agent_binary = str(LAB / "cosmic-applet-network") if (LAB / "cosmic-applet-network").is_file() else "/usr/bin/cosmic-applet-network"
        self.home = LAB / "desktop-home"
        self.runtime = LAB / "desktop-runtime"
        self.home.mkdir(mode=0o700)
        self.runtime.mkdir(mode=0o700)
        self.env = dict(os.environ)
        for key in ["DISPLAY", "WAYLAND_DISPLAY", "WAYLAND_SOCKET", "DBUS_SESSION_BUS_ADDRESS",
                    "GNOME_KEYRING_CONTROL", "GNOME_KEYRING_PID", "DBUS_STARTER_ADDRESS", "DBUS_STARTER_BUS_TYPE"]:
            self.env.pop(key, None)
        self.env.update(HOME=str(self.home), XDG_CONFIG_HOME=str(self.home / "config"),
            XDG_DATA_HOME=str(self.home / "data"), XDG_CACHE_HOME=str(self.home / "cache"),
            XDG_STATE_HOME=str(self.home / "state"), XDG_RUNTIME_DIR=str(self.runtime),
            DBUS_SESSION_BUS_ADDRESS="unix:path=" + str(self.runtime / "bus"),
            LIBGL_ALWAYS_SOFTWARE="1", GALLIUM_DRIVER="llvmpipe", WGPU_BACKEND="gl")

    def launch(self, name, command, **kwargs):
        log = (LAB / ("desktop-" + name + ".log")).open("a")
        self.logs.append(log)
        child = subprocess.Popen(command, env=self.env, stdout=log, stderr=log, **kwargs)
        self.children.append(child)
        return child

    def command(self, *args, **kwargs):
        return run(*args, env=self.env, **kwargs)

    def secret_call(self, member, *args):
        return self.command("gdbus", "call", "--address", self.env["DBUS_SESSION_BUS_ADDRESS"],
            "--dest", "org.freedesktop.secrets", "--object-path", "/org/freedesktop/secrets",
            "--method", "org.freedesktop.Secret.Service." + member, *args).stdout

    def collection(self):
        result = self.secret_call("ReadAlias", "default")
        match = re.search(r"'(/org/freedesktop/secrets/collection/[A-Za-z0-9_]+)'", result)
        if not match:
            raise RuntimeError("The genuine keyring did not expose a default collection")
        return match[1]

    def items(self):
        result = self.command("gdbus", "call", "--address", self.env["DBUS_SESSION_BUS_ADDRESS"],
            "--dest", "org.freedesktop.secrets", "--object-path", self.collection(),
            "--method", "org.freedesktop.DBus.Properties.Get", "org.freedesktop.Secret.Collection", "Items").stdout
        return set(re.findall(r"/org/freedesktop/secrets/collection/[A-Za-z0-9_/]+", result))

    def require_unlocked(self):
        result = self.command("gdbus", "call", "--address", self.env["DBUS_SESSION_BUS_ADDRESS"],
            "--dest", "org.freedesktop.secrets", "--object-path", self.collection(),
            "--method", "org.freedesktop.DBus.Properties.Get", "org.freedesktop.Secret.Collection", "Locked").stdout
        if result.strip() != "(<false>,)":
            raise RuntimeError("Genuine default keyring collection is not unlocked")

    def start_keyring(self):
        self.keyring = self.launch("keyring", ["gnome-keyring-daemon", "--foreground", "--unlock",
            "--components=secrets", "--control-directory=" + str(self.runtime / "keyring")], stdin=subprocess.PIPE)
        self.keyring.stdin.write(b"synthetic-vm-keyring-password\n")
        self.keyring.stdin.close()
        self.command("gdbus", "wait", "--address", self.env["DBUS_SESSION_BUS_ADDRESS"],
                     "--timeout=10", "org.freedesktop.secrets", timeout=12)
        self.collection()
        self.require_unlocked()

    def registrations(self):
        result = run("journalctl", "-b", "-u", "NetworkManager", "--no-pager", "--quiet", "-o", "cat",
                     "--grep", "com.system76.CosmicSettings.Applet.*agent registered", check=False)
        # journalctl --grep uses status 1 for a valid empty match set.
        if result.returncode not in [0, 1] or (result.returncode == 1 and result.stderr.strip()):
            raise RuntimeError("NM agent registration journal is unavailable")
        return len(result.stdout.splitlines())

    def start_agent(self):
        before = self.registrations()
        self.agent = self.launch("agent", [self.agent_binary])
        def ready():
            if self.agent.poll() is not None:
                raise RuntimeError("The genuine COSMIC network applet exited before NM registration")
            return self.registrations() > before
        wait(ready, 25, "Genuine COSMIC NM agent registration")

    def reject_non_nm_calls(self):
        # Even guest root must not impersonate NM to read/delete VPN credentials.
        # Locate only the owned applet PID's unique bus connection; never guess
        # another desktop agent's name or inspect secret payloads.
        listing = run("busctl", "--system", "--no-pager", "--no-legend", "list").stdout
        (LAB / "desktop-agent-bus-discovery.log").write_text(f"Owned PID={self.agent.pid}\n" + listing)
        names = [line.split()[0] for line in listing.splitlines()
                 if len(line.split()) > 1 and line.split()[1] == str(self.agent.pid) and line.lstrip().startswith(":")]
        journal = run("journalctl", "-b", "-u", "NetworkManager", "--no-pager", "--quiet", "-o", "cat",
                      "--grep", "com.system76.CosmicSettings.Applet.*agent registered").stdout
        # System policy deliberately does not grant agent Introspectable calls.
        # NM's registration log binds the registered unique name to our PID.
        registered = set(re.findall(r"(:[0-9]+\.[0-9]+)/com\.system76\.CosmicSettings\.Applet", journal))
        owners = [name for name in names if name in registered]
        if len(owners) != 1:
            raise RuntimeError("Cannot identify the owned applet's exact NM agent interface")
        before = self.items()
        methods = [("GetSecrets", "a{sa{sv}}osasu", ["0", "/org/freedesktop/NetworkManager/Settings/999999", "vpn", "1", "uuid", "0"]),
                   ("SaveSecrets", "a{sa{sv}}o", ["0", "/org/freedesktop/NetworkManager/Settings/999999"]),
                   ("DeleteSecrets", "a{sa{sv}}o", ["0", "/org/freedesktop/NetworkManager/Settings/999999"]),
                   ("CancelGetSecrets", "os", ["/org/freedesktop/NetworkManager/Settings/999999", "vpn"])]
        for method, signature, arguments in methods:
            result = run("busctl", "--system", "call", owners[0],
                         "/org/freedesktop/NetworkManager/SecretAgent",
                         "org.freedesktop.NetworkManager.SecretAgent", method, signature,
                         *arguments, timeout=8, check=False)
            if result.returncode == 0 or "NetworkManager owner required" not in result.stderr:
                raise RuntimeError("Non-NM caller was not explicitly refused for " + method)
        if self.items() != before:
            raise RuntimeError("Rejected non-NM credential calls mutated the keyring")

    def start(self):
        for name in ["Xvfb", "cosmic-comp", "cosmic-applet-network", "gnome-keyring-daemon", "gdbus"]:
            if shutil.which(name) is None:
                raise RuntimeError("Prepared desktop tool unavailable: " + name)
        # Own this private bus's activation children too; a prompt service must
        # not outlive this fixture. This unit exists only in the disposable OS.
        command = ["systemd-run", "--quiet", "--collect", "--unit=nmt-vm-desktop-bus",
                   "--property=Type=exec", "--property=KillMode=control-group"]
        for key in ["HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"]:
            command.append("--setenv=" + key + "=" + self.env[key])
        run(*command, "dbus-daemon", "--session", "--nofork", "--address=" + self.env["DBUS_SESSION_BUS_ADDRESS"])
        wait(lambda: (self.runtime / "bus").is_socket(), 8, "Private guest desktop session bus")
        read_fd, write_fd = os.pipe()
        try:
            xserver = self.launch("xvfb", ["Xvfb", "-displayfd", str(write_fd), "-screen", "0", "1600x1200x24",
                                          "-nolisten", "tcp"], pass_fds=(write_fd,))
            os.close(write_fd)
            write_fd = None
            if not select.select([read_fd], [], [], 10)[0] or xserver.poll() is not None:
                raise RuntimeError("Private guest X display did not become ready")
            self.env["DISPLAY"] = ":" + os.read(read_fd, 32).decode().strip()
        finally:
            os.close(read_fd)
            if write_fd is not None:
                os.close(write_fd)
        self.start_keyring()
        self.env.update(COSMIC_BACKEND="winit", WINIT_UNIX_BACKEND="x11")
        compositor = self.launch("compositor", ["cosmic-comp", "--no-xwayland"])
        def ready():
            if compositor.poll() is not None:
                raise RuntimeError("Genuine nested COSMIC compositor exited")
            sockets = [path for path in self.runtime.glob("wayland-*") if path.is_socket()]
            return sockets[0] if len(sockets) == 1 else None
        wayland = wait(ready, 20, "Private guest COSMIC Wayland socket")
        self.env.update(WAYLAND_DISPLAY=wayland.name, WINIT_UNIX_BACKEND="wayland", XDG_SESSION_TYPE="wayland")
        self.start_agent()

    def close(self):
        for child in reversed(self.children):
            stop(child)
        run("systemctl", "stop", "nmt-vm-desktop-bus.service", check=False)
        for log in self.logs:
            log.close()


class DesktopScenarios:
    def __init__(self, features):
        self.features = features

    def real_desktop_keyring(self):
        desktop = Desktop()
        try:
            desktop.start()
            before = desktop.items()
            observation = LAB / "desktop-keyring-observation.log"
            observation.write_text("Genuine COSMIC NM agent registered; genuine default Secret Service collection unlocked.\n"
                                   f"Agent executable={desktop.agent_binary}\n"
                                   f"Agent SHA256={hashlib.sha256(Path(desktop.agent_binary).read_bytes()).hexdigest()}\n"
                                   f"Initial item count={len(before)}\n"
                                   "Private nested guest-root desktop; no native Polkit/input/accessibility acceptance.\n")
            with self.features.profile("ask-secret", start=False) as ask_identifier:
                assert_no_system_secret(ask_identifier)
                if desktop.items() != before:
                    raise RuntimeError("Not-saved VPN profile created a keyring item")
            with self.features.profile("agent-secret", start=False) as identifier:
                try:
                    wait(lambda: len(desktop.items() - before) > 0, 12,
                         "Real desktop NM agent persisted the supplied credential in Secret Service")
                finally:
                    desktop.require_unlocked()
                    with observation.open("a") as log:
                        log.write(f"After NM Agent-profile save: item count={len(desktop.items())}; collection remains unlocked.\n")
                desktop.reject_non_nm_calls()
                assert_no_system_secret(identifier)
                keyrings = list((desktop.home / "data/keyrings").glob("*.keyring"))
                if not keyrings or any(b"12345678-1234-4234-8234-123456789abc" in path.read_bytes() for path in keyrings):
                    raise RuntimeError("No encrypted keyring evidence or a plaintext credential fallback")
                stop(desktop.agent)
                stop(desktop.keyring)
                desktop.start_keyring()
                desktop.start_agent()
                run("nmcli", "--wait", "55", "connection", "up", "uuid", identifier, timeout=60)
                tcp_echo()
                run("nmcli", "--wait", "25", "connection", "down", "uuid", identifier, timeout=30)
                assert_clean()
                with observation.open("a") as log:
                    log.write("Non-NM Get/Save/Delete/Cancel calls refused without mutation; encrypted keyring; process reopen; real TUN echo.\n"
                              "No Tunnel GUI or synthetic NM agent was running. Native Polkit/input/accessibility not accepted.\n")
            wait(lambda: not (desktop.items() - before), 12,
                 "NM profile deletion removed the genuine agent's credential item")
            with observation.open("a") as log:
                log.write("Not-saved profile retained no keyring/system secret; Agent profile deletion removed its item.\n")
        finally:
            desktop.close()
