#!/usr/bin/env python3
"""Explicit pinned XUDP/REALITY/Vision checks in a disposable loopback namespace."""
import argparse
import asyncio
import base64
import hashlib
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile

PEER_SHA256 = "a27e3f95ab6ce270956d0cecd32eda4686a811afc71c64a6a734a3dede14883e"
UUID = "12345678-1234-4234-8234-123456789abc"  # Synthetic published fixture only.


def checked_peer(path):
    path = path.resolve(strict=True)
    if hashlib.sha256(path.read_bytes()).hexdigest() != PEER_SHA256:
        raise RuntimeError("Pinned test-peer checksum mismatch; refusing execution")
    return path


def build(root, package="nm-tunnel-engine", example="probe"):
    print(f"[1/2] Build project-owned {package}/{example} (locked dependencies)", flush=True)
    command = ["timeout", "--kill-after=3s", "180s", "cargo", "build", "--locked",
               "-p", package, "--example", example, "--message-format=json"]
    executable = None
    with subprocess.Popen(command, cwd=root, stdout=subprocess.PIPE, text=True) as process:
        for line in process.stdout:
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                print(line, end="", flush=True)
                continue
            if message.get("reason") == "compiler-message":
                print(message["message"].get("rendered", ""), end="", flush=True)
            if (message.get("reason") == "compiler-artifact"
                    and message.get("target", {}).get("name") == example
                    and message.get("executable")):
                executable = pathlib.Path(message["executable"]).resolve()
        if process.wait() != 0 or executable is None:
            raise RuntimeError("Engine probe build failed; no skipped pass")
    return executable


class Echo(asyncio.DatagramProtocol):
    def __init__(self):
        self.count = 0

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        self.count += 1
        self.transport.sendto(data, address)


async def readiness(peer, port):
    async with asyncio.timeout(8):
        while True:
            if peer.returncode is not None:
                raise RuntimeError("Pinned peer exited before readiness")
            try:
                _, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.close()
                await writer.wait_closed()
                return
            except ConnectionRefusedError:
                await asyncio.sleep(0)  # Yield until actual socket readiness, not a timed sleep.


async def stop(process):
    if process.returncode is None:
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), 3)
        except TimeoutError:
            process.kill()
            await process.wait()


async def inside(scratch, peer_path, probe, domain_probe=None):
    if os.environ.get("MEOW_ISOLATED_PEER_TEST") != "1" or {name for _, name in socket.if_nameindex()} != {"lo"}:
        raise RuntimeError("Refusing peer test outside a loopback-only network namespace")
    peer_path = checked_peer(peer_path)
    # Deterministic synthetic key material. No personal subscription/node input.
    private = bytes(range(32))
    der = bytes.fromhex("302e020100300506032b656e04220420") + private
    key_file = scratch / "fixture.der"
    key_file.write_bytes(der)
    public_der = subprocess.check_output(["openssl", "pkey", "-inform", "DER", "-in", str(key_file), "-pubout", "-outform", "DER"], timeout=10)
    public = base64.urlsafe_b64encode(public_der[-32:]).decode().rstrip("=")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-keyout", str(scratch / "peer.key"), "-out", str(scratch / "peer.crt"), "-days", "1",
                    "-subj", "/CN=peer.example", "-addext", "subjectAltName=DNS:peer.example"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    inbounds = []
    for port, vision in [(24444, False), (24449, True)]:
        user = {"id": UUID}
        if vision:
            user["flow"] = "xtls-rprx-vision"
        inbounds.append({"listen": "127.0.0.1", "port": port, "protocol": "vless",
                         "settings": {"clients": [user], "decryption": "none"},
                         "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {
                             "target": "127.0.0.1:24446", "serverNames": ["peer.example"],
                             "privateKey": base64.urlsafe_b64encode(private).decode().rstrip("="),
                             "shortIds": ["abababababababab"]}}})
    inbounds.append({"listen": "127.0.0.1", "port": 24446, "protocol": "vless",
                     "settings": {"clients": [{"id": UUID}], "decryption": "none"},
                     "streamSettings": {"network": "raw", "security": "tls", "tlsSettings": {
                         "certificates": [{"certificateFile": str(scratch / "peer.crt"), "keyFile": str(scratch / "peer.key")}]}}})
    config = scratch / "peer.json"
    config.write_text(json.dumps({"log": {"loglevel": "debug"}, "inbounds": inbounds,
                                  "dns": {"hosts": {"echo.fixture.invalid": "127.0.0.1"}},
                                  "outbounds": [{"protocol": "freedom", "settings": {"domainStrategy": "UseIPv4",
                                      "finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"]}]}}]}))
    echo = Echo()
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(lambda: echo, local_addr=("127.0.0.1", 24445))
    tcp_bytes = [0]
    async def tcp_echo(reader, writer):
        try:
            async with asyncio.timeout(20):
                while data := await reader.read(65536):
                    tcp_bytes[0] += len(data)
                    writer.write(data)
                    await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
    tcp_server = await asyncio.start_server(tcp_echo, "127.0.0.1", 24445)
    with (scratch / "peer.log").open("w") as log:
        peer = await asyncio.create_subprocess_exec(str(peer_path), "run", "-c", str(config), stdout=log, stderr=log)
        try:
            for port in [24444, 24449, 24446]:
                await readiness(peer, port)
            commands = [(probe, mode) for mode in ["xudp", "vision-xudp", "xudp-invalid-auth", "domain", "vision-domain"]]
            if domain_probe is not None:
                commands += [(domain_probe, mode) for mode in ["xudp-domain", "vision-xudp-domain"]]
            for executable, mode in commands:
                before = echo.count
                before_tcp = tcp_bytes[0]
                before_log = (scratch / "peer.log").stat().st_size
                env = dict(os.environ, MEOW_TEST_PUBLIC_KEY=public)
                process = await asyncio.create_subprocess_exec(str(executable), mode, env=env)
                try:
                    result = await asyncio.wait_for(process.wait(), 25)
                finally:
                    await stop(process)
                if result != 0:
                    print(f"Isolated echo datagrams during failed probe: {echo.count - before}", flush=True)
                    raise RuntimeError(f"Engine {mode} probe failed; no skipped pass")
                if mode == "xudp-invalid-auth" and echo.count != before:
                    raise RuntimeError("Invalid authentication reached the isolated echo service")
                if mode in ["xudp", "vision-xudp", "xudp-domain", "vision-xudp-domain"] and echo.count - before != 4:
                    raise RuntimeError("Required XUDP datagrams did not traverse the pinned peer")
                if mode in ["domain", "vision-domain", "xudp-domain", "vision-xudp-domain"]:
                    domain_udp = mode.endswith("xudp-domain")
                    if domain_udp and tcp_bytes[0] != before_tcp:
                        raise RuntimeError("Domain XUDP unexpectedly delivered TCP application data")
                    if not domain_udp and (echo.count != before or tcp_bytes[0] - before_tcp != 65549):
                        raise RuntimeError("Required domain TCP payload did not traverse the pinned peer")
                    log.flush()
                    with (scratch / "peer.log").open() as evidence:
                        evidence.seek(before_log)
                        wire_log = evidence.read()
                    marker = "udp:echo.fixture.invalid:24445" if domain_udp else "tcp:echo.fixture.invalid:24445"
                    if marker not in wire_log:
                        raise RuntimeError("Peer did not observe the original domain on the VLESS wire")
        finally:
            await stop(peer)
            transport.close()
            tcp_server.close()
            await tcp_server.wait_closed()


def main():
    if len(sys.argv) in [5, 6] and sys.argv[1] == "--inside":
        asyncio.run(inside(*map(pathlib.Path, sys.argv[2:])))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--peer", type=pathlib.Path, required=True)
    parser.add_argument("--domain-probe", type=pathlib.Path,
                        help="Optional explicitly built fork domain-XUDP probe; never a production backend")
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parent.parent
    for tool in ["cargo", "bwrap", "timeout", "openssl"]:
        if shutil.which(tool) is None:
            raise RuntimeError(f"Required tool unavailable: {tool}; no skipped pass")
    peer = checked_peer(args.peer)
    domain_probe = args.domain_probe.resolve(strict=True) if args.domain_probe else build(
        root, "nm-tunnel-dataplane", "xudp_domain")
    if domain_probe is not None and (not domain_probe.is_file() or not os.access(domain_probe, os.X_OK)):
        raise RuntimeError("Domain probe is not an executable file")
    probe = build(root)
    scratch_root = root / "target" / "source-peer"
    scratch_root.mkdir(parents=True, exist_ok=True)
    print("[2/2] Pinned XUDP and TCP-domain REALITY/Vision, invalid auth, bounds and cleanup", flush=True)
    with tempfile.TemporaryDirectory(prefix="isolated-", dir=scratch_root) as directory:
        scratch = pathlib.Path(directory).resolve()
        try:
            subprocess.run(["timeout", "--kill-after=3s", "160s", "bwrap", "--unshare-user", "--unshare-net", "--unshare-pid",
                        "--die-with-parent", "--ro-bind", "/", "/", "--bind", str(scratch), str(scratch),
                        "--dev", "/dev", "--proc", "/proc", "--setenv", "MEOW_ISOLATED_PEER_TEST", "1",
                         sys.executable, str(pathlib.Path(__file__).resolve()), "--inside", str(scratch), str(peer), str(probe)]
                         + ([str(domain_probe)] if domain_probe else []),
                            check=True, cwd=root)
            if domain_probe is not None:
                log = root / "target" / "xtask" / "logs" / "domain-source-peer.log"
                log.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(scratch / "peer.log", log)
                print(f"Synthetic domain wire evidence retained at {log}", flush=True)
        except subprocess.CalledProcessError:
            log = root / "target" / "xtask" / "logs" / "source-peer.log"
            log.parent.mkdir(parents=True, exist_ok=True)
            if (scratch / "peer.log").exists():
                shutil.copyfile(scratch / "peer.log", log)
            print(f"Synthetic peer diagnostics retained at {log}", flush=True)
            raise
    print("Summary: PASS; isolated XUDP and TCP-domain checks completed; no host tunnel/profile changes", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError, TimeoutError) as error:
        print(f"Summary: FAIL; {error}", file=sys.stderr, flush=True)
        sys.exit(1)
