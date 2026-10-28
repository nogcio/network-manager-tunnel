#!/usr/bin/env python3
"""Compare project routing with pinned sing-box in a rootless loopback namespace."""
import argparse
import asyncio
import hashlib
import json
import os
import pathlib
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile

PEER_SHA256 = "84b23a2304a6c4efa41dc027a78b7226a94ef6c63566b56a5a2721bdfe473446"
UUID = "12345678-1234-4234-8234-123456789abc"  # Published synthetic credential only.
NAMES = ("block.example", "direct.example", "proxy.example")


def checked_peer(path):
    path = path.resolve(strict=True)
    if hashlib.sha256(path.read_bytes()).hexdigest() != PEER_SHA256:
        raise RuntimeError("Pinned sing-box v1.12.0 peer digest mismatch")
    return path


def build(root):
    executable = None
    args = ["timeout", "--kill-after=3s", "180s", "cargo", "build", "--locked", "-p",
            "nm-tunnel-dataplane", "--example", "route_semantics", "--message-format=json"]
    with subprocess.Popen(args, cwd=root, stdout=subprocess.PIPE, text=True) as process:
        for line in process.stdout:
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                print(line, end="", flush=True)
                continue
            if message.get("reason") == "compiler-message":
                print(message["message"].get("rendered", ""), end="", flush=True)
            if (message.get("reason") == "compiler-artifact"
                    and message.get("target", {}).get("name") == "route_semantics"
                    and message.get("executable")):
                executable = pathlib.Path(message["executable"]).resolve()
        if process.wait() != 0 or executable is None:
            raise RuntimeError("Project probe build failed; no skipped pass")
    return executable


async def command(*args):
    process = await asyncio.create_subprocess_exec(*map(str, args), stdout=asyncio.subprocess.PIPE,
                                                 stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(process.communicate(), 5)
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()
    if process.returncode:
        raise RuntimeError(f"Synthetic probe failed ({process.returncode}): {err.decode()}")
    return out.decode().strip()


async def stop(process):
    if process.returncode is None:
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), 3)
        except TimeoutError:
            process.kill()
            await process.wait()


async def readiness(process):
    async with asyncio.timeout(5):
        while True:
            if process.returncode is not None:
                raise RuntimeError("Peer exited before readiness")
            try:
                _, writer = await asyncio.open_connection("127.0.0.1", 15480)
                writer.close()
                await writer.wait_closed()
                return
            except ConnectionRefusedError:
                await asyncio.sleep(0)  # Yield until actual socket readiness.


def prefix(kind, name):
    if kind == "http":
        return f"GET / HTTP/1.1\r\nHost: {name}\r\n\r\n".encode()
    if kind == "tls":
        outgoing = ssl.MemoryBIO()
        client = ssl.create_default_context().wrap_bio(ssl.MemoryBIO(), outgoing,
                                                     server_hostname=name)
        try:
            client.do_handshake()
        except ssl.SSLWantReadError:
            pass
        return outgoing.read()
    return b""


def configuration():
    return {
        "log": {"level": "debug", "timestamp": False},
        "dns": {"servers": [{"tag": "real", "address": "udp://127.0.0.1:15353"},
                            {"tag": "fake", "address": "fakeip"}],
                "rules": [{"query_type": ["A", "AAAA"], "server": "fake"}],
                "final": "real", "independent_cache": True,
                "fakeip": {"enabled": True, "inet4_range": "198.18.0.0/16"}},
        "inbounds": [{"type": "mixed", "tag": "input", "listen": "127.0.0.1",
                      "listen_port": 15480},
                     {"type": "direct", "tag": "dns-input", "listen": "127.0.0.1",
                      "listen_port": 15354, "network": "udp",
                      "override_address": "1.1.1.1", "override_port": 53}],
        "outbounds": [{"type": "direct", "tag": "direct"},
                      {"type": "vless", "tag": "proxy", "server": "127.0.0.1",
                       "server_port": 15444, "uuid": UUID},
                      {"type": "block", "tag": "block"}],
        "route": {"final": "proxy", "rules": [
            {"action": "sniff"},
            {"type": "logical", "mode": "or", "rules": [{"protocol": "dns"}, {"port": 53}],
             "action": "hijack-dns"},
            {"protocol": "bittorrent", "outbound": "block"},
            {"domain": ["block.example"], "outbound": "block"},
            {"domain": ["direct.example"], "outbound": "direct"},
            {"ip_is_private": True, "outbound": "direct"}]} }


async def observe_peer(fake, payload):
    reader, writer = await asyncio.open_connection("127.0.0.1", 15480)
    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        if await reader.readexactly(2) != b"\x05\x00":
            raise RuntimeError("SOCKS fixture negotiation failed")
        writer.write(b"\x05\x01\x00\x01" + socket.inet_aton(fake) + (8443).to_bytes(2, "big"))
        await writer.drain()
        reply = await asyncio.wait_for(reader.readexactly(10), 2)
        if reply[:2] != b"\x05\x00":
            raise RuntimeError("SOCKS fixture CONNECT failed")
        writer.write(payload)
        await writer.drain()
        try:
            await asyncio.wait_for(reader.read(), 2)
        except TimeoutError:
            pass  # Classification is observed in the bounded peer log below.
    finally:
        writer.close()
        await writer.wait_closed()


async def inside(scratch, peer, probe):
    if os.environ.get("NMTUN_ISOLATED_SEMANTICS") != "1" or {name for _, name in socket.if_nameindex()} != {"lo"}:
        raise RuntimeError("Refusing execution outside a loopback-only network namespace")
    checked_peer(peer)
    config = scratch / "peer.json"
    config.write_text(json.dumps(configuration()))
    rows = []
    with (scratch / "peer.log").open("w") as log:
        process = await asyncio.create_subprocess_exec(str(peer), "run", "-c", str(config), stdout=log, stderr=log)
        try:
            await readiness(process)
            for kind in ["http", "tls", "none"]:
                for original in NAMES:
                    for observed in (NAMES if kind != "none" else ["none"]):
                        fake = await command(probe, "allocate", original, "none", "[]")
                        payload = prefix(kind, observed)
                        offset = (scratch / "peer.log").stat().st_size
                        async with asyncio.timeout(4):
                            await observe_peer(fake, payload)
                        with (scratch / "peer.log").open() as reader:
                            reader.seek(offset)
                            evidence = reader.read()
                        evidence = re.sub(r"\x1b\[[0-9;]*m", "", evidence)
                        ids = re.findall(r"\[(\d+) [^\]]+\] inbound/mixed\[input\]: inbound connection to "
                                         + re.escape(fake) + r":8443", evidence)
                        if len(ids) != 1:
                            raise RuntimeError("Missing or ambiguous fixture connection identity")
                        evidence = "\n".join(line for line in evidence.splitlines() if f"[{ids[0]} " in line)
                        if kind != "none" and f"domain: {observed}" not in evidence:
                            raise RuntimeError(f"Peer did not sniff the supplied fixture: {kind}/{observed}: {evidence}")
                        # Match selected final rules/outbounds, not a successful connection.
                        if "=> route(block)" in evidence or "outbound/block[block]" in evidence:
                            oracle = "block"
                        elif "=> route(direct)" in evidence or "outbound/direct[direct]" in evidence:
                            oracle = "direct"
                        elif "outbound/vless[proxy]" in evidence:
                            oracle = "proxy"
                        else:
                            raise RuntimeError(f"Missing route evidence for {kind}/{original}/{observed}: {evidence}")
                        actual = json.loads(await command(probe, "tcp", original, observed, json.dumps(list(payload))))
                        expected_dns = int(oracle == "direct")
                        if actual["dns_queries"] != expected_dns:
                            raise RuntimeError("Unexpected destination DNS for the selected TCP route")
                        row = {"kind": kind, "original": original, "observed": observed,
                               "sing_box": oracle, "project": actual["route"], "dns_queries": actual["dns_queries"]}
                        rows.append(row)
                        print(("PASS" if oracle == actual["route"] else "MISMATCH"), kind, original, observed,
                              f"sing-box={oracle} project={actual['route']}", flush=True)
        finally:
            await stop(process)
    (scratch / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
    mismatches = sum(row["sing_box"] != row["project"] for row in rows)
    if mismatches:
        raise RuntimeError(f"{mismatches}/{len(rows)} route differences; evidence retained in {scratch}")
    print(f"Summary: PASS {len(rows)} TCP route comparisons; not wire or deployed acceptance", flush=True)


def main():
    if len(sys.argv) == 5 and sys.argv[1] == "--inside":
        asyncio.run(inside(*map(pathlib.Path, sys.argv[2:])))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--peer", type=pathlib.Path, required=True)
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parent.parent
    for tool in ["cargo", "bwrap", "timeout"]:
        if shutil.which(tool) is None:
            raise RuntimeError(f"Required tool unavailable: {tool}; no skipped pass")
    peer = checked_peer(args.peer)
    print("[1/2] Build project-owned synthetic route probe", flush=True)
    probe = build(root)
    parent = root / "target" / "route-semantics"
    parent.mkdir(parents=True, exist_ok=True)
    scratch = pathlib.Path(tempfile.mkdtemp(prefix="isolated-", dir=parent)).resolve()
    print(f"[2/2] Compare pinned peer; synthetic evidence: {scratch}", flush=True)
    subprocess.run(["timeout", "--kill-after=3s", "110s", "bwrap", "--unshare-user", "--unshare-net", "--unshare-pid",
                    "--die-with-parent", "--ro-bind", "/", "/", "--bind", str(scratch), str(scratch),
                    "--dev", "/dev", "--proc", "/proc", "--setenv", "NMTUN_ISOLATED_SEMANTICS", "1",
                    sys.executable, str(pathlib.Path(__file__).resolve()), "--inside", str(scratch), str(peer),
                    str(probe)], cwd=root, check=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError, TimeoutError) as error:
        print(f"Summary: FAIL; {error}", file=sys.stderr, flush=True)
        sys.exit(1)
