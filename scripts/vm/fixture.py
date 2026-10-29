"""Synthetic protocol peers confined to the VM's internal network namespace."""
import asyncio
import base64
import json
from pathlib import Path
import socket
import subprocess
import sys
import time
import ssl

from dnslib import A, DNSRecord, QTYPE, RR

from contract import PEER_SHA256
from support import LAB, run, stop, wait

ECHO = "198.51.100.10"
IPV6 = "2001:db8::10"


def record(kind, **fields):
    with (LAB / "peer-events.jsonl").open("a") as stream:
        stream.write(json.dumps({"kind": kind, **fields}) + "\n")


def dns_reply(data, transport, server, client):
    request = DNSRecord.parse(data)
    record("dns", transport=transport, server=server, client=client, name=str(request.q.qname))
    reply = request.reply()
    for question in request.questions:
        if question.qtype == QTYPE.A:
            address = "192.0.2.2" if str(question.qname).lower() == "endpoint.fixture.invalid." else ECHO
            reply.add_answer(RR(question.qname, QTYPE.A, rdata=A(address), ttl=30))
    return reply.pack()


class DNS(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        self.transport.sendto(dns_reply(data, "udp", self.transport.get_extra_info("sockname")[0], address[0]), address)


class Echo(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        self.transport.sendto(data, address)


async def echo(reader, writer):
    try:
        async with asyncio.timeout(20):
            while data := await reader.read(65536):
                record("echo", source=writer.get_extra_info("peername")[0], bytes=len(data))
                writer.write(data)
                await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def dns_tcp(reader, writer):
    try:
        async with asyncio.timeout(10):
            size = int.from_bytes(await reader.readexactly(2), "big")
            if size > 4096:
                raise RuntimeError("Oversized fixture DNS query")
            reply = dns_reply(await reader.readexactly(size), "tcp", writer.get_extra_info("sockname")[0],
                              writer.get_extra_info("peername")[0])
            writer.write(len(reply).to_bytes(2, "big") + reply)
            await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def steady_echo(reader, writer):
    total = 0
    try:
        while data := await asyncio.wait_for(reader.read(65536), 20):
            writer.write(data)
            await writer.drain()
            total += len(data)
    finally:
        record("soak-echo", source=writer.get_extra_info("peername")[0], bytes=total)
        writer.close()
        await writer.wait_closed()


async def serve():
    if {name for _, name in socket.if_nameindex()} != {"lo", "peer0"}:
        raise RuntimeError("Peer namespace has unexpected interfaces")
    servers = [await asyncio.start_server(echo, address, 12345)
               for address in [ECHO, IPV6, "10.77.0.2", "10.88.0.2"]]
    servers.append(await asyncio.start_server(steady_echo, ECHO, 12346))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(LAB / "peer.crt", LAB / "peer.key")
    context.set_servername_callback(lambda _socket, name, _context: record("tls-sni", name=name))
    servers.extend([await asyncio.start_server(echo, ECHO, 443, ssl=context),
                    await asyncio.start_server(dns_tcp, "1.1.1.1", 853, ssl=context),
                    await asyncio.start_server(echo, "1.1.1.1", 443, ssl=context)])
    loop = asyncio.get_running_loop()
    transports = [await loop.create_datagram_endpoint(Echo, local_addr=(address, 12345))
                  for address in [ECHO, "10.77.0.2", "10.88.0.2"]]
    for address in ["1.1.1.1", "9.9.9.9", "192.0.2.2", "10.77.0.2"]:
        transports.append(await loop.create_datagram_endpoint(DNS, local_addr=(address, 53)))
        servers.append(await asyncio.start_server(dns_tcp, address, 53))
    (LAB / "listeners-ready").touch()
    try:
        await asyncio.Future()
    finally:
        for server in servers:
            server.close()
            await server.wait_closed()
        for transport, _ in transports:
            transport.close()


def tcp_echo(address=ECHO, size=65549, payload=None):
    payload = payload if payload is not None else bytes(i % 251 for i in range(size))
    deadline = time.monotonic() + 4
    with socket.create_connection((address, 12345), timeout=4) as stream:
        stream.settimeout(max(0.001, deadline - time.monotonic()))
        stream.sendall(payload)
        response = bytearray()
        while len(response) < len(payload):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Total TCP echo deadline")
            stream.settimeout(remaining)
            chunk = stream.recv(len(payload) - len(response))
            if not chunk:
                raise RuntimeError("Truncated TCP echo")
            response.extend(chunk)
        if response != payload:
            raise RuntimeError("TCP echo mismatch")


def udp_dns():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.settimeout(4)
        stream.connect((ECHO, 12345))
        for size in [1, 1200]:
            payload = bytes(i % 251 for i in range(size))
            stream.send(payload)
            if stream.recv(2048) != payload:
                raise RuntimeError("UDP echo mismatch")
    query = DNSRecord.question("echo.fixture.invalid", "A")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.settimeout(4)
        stream.connect(("1.1.1.1", 53))
        stream.send(query.pack())
        answer = DNSRecord.parse(stream.recv(4096))
        if answer.header.id != query.header.id or not answer.rr or str(answer.rr[0].rdata) != ECHO:
            raise RuntimeError("DNS response mismatch")


class Peers:
    def __init__(self):
        self.processes = []
        self.logs = []
        self.proxy = None

    def start_proxy(self):
        self.proxy_log = LAB / f"xray-{len(self.logs)}.log"
        log = self.proxy_log.open("w")
        self.logs.append(log)
        self.proxy = subprocess.Popen(["ip", "netns", "exec", "nmt-peer", str(LAB / "xray"),
                                       "run", "-c", str(LAB / "peer.json")], stdout=log, stderr=log)
        self.processes.append(self.proxy)
        def ready():
            if self.proxy.poll() is not None:
                raise RuntimeError("Pinned Xray exited")
            # Observe the listener in its owning namespace. A client-side dial
            # would correctly be blocked by the active unmarked-socket guard.
            listeners = run("ip", "netns", "exec", "nmt-peer", "ss", "-H", "-lntp",
                            "sport = :24444").stdout
            return f"pid={self.proxy.pid}," in listeners and "192.0.2.2:24444" in listeners
        wait(ready, 10, "Pinned REALITY listener readiness")

    def start(self):
        import hashlib
        if hashlib.sha256((LAB / "xray").read_bytes()).hexdigest() != PEER_SHA256:
            raise RuntimeError("Pinned Xray mismatch")
        run("ip", "netns", "add", "nmt-peer")
        run("ip", "link", "add", "uplink0", "type", "veth", "peer", "name", "peer0", "netns", "nmt-peer")
        run("ip", "-n", "nmt-peer", "link", "set", "lo", "up")
        for address, device in [("192.0.2.2/24", "peer0"), ("fd00::2/64", "peer0"),
                                ("10.77.0.2/24", "peer0"), ("10.88.0.2/32", "lo"),
                                ("9.9.9.9/32", "lo"), ("1.1.1.1/32", "lo"),
                                (ECHO + "/32", "lo"), (IPV6 + "/128", "lo")]:
            run("ip", "-n", "nmt-peer", "addr", "add", address, "dev", device)
        run("ip", "-n", "nmt-peer", "link", "set", "peer0", "up")
        run("nmcli", "device", "set", "uplink0", "managed", "yes")
        run("nmcli", "connection", "add", "type", "ethernet", "ifname", "uplink0", "con-name", "nmt-vm-uplink",
            "ipv4.method", "manual", "ipv4.addresses", "192.0.2.1/24,10.77.0.1/24", "ipv4.gateway", "192.0.2.2",
            "ipv4.dns", "192.0.2.2", "ipv4.route-metric", "10", "ipv6.method", "manual",
            "ipv6.addresses", "fd00::1/64", "ipv6.gateway", "fd00::2", "ipv6.may-fail", "no")
        run("nmcli", "--wait", "20", "connection", "up", "nmt-vm-uplink", timeout=25)
        def addresses_ready():
            for prefix in [[], ["-n", "nmt-peer"]]:
                addresses = json.loads(run("ip", *prefix, "-j", "addr", "show").stdout)
                for link in addresses:
                    for address in link.get("addr_info", []):
                        flags = address.get("flags", [])
                        if address.get("dadfailed") or "dadfailed" in flags:
                            raise RuntimeError("Fixture IPv6 duplicate-address detection failed")
                        if address.get("tentative") or "tentative" in flags:
                            return False
            route = json.loads(run("ip", "-j", "-6", "route", "get", IPV6).stdout)
            return route[0].get("prefsrc") == "fd00::1"
        wait(addresses_ready, 10, "Both fixture IPv6 addresses and source route ready")
        private = bytes(range(32))
        (LAB / "fixture.der").write_bytes(bytes.fromhex("302e020100300506032b656e04220420") + private)
        # DER is binary; do not pass it through the text command helper.
        public = subprocess.check_output(["openssl", "pkey", "-inform", "DER", "-in", str(LAB / "fixture.der"),
                                          "-pubout", "-outform", "DER"], timeout=5)[-32:]
        self.public_key = base64.urlsafe_b64encode(public).decode().rstrip("=")
        run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", str(LAB / "peer.key"), "-out", str(LAB / "peer.crt"), "-days", "1",
            "-subj", "/CN=peer.example", "-addext",
            "subjectAltName=DNS:peer.example,DNS:resolver.fixture.invalid,DNS:example.com")
        user = {"id": "12345678-1234-4234-8234-123456789abc"}
        config = {"log": {"loglevel": "warning"}, "inbounds": [
            {"listen": "192.0.2.2", "port": 24444, "protocol": "vless",
             "settings": {"clients": [user], "decryption": "none"}, "streamSettings": {
                 "network": "raw", "security": "reality", "realitySettings": {
                     "target": "127.0.0.1:24446", "serverNames": ["peer.example"],
                     "privateKey": base64.urlsafe_b64encode(private).decode().rstrip("="),
                     "shortIds": ["abababababababab"]}}},
            {"listen": "127.0.0.1", "port": 24446, "protocol": "vless",
             "settings": {"clients": [user], "decryption": "none"}, "streamSettings": {
                 "network": "raw", "security": "tls", "tlsSettings": {"certificates": [{
                     "certificateFile": str(LAB / "peer.crt"), "keyFile": str(LAB / "peer.key")} ]}}}],
            "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [
                {"action": "allow", "ip": ["1.1.1.1/32", "9.9.9.9/32", "10.77.0.2/32", "10.88.0.2/32", ECHO + "/32"]}]}}]}
        import copy
        vision = copy.deepcopy(config["inbounds"][0])
        vision["port"] = 24449
        vision["settings"]["clients"][0]["flow"] = "xtls-rprx-vision"
        config["inbounds"].append(vision)
        for port, network in [(24447, "raw"), (24448, "ws")]:
            inbound = copy.deepcopy(config["inbounds"][1])
            inbound["listen"], inbound["port"] = "192.0.2.2", port
            inbound["streamSettings"]["network"] = network
            if network == "ws":
                inbound["streamSettings"]["wsSettings"] = {"path": "/fixture"}
            config["inbounds"].append(inbound)
        config["dns"] = {"hosts": {name: ECHO for name in ["proxy.fixture.invalid", "echo.fixture.invalid"]}}
        config["outbounds"][0]["settings"]["domainStrategy"] = "UseIPv4"
        (LAB / "peer.json").write_text(json.dumps(config))
        log = (LAB / "listeners.log").open("w")
        self.logs.append(log)
        child = subprocess.Popen(["ip", "netns", "exec", "nmt-peer", sys.executable,
                                  str(Path(__file__)), "--serve"], stdout=log, stderr=log)
        self.processes.append(child)
        def ready():
            if child.poll() is not None:
                raise RuntimeError("DNS/echo fixture exited")
            return (LAB / "listeners-ready").exists()
        wait(ready, 10, "DNS/echo readiness")
        self.start_proxy()

    def close(self):
        for child in reversed(self.processes):
            stop(child)
        for log in self.logs:
            log.close()


if __name__ == "__main__":
    if sys.argv[1:] != ["--serve"] or not (LAB / "authorized").is_file():
        raise SystemExit("Guest fixture authorization required")
    asyncio.run(serve())
