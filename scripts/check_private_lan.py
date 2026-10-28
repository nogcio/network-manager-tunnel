#!/usr/bin/env python3
"""Explicit synthetic nft adapter check in nested disposable network namespaces."""
import argparse
import asyncio
import os
import pathlib
import socket
import subprocess
import sys

MARK = 0x4e4d5401


def ip(*args):
    subprocess.run(['ip', *args], check=True, timeout=5)


def require_fresh_namespace():
    if {name for _, name in socket.if_nameindex()} != {'lo'} or os.geteuid() != 0:
        raise RuntimeError('Refusing outside a fresh isolated root-mapped network namespace')


class Echo(asyncio.DatagramProtocol):
    def __init__(self, answer):
        self.answer = answer

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        self.transport.sendto(self.answer, address)


async def tcp_echo(reader, writer, answer):
    try:
        await asyncio.wait_for(reader.read(32), 3)
        writer.write(answer)
        await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def listeners(hosts, answer):
    servers, transports = [], []
    for host, port in hosts:
        servers.append(await asyncio.start_server(lambda r, w: tcp_echo(r, w, answer), host, port))
        if port == 53:
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: Echo(answer), local_addr=(host, port))
            transports.append(transport)
    return servers, transports


async def peer():
    require_fresh_namespace()
    ip('link', 'set', 'lo', 'up')
    print('namespace-ready', flush=True)
    if sys.stdin.readline().strip() != 'configure':
        raise RuntimeError('Missing isolated peer configuration')
    for address in ['192.168.68.1/24', '10.2.2.1/32', '203.0.113.1/32', '198.19.0.3/32']:
        ip('addr', 'add', address, 'dev', 'linkpeer')
    ip('link', 'set', 'linkpeer', 'up')
    ip('-6', 'addr', 'add', 'fd00::1/64', 'dev', 'linkpeer', 'nodad')
    ip('addr', 'add', '198.18.0.2/30', 'dev', 'tunpeer')
    ip('link', 'set', 'tunpeer', 'up')
    servers, transports = await listeners([('192.168.68.1', 53), ('192.168.68.1', 18080),
                     ('10.2.2.1', 18080), ('203.0.113.1', 18080),
                     ('198.19.0.3', 18080), ('fd00::1', 18080)], b'physical')
    selected_servers, selected_transports = await listeners([('198.18.0.2', 53)], b'selected-resolver')
    print('listeners-ready', flush=True)
    await asyncio.Future()


def exchange(host, port, udp=False, marked=False):
    kind = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET, kind) as client:
        client.settimeout(2)
        if marked:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, MARK)
        client.connect((host, port))
        client.sendall(b'synthetic-adapter-check')
        return client.recv(64)


async def denied(host, port, marked=False):
    try:
        await asyncio.to_thread(exchange, host, port, False, marked)
    except TimeoutError:
        return
    raise RuntimeError('Forbidden destination bypassed the isolated guard')


async def inside(rules):
    require_fresh_namespace()
    process = await asyncio.create_subprocess_exec('unshare', '--net', sys.executable,
        str(pathlib.Path(__file__).resolve()), '--peer', stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE)
    try:
        assert await asyncio.wait_for(process.stdout.readline(), 5) == b'namespace-ready\n'
        ip('link', 'add', 'uplink0', 'type', 'veth', 'peer', 'name', 'linkpeer')
        ip('link', 'set', 'linkpeer', 'netns', str(process.pid))
        ip('addr', 'add', '192.168.68.109/24', 'dev', 'uplink0')
        ip('link', 'set', 'uplink0', 'up')
        ip('-6', 'addr', 'add', 'fd00::2/64', 'dev', 'uplink0', 'nodad')
        ip('link', 'add', 'nmtun0', 'type', 'veth', 'peer', 'name', 'tunpeer')
        ip('link', 'set', 'tunpeer', 'netns', str(process.pid))
        ip('addr', 'add', '198.18.0.1/30', 'dev', 'nmtun0')
        ip('link', 'set', 'nmtun0', 'up')
        for address in ['10.2.2.0/24', '203.0.113.1/32', '198.19.0.3/32']:
            ip('route', 'add', address, 'via', '192.168.68.1')
        # Reproduce the NM-created DNS/gateway host route that beat TUN capture.
        ip('route', 'add', '192.168.68.1/32', 'dev', 'uplink0')
        process.stdin.write(b'configure\n')
        await process.stdin.drain()
        assert await asyncio.wait_for(process.stdout.readline(), 5) == b'listeners-ready\n'
        subprocess.run(['nft', '-f', str(rules)], check=True, timeout=5)
        for host in ['192.168.68.1', '10.2.2.1']:
            assert await asyncio.to_thread(exchange, host, 18080) == b'physical'
        for udp in [False, True]:
            assert await asyncio.to_thread(exchange, '192.168.68.1', 53, udp) == b'selected-resolver'
            assert await asyncio.to_thread(exchange, '192.168.68.1', 53, udp, True) == b'physical'
        # A public physical destination is blocked, while the root's marked socket
        # remains available. This is a synthetic peer, never external networking.
        assert await asyncio.to_thread(exchange, '203.0.113.1', 18080, False, True) == b'physical'
        await denied('203.0.113.1', 18080)
        await denied('198.19.0.3', 18080, True)
        await denied('fd00::1', 18080, True)
        # Even a more-specific bad physical route for the translated internal DNS
        # must not turn the OUTPUT exception into a synthetic-address leak.
        ip('route', 'add', '198.18.0.2/32', 'via', '192.168.68.1')
        await denied('192.168.68.1', 53)
        ip('route', 'del', '198.18.0.2/32')
        subprocess.run(['nft', 'delete', 'table', 'inet', 'nm_tunnel'], check=True, timeout=5)
        subprocess.run(['nft', 'delete', 'table', 'inet', 'nm_tunnel_fakeip'], check=True, timeout=5)
        # No stale DNAT/conntrack grant may keep a new DNS socket hijacked after
        # teardown; never flush unrelated conntrack state as a shortcut.
        assert await asyncio.to_thread(exchange, '192.168.68.1', 53) == b'physical'
        print('PASS: private/routed LAN, gateway /32, TCP/UDP DNS precedence, marked bootstrap, public/IPv6/FakeIP blocking, bad-egress refusal and clean teardown', flush=True)
    except Exception:
        subprocess.run(['nft', 'list', 'ruleset'], check=False, timeout=5)
        subprocess.run(['ip', '-4', 'route', 'show', 'table', 'all'], check=False, timeout=5)
        raise
    finally:
        if process.returncode is None:
            process.terminate()
        await asyncio.wait_for(process.wait(), 5)


def main():
    if sys.argv[1:] == ['--peer']:
        asyncio.run(peer())
        return
    if len(sys.argv) == 3 and sys.argv[1] == '--inside':
        asyncio.run(inside(pathlib.Path(sys.argv[2])))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rules', type=pathlib.Path, required=True)
    args = parser.parse_args()
    rules = args.rules.resolve(strict=True)
    print('Checking generated production rules in isolated namespaces; no host networking changes.', flush=True)
    subprocess.run(['timeout', '--kill-after=3s', '45s', 'bwrap', '--unshare-user', '--uid', '0', '--gid', '0',
        '--unshare-net', '--unshare-pid', '--die-with-parent', '--ro-bind', '/', '/', '--dev', '/dev', '--proc', '/proc',
        '--cap-add', 'CAP_NET_ADMIN', '--cap-add', 'CAP_SYS_ADMIN', '--cap-add', 'CAP_NET_BIND_SERVICE',
        sys.executable, str(pathlib.Path(__file__).resolve()), '--inside', str(rules)], check=True)
    print('Summary: PASS; isolated private-LAN kernel adapter checks completed.', flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'Summary: FAIL; {type(error).__name__}: {error}', file=sys.stderr, flush=True)
        sys.exit(1)
