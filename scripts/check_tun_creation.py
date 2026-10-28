#!/usr/bin/env python3
"""Explicit rootless kernel regression for production TUN creation and collision."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys


def run(*args):
    return subprocess.check_output(args, text=True, timeout=10)


def inside(binary):
    parent = os.environ.get('NMT_TEST_PARENT_NETNS')
    if (not parent or os.readlink('/proc/self/ns/net') == parent
            or os.geteuid() != 0
            or {name for _, name in socket.if_nameindex()} != {'lo'}):
        raise RuntimeError('Fresh isolated root-mapped network namespace required')
    # Include the kernel's first automatic name as well as our public name.
    for name in ['tun0', 'nmtun0']:
        run('ip', 'tuntap', 'add', 'dev', name, 'mode', 'tun')
        run('ip', 'address', 'add', '192.0.2.1/32', 'dev', name)
        run('ip', 'link', 'set', 'dev', name, 'up')
    before = json.loads(run('ip', '-j', 'address', 'show'))
    subprocess.run([str(binary), 'reject'], check=True, timeout=10)
    assert json.loads(run('ip', '-j', 'address', 'show')) == before
    print('PASS occupied interfaces retain identity, flags and addresses; no temporary TUN remains', flush=True)
    run('ip', 'tuntap', 'delete', 'dev', 'nmtun0', 'mode', 'tun')
    before = json.loads(run('ip', '-j', 'address', 'show'))
    subprocess.run([str(binary), 'race'], check=True, timeout=10)
    assert json.loads(run('ip', '-j', 'address', 'show')) == before
    run('ip', 'tuntap', 'delete', 'dev', 'tun0', 'mode', 'tun')
    assert {name for _, name in socket.if_nameindex()} == {'lo'}
    print('PASS simultaneous creation has one winner; owned devices removed on drop', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if args.inside:
        inside(binary)
        return
    if os.geteuid() == 0:
        raise RuntimeError('Run this rootless probe as an unprivileged user')
    print('Checking production TUN creation in a fresh rootless namespace', flush=True)
    subprocess.run([
        'timeout', '--kill-after=3s', '30s', 'bwrap',
        '--unshare-user', '--uid', '0', '--gid', '0', '--unshare-net',
        '--unshare-pid', '--die-with-parent', '--ro-bind', '/', '/',
        '--dev', '/dev', '--dev-bind', '/dev/net/tun', '/dev/net/tun',
        '--proc', '/proc', '--cap-add', 'CAP_NET_ADMIN',
        '--setenv', 'NMT_TEST_PARENT_NETNS', os.readlink('/proc/self/ns/net'),
        sys.executable, str(Path(__file__).resolve()), '--inside', '--binary', str(binary),
    ], check=True, timeout=35)


if __name__ == '__main__':
    main()
