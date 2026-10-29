"""Shared guest-only observation of NM's standard keyfile secret boundary."""
import configparser
from pathlib import Path


def assert_no_system_secret(identifier):
    matched = 0
    for path in Path("/etc/NetworkManager/system-connections").iterdir():
        config = configparser.ConfigParser(interpolation=None)
        config.read(path)
        if config.get("connection", "uuid", fallback="") == identifier:
            matched += 1
            if config.has_option("vpn-secrets", "uuid"):
                raise RuntimeError("Agent/not-saved credential was written into NM system storage")
    if matched != 1:
        raise RuntimeError("Persistent fixture settings were not observed exactly once")
