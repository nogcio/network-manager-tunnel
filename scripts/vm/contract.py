"""Versioned acceptance protocol shared by host and guest, without native imports."""
VERSION = 7
# Bounded aggregate for required lifecycle plus source-routing packet captures.
MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
MAX_PACKET_BYTES = 4 * 1024 * 1024
MAX_EVENT_BYTES = ((MAX_PACKET_BYTES + 2) // 3) * 4 + 4096


def packet_limit(name):
    return MAX_PACKET_BYTES if name == "steady-traffic.pcap" else 512 * 1024


PEER_SHA256 = "a27e3f95ab6ce270956d0cecd32eda4686a811afc71c64a6a734a3dede14883e"
# Ordered lifecycle: scenarios explicitly establish/retire the session they own.
# A failed prerequisite ends the suite; no dependent case is reported as passed.
CORE_CASES = ("baseline-paths", "storage", "native-tcp-udp-dns", "physical-isolation", "clean-disconnect",
         "worker-crash", "backend-crash", "backend-hang", "recovery-restart",
         "endpoint-refusal", "active-image-replacement", "tun-collision",
         "vision-transport", "manual-dns", "dns-interception", "connected-lan",
         "private-lan", "combined-lan", "domain-rule-actions", "fakeip-persistence",
         "invalid-auth-flow-refusal", "tls-certificate-refusal", "websocket-certificate-refusal",
          "source-dns-certificate-refusal", "active-profile-isolation", "uplink-loss-retention",
         "preparation-cancellation", "unprivileged-bus-boundary",
         "network-dns", "traffic-telemetry", "source-dns-routes", "readiness-no-destination-egress",
         "persistent-uplink-recovery", "persistent-source-recovery", "desktop-secret-agent")
SUITES = {"core": CORE_CASES, "dhcp": ("dhcp-lease-recovery",), "power": ("suspend-resume",),
          "desktop": ("real-desktop-keyring",), "soak": ("steady-traffic",),
          "terminal": ("persistent-terminal-retention",)}
CASES = CORE_CASES + SUITES["dhcp"] + SUITES["power"] + SUITES["desktop"] + SUITES["soak"] + SUITES["terminal"]
SUITES["full"] = CASES
SUITES["power-soak"] = SUITES["power"] + SUITES["soak"]
SUITES["desktop-soak"] = SUITES["desktop"] + SUITES["soak"]
SUITES["fail-closed"] = ("baseline-paths", "native-tcp-udp-dns", "clean-disconnect",
                         "worker-crash", "backend-crash", "backend-hang",
                         "recovery-restart", "persistent-terminal-retention")
SUITES["platform-power"] = ("platform-s3-idle",)
SUITES["platform-idle"] = ("platform-idle",)
