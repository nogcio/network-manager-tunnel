"""Complete native policy and destination-free readiness in the real guest path."""
from fixture import ECHO, tcp_echo
from features import events, query, rejected_stream, udp_echo
from support import LAB, active, guards_present, run, wait


def fake_address(name):
    response = query(name)
    if len(response.rr) != 1:
        raise RuntimeError("Expected one owned source FakeIP answer")
    return str(response.rr[0].rdata)


class SourceScenarios:
    def __init__(self, features):
        self.features = features
        self.suite = features.suite

    def source_dns_routes(self):
        for mode in ["source-udp-proxy", "source-udp-direct", "source-tcp-proxy", "source-tcp-direct"]:
            before = len(events())
            with self.features.profile(mode):
                wire_log = self.suite.peers.proxy_log
                wire_offset = wire_log.stat().st_size
                if events()[before:]:
                    raise RuntimeError("Source activation queried a resolver or destination")
                proxy = fake_address("proxy.fixture.invalid")
                direct = fake_address("direct.fixture.invalid")
                block = fake_address("block.fixture.invalid")
                def traffic():
                    tcp_echo(proxy)
                    udp_echo(proxy)
                    tcp_echo(direct)
                    udp_echo(direct)
                    for label, address, payload in [
                        ("domain Block", block, b"synthetic blocked source flow"),
                        ("sniff Block", proxy, b"GET / HTTP/1.1\r\nHost: block.fixture.invalid\r\n\r\n"),
                        ("BitTorrent Block", proxy, b"\x13BitTorrent protocol" + bytes(48)),
                    ]:
                        checkpoint = len(events())
                        rejected_stream(address, payload)
                        observed = events()[checkpoint:]
                        if any(e["kind"] in ["echo", "dns"] for e in observed):
                            raise RuntimeError("Source " + label + " reached an outbound: " + repr(observed))
                required = ["tcp and dst port 24444", "dst host 198.51.100.10 and dst port 12345"]
                forbidden = ["dst net 198.18.0.0/15", "ip6 and dst host 2001:db8::10"]
                if mode.endswith("direct"):
                    required.append("dst host 1.1.1.1 and dst port 53")
                    forbidden.append("dst port 53 and not dst host 1.1.1.1")
                else:
                    forbidden.append("dst port 53")
                self.suite.capture(mode, traffic, required=required, forbidden=forbidden)
                # Echo alone could pass after a regression to IP-address proxy
                # requests. Require fresh peer-side evidence of both original
                # names, including the UDP/XUDP request, for every resolver mode.
                def named_requests():
                    wire = wire_log.read_bytes()[wire_offset:]
                    return all(marker in wire for marker in [
                        b"accepted tcp:proxy.fixture.invalid:12345",
                        b"accepted udp:proxy.fixture.invalid:12345",
                    ])
                wait(named_requests, 5, "Peer-confirmed original TCP/XUDP destination names")
                expected_transport = "tcp" if "tcp" in mode else "udp"
                expected_client = "192.0.2.1" if mode.endswith("direct") else "1.1.1.1"
                dns = [e for e in events()[before:] if e["kind"] == "dns"]
                if not dns or any(e["transport"] != expected_transport or e["client"] != expected_client for e in dns):
                    raise RuntimeError("Source resolver transport/detour mismatch: " + mode)

    def source_dns_certificate_refusal(self):
        for mode in ["source-dot-untrusted", "source-doh-untrusted"]:
            before = len(events())
            with self.features.profile(mode):
                if events()[before:]:
                    raise RuntimeError("Source activation contacted a DNS or destination peer: " + mode + ": " + repr(events()[before:]))
                direct = fake_address("direct.fixture.invalid")
                self.suite.capture(mode, lambda: rejected_stream(direct, b"synthetic Direct DNS certificate refusal"))
                observed = events()[before:]
                if not any(e["kind"] == "tls-sni" and e["name"] == "resolver.fixture.invalid" for e in observed):
                    raise RuntimeError("Configured DNS TLS verification was not exercised")
                if any(e["kind"] in ["dns", "echo"] for e in observed):
                    raise RuntimeError("Untrusted DNS reached a destination or alternate resolver")
                if not active() or not guards_present():
                    raise RuntimeError("DNS flow refusal removed protection")

    def readiness_no_destination_egress(self):
        # A deliberately untrusted DNS endpoint must not be contacted until a
        # real flow needs it. Observe a fresh periodic endpoint handshake too,
        # rather than merely checking that initial activation was quiet.
        before = len(events())
        with self.features.profile("source-doh-untrusted"):
            label = "readiness-no-egress"
            expression = "tcp and dst port 24444 and tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn"
            def observe_health():
                def handshaking():
                    capture = run("tcpdump", "-n", "-r", str(LAB / (label + ".pcap")), expression, check=False)
                    return capture.returncode == 0 and bool(capture.stdout.strip())
                wait(handshaking, 27, "Fresh periodic configured-endpoint handshake")
                if events()[before:]:
                    raise RuntimeError("Readiness/health generated DNS or destination traffic")
                if not active() or not guards_present():
                    raise RuntimeError("Endpoint-only health lost its session")
            self.suite.capture(label, observe_health)
