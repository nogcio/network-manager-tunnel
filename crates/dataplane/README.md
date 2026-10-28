# Shared data plane

`nm-tunnel-dataplane` owns the existing IPv4 packet/flow pipeline independently of
NetworkManager and Linux resource management. The production consumer is the NM
service's unprivileged worker; the supervisor also consumes DNS/identity logic.
This is an architectural extraction, not a new platform client or stable API.

## Owners and capabilities

- `runtime`: pinned library netstack, packet pumps, bounded flow admission/queues,
  UDP deadlines and QUIC inspection scheduling. `PacketIo` supplies an already
  configured packet device. `Observer` only counts traffic and owns flow leases.
- `stream` / `datagram`: one outbound executor per flow, preserving legacy and
  complete-policy classification order, prefix replay and no-fallback behavior.
- `routing`: pure intended decisions over checked profile policy and `LanScope`.
  Neither a decision nor a worker LAN snapshot grants physical socket authority.
- `inspection`: bounded DNS/signature classification and owned prefix replay.
- `resolver` / `destination`: DNS interception and owned FakeIP resolution before
  application outbound admission, through explicitly supplied `Host` operations.
- `dns`: library message parsing, validation, question/answer-chain binding and framing.
- `source_dns`: activation-local selected-resolver cache, TTL aging and independent
  complete-policy Direct authorization. `Exchange` supplies platform DNS transport.
- `fakeip`: library-backed append-only identities, deterministic journal restoration
  and DNS answers. Publication requires a successful durable append callback.

`Host` returns approved endpoint connections and destination-confined payload
channels. It must independently authorize non-proxy requests, preserve endpoint
bypass and redact errors. No implicit host resolver, socket creation or direct
fallback exists here. NM's adapter keeps IP sockets in the root supervisor and
exports only Unix payload channels; serialized exchange poisoning stays there.

## Ownership, cancellation and storage

Flow futures own their streams; cancellation drops them without replay/redial.
Runtime termination aborts and joins owned flow/pump tasks, then waits up to two
seconds for library stack teardown, as before. Dropping the runtime future aborts
its JoinSets, but is not a confirmed platform teardown barrier: the integration
must retain guards/resources until worker exit. One lwIP core is allowed per worker
process. Readiness and health are platform-supplied futures, not route/DNS owners.

FakeIP allocation is synchronous through durable publication. A failed or ambiguous
append poisons all identity reads/writes until reopen. Invalid journals never reset,
and published addresses never expire or get reused. The platform owns exclusive
locking, trusted storage paths, permissions, journal creation/fsync and blocking-I/O
scheduling. Existing Linux namespace checks, migration refusal and format remain
unchanged. No plaintext credential/profile database is introduced.

TUN allocation, routes, DNS installation, firewall guards, socket protection,
uplink discovery, IPC, root/worker separation and recovery remain in `nm-service`.
The core uses the existing pinned protocol/netstack libraries and introduces no
new external package versions, FFI exception or platform implementation.

## Verification

```sh
cargo test --locked -p nm-tunnel-dataplane --all-targets
cargo xtask check --non-interactive
cargo xtask features --non-interactive
```

Core contracts use synthetic capabilities and an in-memory packet device, without
NM, Unix IPC, root or a kernel TUN. Linux broker/storage regressions remain in the
service. These checks do not establish packet interoperability, deployed security
acceptance or operation on other platforms; no cross-build is part of this refactor.

The optional [pinned sing-box route comparison](../../docs/research/sing-box-compatibility.md)
checks complete-policy FakeIP/HTTP Host/TLS SNI name precedence in a rootless
loopback namespace. It is an explicit test-peer command, not part of ordinary
checks or a production backend. UDP supplied-name precedence, original-name DNS
and independent Direct refusal have ordinary regression contracts. Wire FQDN
forwarding for complete-policy TCP Proxy with inherited DNS preserves the owned original name
without destination DNS. Only an explicit Direct domain rule resolves that name;
its IP still needs independent authorization. Unresolved FQDNs do not match IP-only
rules. Explicit DNS overrides retain pre-resolution. Legacy and UDP behavior remain
unchanged. The engine's isolated peer probe
checks TCP-domain wire forwarding separately; full packet/deployed parity remains
unaccepted, and domain-addressed XUDP still needs a library API change.
