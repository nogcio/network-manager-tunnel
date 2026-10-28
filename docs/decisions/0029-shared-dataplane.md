# ADR 0029: Shared data plane and explicit platform capabilities

Status: implemented structural extraction; existing acceptance limits remain.

## Context

The protocol engine was independent of NM, but packet scheduling, flow dispatch,
DNS and FakeIP identities lived in the Linux service alongside privileged resource
management. Reusing these semantics should not require reusing Linux IPC or moving
physical socket authority into an unprivileged packet worker.

## Decision

Introduce the workspace-local `nm-tunnel-dataplane` package in the existing `engine`
layer, consumed now by `nm-service`. It depends on the model and protocol engine,
not on NM schemas, D-Bus, desktop toolkits or the integration layer. It owns the
library netstack/packet loop, flow scheduling, TCP/UDP routing/execution, DNS
messages/interception, FakeIP destination handling, append-only identity semantics
and selected-resolver cache/Direct checks.

Capabilities correspond to existing consumers, not a platform plugin registry:

- `PacketIo`: an already configured packet device, not TUN creation or route control.
- `Host`: approved endpoint connections, confined non-proxy payload channels and
  activation-selected DNS/FakeIP operations. Requests are never authorization.
- `LanScope`: local eligibility, separate from independent privileged verification.
- `Observer` / `Flow`: nonblocking traffic observations and drop-owned active counts.
- `source_dns::Exchange`: selected DNS transport with platform-owned bypass/bootstrap.
- FakeIP durable-append callback: synchronous durable publication, not path/lock policy.

Linux retains NM profile/activation ownership, TUN allocation, marked sockets,
nftables guards, Secret Service/NM secret boundaries, private Unix/FD transport,
root authorization, storage namespace/permissions/locks/fsync, telemetry delivery,
health reporting and systemd recovery. The supervisor consumes shared pure
authorization semantics with its own profile/cache; it never trusts worker decisions.

## Preserved contracts and consequences

Legacy LAN-before-sniffing and complete DNS/signature-before-FakeIP order remain
distinct. Refusal never changes outbound/resolver. Limits, timeouts, packet counters,
schema v1/v2, FakeIP journal bytes/allocation order and exchange-poisoning behavior
are retained. Readiness failure now also passes through the explicit packet-pump
join/stack teardown path, rather than relying only on JoinSet drop and process exit.
Existing external process-exit/resource teardown barriers remain required.

The extraction reuses locked dependencies and native code; it does not establish
cross-platform compilation. Android/macOS implementations, UI, FFI bridges,
packaging, new networking behavior and cross-builds are outside this change.
Core contracts run with synthetic non-IPC capabilities; Linux broker/storage tests
remain with the service. Full workspace checks do not replace deployed packet,
interoperability, privileged DNS or security acceptance.
