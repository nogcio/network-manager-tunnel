# ADR 0006: Experimental NM runtime and packet adaptation

Status: implemented experimentally; production acceptance pending.
Date: 2026-10-25.

## Context

The supplied-socket stream engine needs both an NM lifecycle owner and an IP-to-stream
adapter. Initial integration was exercised in a disposable Linux VM, not a host
tunnel. `meow-lwip` was selected from the same pinned maintained fork after
review found an unconditional, unsound `Send` implementation in
`netstack-smoltcp 0.2.4`. The latter is not a workspace dependency.

## Decision

Use the existing pinned meow fork's `meow-lwip` package for experimental IPv4 TCP/UDP
adaptation. It includes upstream C lwIP with a Rust single-owner-core wrapper;
one worker process owns one stack. Preserve its BSD-3-Clause and upstream notices.
Workspace Rust remains safe-only; unsafe/FFI in dependencies is not an exception to
that rule and still needs source, maintenance and security review before release.

`nm-tunnel-service` owns activation, resource cleanup and the private socket broker.
Use `tun-rs =2.8.13` without default features for privileged TUN creation and safe
owned-FD cloning; use `async-io =2.6.0` for safe `AsFd`-based worker registration.
Use existing `rustix` safe FD-transfer APIs, not local unsafe adoption. The default
`tun-rs` address-management feature is disabled; NM remains the route/DNS owner.

Root handles TUN/firewall/uplink-bound marked sockets. A `setpriv` child drops UID,
GID, groups and capabilities before parsing protocols and packets. No external
core is launched by production code. Xray is restricted to explicit pinned
synthetic interoperability fixtures.

Only IPv4 full-tunnel with tunneled DNS is implemented. Explicitly block IPv6;
do not claim IPv6 support, ICMP encapsulation, split routing or uplink roaming.
Normal Disconnect removes our firewall table. Unexpected failure retains it until
explicit lab recovery or a successful retry followed by normal teardown. A new
service instance must respect an existing guard, even if its first request is NM's
post-crash Disconnect. No mandatory frontend/tray or parallel route manager is added.

## Consequences and evidence boundaries

The [service contract](../../crates/nm-service/README.md) records implementation,
bounded resources, reproducible synthetic VM probes and limitations. Regression
tests check observable failures rather than treating compilation as networking
evidence. Outstanding product work lives in the [roadmap](../roadmap.md);
distribution obligations live in [dependency review](../dependency-review.md).
