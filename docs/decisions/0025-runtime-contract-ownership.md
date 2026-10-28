# ADR 0025: Shared settings contract and explicit runtime owners

Status: implemented structural refactor, typed executable profile and explicit frontend
async owners. Recovery policy and its acceptance limits are owned by ADR 0026.

## Context

NM encoding, decoding and metadata observation had separate policy admission rules.
Activation setup also implemented the complete broker request loop, and the NM D-Bus
adapter owned lifecycle orchestration. Worker DNS code mixed message validation,
privileged transport and application dispatch. Frontend import state was held by the
application alongside unrelated NM operations.

## Decision

- `nm-tunnel-profile` owns domain validation and execution-facing `RoutingPolicy`
  and mutually exclusive `LanBypass` views. Drafts remain boundary inputs; new
  runtime code should consume checked semantics rather than infer source formats.
- `nm-tunnel-schema` is a pure `contract`-layer consumer of the model and existing
  D-Bus value types. It owns NM conversion, version/mode admission and the policy
  metadata projection. Client and service both consume it. The engine does not.
- Public configuration validation and executable credential admission are separate
  operations. Missing credentials never become a synthetic authenticated Profile.
- The NM plugin adapter authenticates calls, validates requests and emits NM signals.
  `lifecycle` alone admits queued operations and owns preparation/session teardown.
- `supervisor::plan` makes pure, activation-local network decisions from a checked
  profile and NM uplink snapshot, before runtime resource allocation.
  `supervisor::session` creates/owns resources, and `supervisor::broker` independently
  authorizes worker requests and owns relays. Requests never confer authority.
- Shared DNS message policy/framing contains no socket creation. Privileged uplink
  DNS exchange belongs to the supervisor; application DNS dispatch, destination
  handling and inspection belong to private worker modules.
- COSMIC's catalog owns imported-node admission/selection/reconciliation; profile
  options own resolver/LAN/protection transformations. Neither owns NM or HTTP tasks.
  Retention after invalidation is read-only and cannot supply save candidates.

## Extension rules and consequences

A schema addition has one codec owner. A new routing behavior belongs to checked
domain semantics first, then worker dispatch and independent supervisor authorization.
A DNS transport must not add host dialing to the worker or engine. New protocols
remain library adapters over approved transports; no speculative protocol plugin ABI
or generic RPC framework is introduced. New frontend widgets consume scenario state
rather than become the owner of profile persistence or network protection.

This restructuring preserves schema-v1/v2 storage, legacy/complete in-session behavior,
serialized broker backpressure/poisoning and protocol deadlines. It does not reduce
root source-DNS processing, establish live packet acceptance, change firewall policy
or certify new protocol support. Those require separate reviewed changes.

Draft remains a flat boundary input, but executable Profile separately owns typed
node settings, parsed credential and immutable NetworkPolicy. Engine/runtime never
borrow Draft; edits explicitly call `to_draft`. Metadata decoding returns the same
checked NetworkPolicy, not an independent mutable policy model. TCP/UDP outbound
selection shares one pure worker decision and TCP has one relay executor; distinct
classification schedules preserve legacy LAN bypass and complete DNS/signature order.
The privileged network adapters separately own sockets, bootstrap, legacy/LAN
authorization and nftables, without depending on IPC request representations.
NM client transport owns pinned bus/owner identity and uncached proxies; separate
observation and mutation owners handle versioned reads/revalidation and explicit
writes/control. Public handles/deadlines stay in the API facade. Confirmed writes
perform no fallible post-write read; indeterminate outcomes never trigger retries.
COSMIC's pure operation owner distinguishes dispatched addition, replacement and
control from accepted control awaiting observation. Completion kinds cannot release
another mutation; additions pin their admitted row and ambiguous storage permanently
blocks further writes for the app session without blocking connection control.
`download` owns the memory-only URL, immutable in-flight format, request ticket and
HTTP error. `reads` owns separate coalesced NM, usage and recovery slots. Every read
has a unique ticket; mutation invalidates pending results without releasing their
slots or pretending to cancel remote work. Duplicates cannot finish a newer request.
`recovery` projects independent-helper progress without acquiring cleanup authority.
Widget code consumes these states rather than maintaining cross-cutting busy flags.
Module privacy protects internal implementation entry points; the workspace DAG
checks package edges, not an internal privilege sandbox.
