//! Privileged Linux adapters. NM alone owns normal routes, addresses and DNS.
pub(crate) mod authority;
pub(crate) mod bootstrap;
pub(crate) mod guard;
pub(crate) mod sockets;

/// Shared by marked upstream sockets and the session guard's bypass rule.
const MARK: u32 = 0x4e4d5401;
