//! Public engine ownership contracts, using only synthetic loopback sockets.
#[path = "contracts/doh.rs"]
mod doh;
#[path = "contracts/hostname.rs"]
mod hostname;
#[path = "contracts/ownership.rs"]
mod ownership;
#[path = "contracts/quic_hostname.rs"]
mod quic_hostname;
