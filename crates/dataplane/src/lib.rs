//! Shared flow processing over explicitly supplied platform capabilities.
//!
//! No NetworkManager, D-Bus, TUN allocation, host resolver, firewall or socket creation.
//! See the package README for ownership, cancellation and authorization contracts.
pub mod datagram;
pub mod destination;
pub mod dns;
pub mod fakeip;
mod host;
pub mod inspection;
pub mod resolver;
pub mod routing;
pub mod runtime;
pub mod source_dns;
pub mod stream;

pub use host::{Datagram, Host, LanScope, PayloadStream};
