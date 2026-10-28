//! Linux broker integration tests for shared DNS dispatch.
#[cfg(test)]
use crate::dns::{self, framed, invalid, parse_query, validate_response};
#[cfg(test)]
use futures_util::{SinkExt, StreamExt};
pub(super) use nm_tunnel_dataplane::resolver::*;
#[cfg(test)]
use std::{io, net::SocketAddr, time::Duration};
#[cfg(test)]
#[path = "resolver_tests.rs"]
mod tests;
