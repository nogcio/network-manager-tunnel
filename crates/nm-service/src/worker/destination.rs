//! Linux broker integration tests for shared FakeIP destination processing.
#[cfg(test)]
use crate::{dns, lan::Plan, wire::Broker};
#[cfg(test)]
use nm_tunnel_dataplane::destination::*;
#[cfg(test)]
use std::io;
#[cfg(test)]
#[path = "destination_tests.rs"]
mod tests;
