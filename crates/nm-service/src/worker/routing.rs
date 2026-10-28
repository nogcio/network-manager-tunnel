//! Linux integration regressions for the shared outbound selector.
#[cfg(test)]
use crate::lan::Plan;
#[cfg(test)]
use nm_tunnel_dataplane::routing::*;
#[cfg(test)]
use std::io;
#[cfg(test)]
#[path = "routing_tests.rs"]
mod tests;
