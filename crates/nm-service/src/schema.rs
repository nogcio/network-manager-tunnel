//! Service admission uses the same settings contract as the client.
pub(crate) use nm_tunnel_schema::decode_configuration;
pub(crate) use nm_tunnel_schema::{Settings, Strings, data, decode, ip_policy};

#[cfg(test)]
#[path = "schema_tests.rs"]
mod tests;
