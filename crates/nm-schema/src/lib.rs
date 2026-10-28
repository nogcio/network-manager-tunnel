//! Pure NetworkManager settings contract shared by the service and unprivileged client.
//! No bus connections, activation, socket creation or persistence are performed here.
mod decode;
mod edit;
mod encode;
mod policy;

pub use decode::{Configuration, Settings, Strings, data, decode, decode_configuration, ip_policy};
pub use edit::ProfileChanges;
pub use encode::{EncodedProfile, encode_profile};
pub use policy::{LanBypass, decode_policy};
