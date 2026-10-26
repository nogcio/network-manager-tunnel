//! Unprivileged profile storage and explicit connection control through NetworkManager.
mod runtime;
mod settings;
mod telemetry;
pub use runtime::{
    ActiveConnection, ConnectionState, SavedProfile, Snapshot, activate, deactivate, save_profile,
    snapshot,
};
pub use telemetry::{TrafficCounters, TrafficSample, UsageError, UsageSnapshot, usage_snapshot};

use settings::encode_profile;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(20);

/// Deliberately sanitized errors; raw D-Bus payloads are never displayed or logged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    /// System bus or NetworkManager is unavailable, or access was refused.
    #[error("NetworkManager could not be reached or access was denied.")]
    Unavailable,
    /// NM rejected an explicit save; commonly authorization or schema validation.
    #[error("NetworkManager rejected the profile. Check authorization and service settings.")]
    Rejected,
    /// Save outcome is unknown: the remote operation may have completed.
    #[error(
        "NetworkManager did not confirm the save. Check its saved profiles before retrying; the save may have completed."
    )]
    Timeout,
    /// The bus/NM restarted, NM lost ownership, or an object no longer has its expected identity.
    #[error("NetworkManager state changed. Refresh the connection list before trying again.")]
    Stale,
    /// A request was refused; the frontend must observe NM rather than claim success.
    #[error(
        "NetworkManager refused the connection request. Check authorization and VPN service settings."
    )]
    Control,
    /// Control outcome is unknown. No request may be retried automatically.
    #[error(
        "NetworkManager did not confirm the connection request. Refresh its state; do not retry automatically."
    )]
    ControlTimeout,
}
