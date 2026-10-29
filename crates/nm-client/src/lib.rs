//! Unprivileged profile storage and explicit connection control through NetworkManager.
mod protection;
mod recovery;
pub use protection::disconnect_protection;
mod runtime;
mod settings;
mod telemetry;
mod transport;
pub use nm_tunnel_schema::{CredentialStorage, LanBypass, ProfileChanges, ProfileOptions};
pub use recovery::{RecoveryError, RecoveryStatus, recovery_status};
pub use runtime::{
    ActiveConnection, ConnectionState, SavedProfile, Snapshot, activate, deactivate,
    delete_profile, edit_profile, replace_profile, save_profile, save_profile_with_options,
    snapshot, update_from_source,
};
pub use telemetry::{TrafficCounters, TrafficSample, UsageError, UsageSnapshot, usage_snapshot};

use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(20);

/// Deliberately sanitized errors; raw D-Bus payloads are never displayed or logged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    /// System bus or NetworkManager is unavailable, or access was refused.
    #[error("NetworkManager could not be reached or access was denied.")]
    Unavailable,
    /// NM rejected an explicit profile change; commonly authorization or validation.
    #[error("NetworkManager rejected the profile change. Check authorization and saved settings.")]
    Rejected,
    /// Storage outcome is unknown: the remote operation may have completed.
    #[error(
        "NetworkManager did not confirm the write. Check its saved profiles before retrying; the change may have completed."
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
    /// Checked mutations require a fresh versioned snapshot; updates use Update2.
    #[error(
        "Profile changes require a fresh versioned NetworkManager observation (NM 1.44 or newer). Refresh before changing profiles; no unconditional fallback is allowed."
    )]
    UpdateUnsupported,
}
