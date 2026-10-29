//! Non-activating observation of independent recovery; never a guard controller.
use std::time::Duration;

const NAME: &str = "org.freedesktop.NetworkManager.tunnel.Recovery";
const PATH: &str = "/org/freedesktop/NetworkManager/tunnel/Recovery";

/// Last independent-helper state. Not NM connectivity or a protection certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryStatus {
    /// The helper is observing ownership before any confirmed cleanup.
    Starting,
    /// The backend's lifecycle lease is live.
    Watching,
    /// The lease expired or its owner changed; process termination is pending.
    Terminating,
    /// The helper is removing only its owned session tables.
    Cleaning,
    /// Cleanup/termination failed and will be retried; networking is not confirmed restored.
    Retrying,
    /// The helper confirmed table cleanup; this is historical once received.
    Cleaned,
    /// The live backend reports that its own cleanup is pending.
    BackendCleanup,
    /// VPN transport is unavailable; protection is retained until explicit Disconnect.
    Blocked,
}

/// Sanitized observation error. Does not authorize retrying any NM write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryError {
    /// Bus, owner, authorization, transport or the total deadline failed.
    #[error("Automatic recovery status is unavailable.")]
    Unavailable,
    /// The response is outside the versioned read-only contract.
    #[error("Automatic recovery status has an unsupported format.")]
    Invalid,
}

/// Observe an existing helper without starting it. None means no helper owner,
/// not confirmed cleanup. One 3-second deadline covers connection and read; owner
/// changes reject publication. Cancellation owns read-only work, never recovery.
pub async fn recovery_status() -> Result<Option<RecoveryStatus>, RecoveryError> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let bus = zbus::Connection::system()
            .await
            .map_err(|_| RecoveryError::Unavailable)?;
        read(&bus).await
    })
    .await
    .map_err(|_| RecoveryError::Unavailable)?
}

async fn read(bus: &zbus::Connection) -> Result<Option<RecoveryStatus>, RecoveryError> {
    let Some(owner) = crate::transport::ReadOnly::pin(bus, NAME)
        .await
        .map_err(|_| RecoveryError::Unavailable)?
    else {
        return Ok(None);
    };
    let proxy = owner
        .proxy(PATH, NAME)
        .await
        .map_err(|_| RecoveryError::Unavailable)?;
    let (version, status): (u32, String) = proxy
        .call_with_flags(
            "GetStatus",
            zbus::proxy::MethodFlags::NoAutoStart.into(),
            &(),
        )
        .await
        .map_err(|error| match error {
            zbus::Error::Variant(_)
            | zbus::Error::InvalidReply
            | zbus::Error::InvalidField
            | zbus::Error::MissingField
            | zbus::Error::ExcessData
            | zbus::Error::IncorrectEndian => RecoveryError::Invalid,
            _ => RecoveryError::Unavailable,
        })?
        .ok_or(RecoveryError::Unavailable)?;
    if !matches!(version, 1 | 2) {
        return Err(RecoveryError::Invalid);
    }
    let status = match status.as_str() {
        "starting" => RecoveryStatus::Starting,
        "watching" => RecoveryStatus::Watching,
        "terminating" => RecoveryStatus::Terminating,
        "cleaning" => RecoveryStatus::Cleaning,
        "retrying" => RecoveryStatus::Retrying,
        "cleaned" => RecoveryStatus::Cleaned,
        "backend-cleanup" => RecoveryStatus::BackendCleanup,
        "blocked" if version == 2 => RecoveryStatus::Blocked,
        _ => return Err(RecoveryError::Invalid),
    };
    owner
        .validate()
        .await
        .map_err(|_| RecoveryError::Unavailable)?;
    Ok(Some(status))
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod tests;
