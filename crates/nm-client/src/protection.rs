//! Explicit Disconnect only. Reads pin a helper generation before any NM mutation;
//! delayed requests never release a replacement session or activate the helper.
use crate::{ClientError, transport::ReadOnly};
use std::time::Duration;
const NAME: &str = "org.freedesktop.NetworkManager.tunnel.Recovery";
const PATH: &str = "/org/freedesktop/NetworkManager/tunnel/Recovery";

pub(crate) struct Request<'a> {
    owner: ReadOnly<'a>,
    generation: String,
}

pub(crate) async fn token(bus: &zbus::Connection) -> Result<Option<Request<'_>>, ClientError> {
    let Some(owner) = ReadOnly::pin(bus, NAME)
        .await
        .map_err(|_| ClientError::Control)?
    else {
        return Ok(None);
    };
    let proxy = owner
        .proxy(PATH, NAME)
        .await
        .map_err(|_| ClientError::Control)?;
    let (version, _): (u32, String) = proxy
        .call_with_flags(
            "GetStatus",
            zbus::proxy::MethodFlags::NoAutoStart.into(),
            &(),
        )
        .await
        .map_err(|_| ClientError::Control)?
        .ok_or(ClientError::Control)?;
    if version == 1 {
        return Ok(None);
    } // Legacy service has no retained-protection API.
    if version != 2 {
        return Err(ClientError::Control);
    }
    let (version, generation, held): (u32, String, bool) = proxy
        .call_with_flags(
            "GetReleaseToken",
            zbus::proxy::MethodFlags::NoAutoStart.into(),
            &(),
        )
        .await
        .map_err(|_| ClientError::Control)?
        .ok_or(ClientError::Control)?;
    if version != 2 || uuid::Uuid::parse_str(&generation).is_err() {
        return Err(ClientError::Control);
    }
    drop(proxy);
    owner.validate().await.map_err(|_| ClientError::Control)?;
    Ok(held.then_some(Request { owner, generation }))
}

impl Request<'_> {
    pub(crate) async fn release(self) -> Result<(), ClientError> {
        tokio::time::timeout(Duration::from_secs(150), async {
            self.owner
                .validate()
                .await
                .map_err(|_| ClientError::Control)?;
            let proxy = self
                .owner
                .proxy(PATH, NAME)
                .await
                .map_err(|_| ClientError::Control)?;
            proxy
                .call_with_flags::<_, _, ()>(
                    "Disconnect",
                    zbus::proxy::MethodFlags::NoAutoStart
                        | zbus::proxy::MethodFlags::AllowInteractiveAuth,
                    &(self.generation,),
                )
                .await
                .map_err(release_error)?
                .ok_or(ClientError::ControlTimeout)
        })
        .await
        .map_err(|_| ClientError::ControlTimeout)?
    }
}

fn release_error(error: zbus::Error) -> ClientError {
    if matches!(&error,zbus::Error::MethodError(name,_,_) if !matches!(name.as_str(),"org.freedesktop.DBus.Error.NoReply" | "org.freedesktop.DBus.Error.Timeout" | "org.freedesktop.DBus.Error.Disconnected" | "org.freedesktop.DBus.Error.ServiceUnknown" | "org.freedesktop.DBus.Error.NameHasNoOwner"))
    {
        ClientError::Control
    } else {
        ClientError::ControlTimeout
    }
}

#[cfg(test)]
#[path = "protection_tests.rs"]
mod tests;

/// Explicitly release retained protection after a crashed/disappeared NM plugin.
/// Uses the normal NM network-control Polkit permission. Never calls this from
/// observation, timeout handling or automatic recovery. No service activation,
/// profile/secret reads, automatic retry or alternate network path.
///
/// # Errors
/// Refuses absent/unsupported helpers, stale generations, denied authorization or
/// unconfirmed process exit/guard removal. Timeout is indeterminate; observe again,
/// never retry automatically. Cancellation cannot certify that release completed.
pub async fn disconnect_protection() -> Result<(), ClientError> {
    let bus = zbus::Connection::system()
        .await
        .map_err(|_| ClientError::Unavailable)?;
    let request = tokio::time::timeout(Duration::from_secs(3), token(&bus))
        .await
        .map_err(|_| ClientError::ControlTimeout)??
        .ok_or(ClientError::Control)?;
    request.release().await
}
