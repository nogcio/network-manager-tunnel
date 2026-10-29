//! Explicit user release uses the desktop's existing NM network-control permission.
//! Polkit resolves the bus subject; no caller-supplied PID, UID or profile is trusted.
use std::{collections::HashMap, time::Duration};
use zbus::{
    message::Header,
    zvariant::{OwnedValue, Str},
};

pub(super) async fn disconnect(
    bus: &zbus::Connection,
    header: &Header<'_>,
) -> zbus::fdo::Result<()> {
    let sender = header.sender().ok_or_else(denied)?.to_string();
    tokio::time::timeout(Duration::from_secs(120), async {
        let proxy = zbus::Proxy::new(
            bus,
            "org.freedesktop.PolicyKit1",
            "/org/freedesktop/PolicyKit1/Authority",
            "org.freedesktop.PolicyKit1.Authority",
        )
        .await
        .map_err(|_| denied())?;
        let subject = (
            "system-bus-name",
            HashMap::from([("name", OwnedValue::from(Str::from(sender.as_str())))]),
        );
        let interactive = u32::from(
            header
                .primary()
                .flags()
                .contains(zbus::message::Flags::AllowInteractiveAuth),
        );
        let ((authorized, _, _),): ((bool, bool, HashMap<String, String>),) = proxy
            .call(
                "CheckAuthorization",
                &(
                    subject,
                    "org.freedesktop.NetworkManager.network-control",
                    HashMap::<String, String>::new(),
                    interactive,
                    "",
                ),
            )
            .await
            .map_err(|_| denied())?;
        if !authorized {
            return Err(denied());
        }
        // A vanished caller cannot leave a delayed authorization to clear a future
        // session. The generation is independently checked after this await.
        zbus::fdo::DBusProxy::new(bus)
            .await
            .map_err(|_| denied())?
            .get_connection_credentials(sender.as_str().try_into().map_err(|_| denied())?)
            .await
            .map_err(|_| denied())?;
        Ok(())
    })
    .await
    .map_err(|_| denied())?
}

fn denied() -> zbus::fdo::Error {
    zbus::fdo::Error::AccessDenied(
        "Explicit Disconnect requires NetworkManager network-control authorization.".into(),
    )
}

#[cfg(test)]
#[path = "authorization_tests.rs"]
mod tests;
