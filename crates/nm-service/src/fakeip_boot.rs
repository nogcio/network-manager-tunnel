//! Read the trusted root XDG identity pin; boot service enablement is not required.
use std::{io, path::PathBuf, time::Duration};
use zbus::zvariant::OwnedObjectPath;

const UNIT: &str = "nm-tunnel-fakeip-guard.service";

fn denied() -> io::Error {
    io::Error::other(
        "Persistent FakeIP requires one absolute root-owned XDG state namespace; no reset or fallback is allowed.",
    )
}

/// Read the installed root-owned unit's XDG pin to preserve existing identities,
/// not the desktop/NM caller's inherited HOME or XDG variables. This is passive
/// configuration discovery: no enablement, startup or NM dependency is required.
pub(crate) async fn state_base(bus: &zbus::Connection) -> io::Result<PathBuf> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let manager = zbus::Proxy::new(
            bus,
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
        )
        .await
        .map_err(|_| denied())?;
        let path: OwnedObjectPath = manager
            .call("LoadUnit", &(UNIT,))
            .await
            .map_err(|_| denied())?;
        let service = zbus::Proxy::new(
            bus,
            "org.freedesktop.systemd1",
            path,
            "org.freedesktop.systemd1.Service",
        )
        .await
        .map_err(|_| denied())?;
        let environment: Vec<String> = service
            .get_property("Environment")
            .await
            .map_err(|_| denied())?;
        let mut values = environment
            .iter()
            .filter_map(|value| value.strip_prefix("XDG_STATE_HOME="));
        let base = PathBuf::from(values.next().ok_or_else(denied)?);
        if values.next().is_some() || !base.is_absolute() {
            return Err(denied());
        }
        Ok(base)
    })
    .await
    .map_err(|_| denied())?
}

#[cfg(test)]
#[path = "fakeip_boot_tests.rs"]
mod tests;
