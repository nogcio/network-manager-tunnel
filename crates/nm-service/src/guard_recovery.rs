//! Independent systemd-owned orphan-guard recovery, not a profile or route manager.
use nm_tunnel_profile::SERVICE_TYPE;
use std::{io, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use zbus::message::Header;

const NAME: &str = "org.freedesktop.NetworkManager.tunnel.Recovery";
const PATH: &str = "/org/freedesktop/NetworkManager/tunnel/Recovery";
const INTERFACE: &str = "org.freedesktop.NetworkManager.tunnel.Recovery";
// Stable recovery ABI across compatible package updates; breaking semantics need
// a new version/interface, never an in-place reinterpretation of Arm/Renew.
const PROTOCOL: u32 = 1;

mod watchdog;

#[derive(Default)]
struct State {
    lease: Option<watchdog::Lease>,
    shutting_down: bool,
}

// Read-only projection stays available while the gate is held through termination/nft.
#[derive(Clone, Default)]
struct Status(Arc<std::sync::Mutex<Progress>>);

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Progress {
    #[default]
    Starting,
    Watching,
    Terminating,
    Cleaning,
    Retrying,
    Cleaned,
    BackendCleanup,
}

impl Status {
    fn set(&self, progress: Progress) {
        *self.0.lock().unwrap_or_else(|error| error.into_inner()) = progress;
    }
    fn get(&self) -> Progress {
        *self.0.lock().unwrap_or_else(|error| error.into_inner())
    }
    fn name(&self) -> &'static str {
        match self.get() {
            Progress::Watching => "watching",
            Progress::Terminating => "terminating",
            Progress::Cleaning => "cleaning",
            Progress::Retrying => "retrying",
            Progress::Cleaned => "cleaned",
            Progress::BackendCleanup => "backend-cleanup",
            Progress::Starting => "starting",
        }
    }
}

struct Recovery {
    bus: zbus::Connection,
    gate: Arc<Mutex<State>>,
    status: Status,
}

/// Gate acknowledgement and orphan cleanup are serialized. A new backend cannot
/// install guards while recovery is deleting the preceding session's tables.
#[zbus::interface(name = "org.freedesktop.NetworkManager.tunnel.Recovery")]
impl Recovery {
    async fn arm(&self, #[zbus(header)] header: Header<'_>) -> zbus::fdo::Result<()> {
        self.renew_owner(&header, false).await
    }

    async fn renew(
        &self,
        cleaning: bool,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<()> {
        self.renew_owner(&header, cleaning).await
    }

    /// Non-activating clients observe only versioned status, never process identity.
    fn get_status(&self) -> (u32, String) {
        (PROTOCOL, self.status.name().into())
    }
}

impl Recovery {
    async fn renew_owner(&self, header: &Header<'_>, cleaning: bool) -> zbus::fdo::Result<()> {
        let mut gate = self.gate.lock().await;
        if gate.shutting_down {
            return Err(zbus::fdo::Error::Failed(
                "Recovery helper is shutting down.".into(),
            ));
        }
        let owner = backend_owner(&self.bus)
            .await
            .map_err(|_| zbus::fdo::Error::Failed("Backend ownership unavailable.".into()))?;
        if header.sender().map(|name| name.as_str()) != owner.as_deref() || owner.is_none() {
            return Err(zbus::fdo::Error::AccessDenied(
                "Only the current VPN backend may arm recovery.".into(),
            ));
        }
        let owner =
            owner.ok_or_else(|| zbus::fdo::Error::AccessDenied("Backend unavailable.".into()))?;
        match &mut gate.lease {
            Some(lease) if lease.owner == owner => lease.renew(),
            Some(_) => Err(io::Error::other("Previous backend cleanup pending.")),
            None => match watchdog::Lease::pin(&self.bus, owner).await {
                Ok(lease) => {
                    gate.lease = Some(lease);
                    Ok(())
                }
                Err(error) => Err(error),
            },
        }
        .map_err(|_| zbus::fdo::Error::Failed("Recovery lease unavailable; current ownership and D-Bus ProcessFD support are required.".into()))?;
        self.status.set(if cleaning {
            Progress::BackendCleanup
        } else {
            Progress::Watching
        });
        Ok(())
    }
}

async fn backend_owner(bus: &zbus::Connection) -> io::Result<Option<String>> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let proxy = zbus::fdo::DBusProxy::new(bus)
            .await
            .map_err(|_| unavailable())?;
        match proxy
            .get_name_owner(SERVICE_TYPE.try_into().map_err(|_| unavailable())?)
            .await
        {
            Ok(owner) => Ok(Some(owner.to_string())),
            Err(zbus::fdo::Error::NameHasNoOwner(_)) => Ok(None),
            Err(_) => Err(unavailable()),
        }
    })
    .await
    .map_err(|_| unavailable())?
}

fn unavailable() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "Guard recovery ownership observation failed.",
    )
}

/// Must succeed before privileged session guards are installed. Missing packaging
/// or a failed helper rejects activation rather than leaving unowned protection.
pub(crate) async fn arm(bus: &zbus::Connection) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let proxy = zbus::Proxy::new(bus, NAME, PATH, INTERFACE)
            .await
            .map_err(|_| unavailable())?;
        let (version, _): (u32, String) = proxy
            .call("GetStatus", &())
            .await
            .map_err(|_| unavailable())?;
        if version != PROTOCOL {
            return Err(unavailable());
        }
        proxy
            .call::<_, _, ()>("Arm", &())
            .await
            .map_err(|_| unavailable())
    })
    .await
    .map_err(|_| unavailable())?
}

/// Called by the lifecycle loop itself, never an independent heartbeat task that
/// could hide a stuck owner. A failed renewal terminates that backend lifetime.
pub(crate) async fn renew(bus: &zbus::Connection, cleaning: bool) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let proxy = zbus::Proxy::new(bus, NAME, PATH, INTERFACE)
            .await
            .map_err(|_| unavailable())?;
        proxy
            .call::<_, _, ()>("Renew", &(cleaning,))
            .await
            .map_err(|_| unavailable())
    })
    .await
    .map_err(|_| unavailable())?
}

/// Cleanup is lazy: unknown ownership never authorizes it. A present backend must
/// lose/expire its lease and have process death confirmed before cleanup is polled.
/// The gate remains held through cleanup, so a simultaneous Arm cannot race it.
async fn clean_if_orphaned(
    bus: &zbus::Connection,
    gate: &Mutex<State>,
    status: &Status,
    cleanup: impl std::future::Future<Output = io::Result<()>>,
) -> io::Result<bool> {
    let mut gate = gate.lock().await;
    let owner = backend_owner(bus).await?;
    if let Some(lease) = &gate.lease
        && (owner.as_deref() != Some(lease.owner.as_str()) || lease.expired())
    {
        status.set(Progress::Terminating);
        // Keep the dead-process lease until cleanup succeeds. A replacement Arm
        // remains refused while old resources/protection are being removed.
        lease
            .stop_then(async {
                status.set(Progress::Cleaning);
                cleanup.await
            })
            .await?;
        gate.lease = None;
        status.set(Progress::Cleaned);
        return Ok(true);
    }
    if let Some(owner) = owner {
        // After helper restart, recover ownership without extending a prior lease
        // from a journal or trusting a requester-supplied numeric PID.
        if gate.lease.is_none() {
            gate.lease = Some(watchdog::Lease::pin(bus, owner).await?);
            status.set(Progress::Watching);
        }
        return Ok(false);
    }
    if status.get() == Progress::Cleaned {
        return Ok(true);
    }
    status.set(Progress::Cleaning);
    cleanup.await?;
    status.set(Progress::Cleaned);
    Ok(true)
}

/// Runs in a separate systemd cgroup. SIGKILL of the NM-launched backend cannot
/// kill this owner; systemd restarts the helper itself after an unexpected crash.
/// No credentials, profile database, uplink sockets or normal routes/DNS are owned here.
pub(crate) async fn run() -> io::Result<()> {
    if std::env::var_os("NM_TUNNEL_RECOVERY_SYSTEMD").as_deref() != Some(std::ffi::OsStr::new("1"))
    {
        return Err(io::Error::other(
            "Guard recovery requires its independent systemd unit.",
        ));
    }
    let bus = zbus::Connection::system()
        .await
        .map_err(|_| unavailable())?;
    let gate = Arc::new(Mutex::new(State::default()));
    let status = Status::default();
    bus.object_server()
        .at(
            PATH,
            Recovery {
                bus: bus.clone(),
                gate: Arc::clone(&gate),
                status: status.clone(),
            },
        )
        .await
        .map_err(|_| unavailable())?;
    bus.request_name(NAME).await.map_err(|_| unavailable())?;
    let mut ticks = tokio::time::interval(Duration::from_secs(1));
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut reported = false;
    let mut cleaned_at = None;
    loop {
        ticks.tick().await;
        match clean_if_orphaned(
            &bus,
            &gate,
            &status,
            crate::network::guard::clear_session_guards(),
        )
        .await
        {
            Ok(true) => {
                // Briefly retain confirmed cleanup for non-activating observers.
                let since = cleaned_at.get_or_insert_with(tokio::time::Instant::now);
                if since.elapsed() >= Duration::from_secs(30) {
                    let mut state = gate.lock().await;
                    if state.lease.is_none() && backend_owner(&bus).await?.is_none() {
                        // Close admission under the same gate. No final Arm can
                        // succeed between deciding to exit and dropping the bus.
                        state.shutting_down = true;
                        return Ok(());
                    }
                }
                reported = false;
            }
            Ok(false) => {
                reported = false;
                cleaned_at = None;
            }
            Err(error) => {
                status.set(Progress::Retrying);
                cleaned_at = None;
                if error.kind() == io::ErrorKind::NotConnected {
                    return Err(error);
                }
                if !reported {
                    eprintln!("Automatic guard recovery pending; cleanup will retry.");
                    reported = true;
                }
            }
        }
    }
}

/// Bounded nft operations retry until cleanup is confirmed. Cancellation never
/// declares success; loss of this backend's name transfers recovery to the helper.
pub(crate) async fn clear_until_confirmed() -> io::Result<()> {
    let mut ticks = tokio::time::interval(Duration::from_secs(1));
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut reported = false;
    loop {
        ticks.tick().await;
        if crate::network::guard::clear_session_guards().await.is_ok() {
            return Ok(());
        }
        if !reported {
            eprintln!("Automatic session cleanup pending; cleanup will retry.");
            reported = true;
        }
    }
}

#[cfg(test)]
#[path = "guard_recovery_tests.rs"]
mod tests;
