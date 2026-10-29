//! Independent session-protection latch. Failure retains blocking; only an
//! authorized explicit Disconnect releases it. No profile or route manager.
use nm_tunnel_profile::SERVICE_TYPE;
use std::{io, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use zbus::message::Header;

const NAME: &str = "org.freedesktop.NetworkManager.tunnel.Recovery";
const PATH: &str = "/org/freedesktop/NetworkManager/tunnel/Recovery";
const INTERFACE: &str = "org.freedesktop.NetworkManager.tunnel.Recovery";
// V2 deliberately rejects the v1 automatic-unblocking contract. Both processes
// must retire before this incompatible upgrade; never restart a leased v1 helper.
const PROTOCOL: u32 = 2;

mod authorization;
mod watchdog;

#[derive(Default)]
struct State {
    lease: Option<watchdog::Lease>,
    shutting_down: bool,
    held: bool,
    retained: bool,
    generation: uuid::Uuid,
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
    Blocked,
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
            Progress::Starting => "starting",
            Progress::Blocked => "blocked",
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
        self.renew_owner(&header, false, true).await
    }

    async fn renew(
        &self,
        cleaning: bool,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<()> {
        self.renew_owner(&header, cleaning, false).await
    }

    /// Non-activating clients observe only versioned status, never process identity.
    fn get_status(&self) -> (u32, String) {
        (PROTOCOL, self.status.name().into())
    }

    async fn get_release_token(&self) -> (u32, String, bool) {
        let gate = self.gate.lock().await;
        (PROTOCOL, gate.generation.to_string(), gate.held)
    }

    /// This is the sole ordinary release operation. Neither lost ownership,
    /// expired leases nor NM's automatic plugin Disconnect authorizes removal.
    async fn disconnect(
        &self,
        generation: String,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<()> {
        authorization::disconnect(&self.bus, &header).await?;
        self.release(&generation, crate::network::guard::clear_session_guards())
            .await
    }
}

impl Recovery {
    async fn release(
        &self,
        generation: &str,
        clear: impl std::future::Future<Output = io::Result<()>>,
    ) -> zbus::fdo::Result<()> {
        let mut gate = self.gate.lock().await;
        let generation = uuid::Uuid::parse_str(generation).map_err(|_| stale())?;
        if generation != gate.generation || !gate.held || gate.shutting_down {
            return Err(stale());
        }
        // Pin any replacement owner before terminating. Arm/release share this gate;
        // a newer protected lifetime cannot be cleared by an older UI request.
        if gate.lease.is_none()
            && let Some(owner) = backend_owner(&self.bus).await.map_err(|_| stale())?
        {
            gate.lease = Some(
                watchdog::Lease::pin(&self.bus, owner)
                    .await
                    .map_err(|_| stale())?,
            );
        }
        self.status.set(Progress::Terminating);
        if let Some(lease) = &gate.lease {
            lease.terminate().await.map_err(|_| stale())?;
        }
        self.status.set(Progress::Cleaning);
        if clear.await.is_err() {
            self.status.set(Progress::Retrying);
            return Err(stale());
        }
        gate.lease = None;
        gate.held = false;
        gate.retained = false;
        gate.generation = uuid::Uuid::new_v4();
        self.status.set(Progress::Cleaned);
        Ok(())
    }
}

fn stale() -> zbus::fdo::Error {
    zbus::fdo::Error::Failed(
        "Protection release refused or unconfirmed; no automatic retry.".into(),
    )
}

impl Recovery {
    async fn renew_owner(
        &self,
        header: &Header<'_>,
        cleaning: bool,
        arm: bool,
    ) -> zbus::fdo::Result<()> {
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
        self.adopt(
            owner,
            cleaning,
            arm,
            crate::network::guard::retain_session_guard(),
        )
        .await
    }

    /// The caller has authenticated the current backend. Guard I/O remains lazy:
    /// refusal/expired ownership cannot run an nft mutation.
    async fn adopt(
        &self,
        owner: String,
        cleaning: bool,
        arm: bool,
        retain: impl std::future::Future<Output = io::Result<()>>,
    ) -> zbus::fdo::Result<()> {
        let mut gate = self.gate.lock().await;
        if gate.shutting_down {
            return Err(stale());
        }
        if backend_owner(&self.bus)
            .await
            .map_err(|_| stale())?
            .as_deref()
            != Some(owner.as_str())
        {
            return Err(stale());
        }
        if !arm && !gate.held {
            return Ok(());
        }
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
        if !gate.held || cleaning {
            retain.await.map_err(|_| stale())?;
        }
        if !gate.held {
            gate.held = true;
            gate.generation = uuid::Uuid::new_v4();
        }
        if arm {
            if gate.retained {
                gate.generation = uuid::Uuid::new_v4();
            }
            gate.retained = false;
        }
        if cleaning {
            gate.retained = true;
            self.status.set(Progress::Blocked);
        } else if !gate.retained {
            self.status.set(Progress::Watching);
        }
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

/// Unknown ownership never authorizes a transition. Confirm death before revoking
/// stale LAN exceptions. No path here removes protection, even without a backend.
async fn retain_if_orphaned(
    bus: &zbus::Connection,
    gate: &Mutex<State>,
    status: &Status,
    retain: impl std::future::Future<Output = io::Result<()>>,
) -> io::Result<bool> {
    let mut gate = gate.lock().await;
    let owner = backend_owner(bus).await?;
    if let Some(lease) = &gate.lease
        && (owner.as_deref() != Some(lease.owner.as_str()) || lease.expired())
    {
        status.set(Progress::Terminating);
        let held = gate.held;
        // Keep the dead-process lease until restrictive retention succeeds.
        // A replacement Arm cannot race revocation of old physical exceptions.
        lease
            .stop_then(async { if held { retain.await } else { Ok(()) } })
            .await?;
        gate.lease = None;
        gate.retained = gate.held;
        status.set(if gate.held {
            Progress::Blocked
        } else {
            Progress::Starting
        });
        return Ok(!gate.held);
    }
    if let Some(owner) = owner {
        // After helper restart, recover ownership without extending a prior lease
        // from a journal or trusting a requester-supplied numeric PID.
        if gate.held && gate.lease.is_none() {
            gate.lease = Some(watchdog::Lease::pin(bus, owner).await?);
            status.set(Progress::Watching);
        }
        return Ok(false);
    }
    if gate.held {
        if !gate.retained {
            retain.await?;
            gate.retained = true;
        }
        status.set(Progress::Blocked);
        return Ok(false);
    }
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
    let held = crate::network::guard::guard_present().await?;
    let gate = Arc::new(Mutex::new(State {
        held,
        generation: uuid::Uuid::new_v4(),
        ..State::default()
    }));
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
        match retain_if_orphaned(
            &bus,
            &gate,
            &status,
            crate::network::guard::retain_session_guard(),
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

/// Resource teardown does not authorize release. Ask the independent owner to
/// retain blocking/revoke physical exceptions after confirmed local task shutdown.
pub(crate) async fn retain(bus: &zbus::Connection) -> io::Result<()> {
    renew(bus, true).await
}

#[cfg(test)]
#[path = "guard_recovery_tests.rs"]
mod tests;
