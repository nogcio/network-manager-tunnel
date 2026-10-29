//! Sole activation owner. NM calls enqueue intent; this loop owns preparation and teardown.
use crate::{
    guard_recovery,
    plugin::{self, NM, PATH, Plugin},
    supervisor::{self, Session},
    task::AbortTask,
    telemetry::Telemetry,
    wire::WorkerConfig,
};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};
use tokio::sync::{mpsc, oneshot};
use zbus::object_server::SignalEmitter;

pub(crate) enum Request {
    Start(WorkerConfig, oneshot::Sender<Result<(), &'static str>>),
    Authenticate(
        String,
        WorkerConfig,
        oneshot::Sender<Result<(), &'static str>>,
    ),
    Secrets(
        String,
        WorkerConfig,
        oneshot::Sender<Result<(), &'static str>>,
    ),
    Stop,
}

struct Preparation {
    task: AbortTask<Result<Session, supervisor::Failure>>,
    cancel: oneshot::Sender<()>,
}

fn launch(bus: &zbus::Connection, config: WorkerConfig, telemetry: &Telemetry) -> Preparation {
    let (cancel, cancelled) = oneshot::channel();
    Preparation {
        cancel,
        task: AbortTask(tokio::spawn(supervisor::prepare(
            bus.clone(),
            config,
            telemetry.clone(),
            cancelled,
        ))),
    }
}

async fn await_authentication(pending: &Option<crate::authentication::Pending>) {
    match pending {
        Some(pending) => tokio::time::sleep_until(pending.deadline).await,
        None => std::future::pending().await,
    }
}

async fn await_preparation(
    pending: &mut Option<Preparation>,
) -> Result<Session, supervisor::Failure> {
    match pending {
        Some(task) => (&mut task.task.0).await.map_err(|_| {
            supervisor::Failure::Shutdown(io::Error::other("Activation task failed."))
        })?,
        None => std::future::pending().await,
    }
}

fn admit_start(state: &AtomicU32, pending: bool, session: bool) -> Result<(), &'static str> {
    if pending || session || !matches!(state.load(Ordering::SeqCst), 1 | 6) {
        return Err("A VPN activation is already owned by this service.");
    }
    state.store(3, Ordering::SeqCst);
    Ok(())
}

fn idle_generation_boundary(state: u32, pending: bool, session: bool, cleanup: bool) -> bool {
    matches!(state, 1 | 6) && !pending && !session && !cleanup
}

async fn cancel_preparation(pending: &mut Option<Preparation>) -> zbus::Result<()> {
    if let Some(mut task) = pending.take() {
        let _ = task.cancel.send(());
        // Completion may win cancellation. Stop the resulting session before releasing protection.
        match (&mut task.task.0).await {
            Ok(Ok(active)) => active.stop().await.map_err(shutdown_failure)?,
            Ok(Err(supervisor::Failure::Activation(_))) => {}
            Ok(Err(supervisor::Failure::Shutdown(error))) => return Err(shutdown_failure(error)),
            Err(_) => {
                return Err(shutdown_failure(io::Error::other(
                    "Activation task failed.",
                )));
            }
        }
    }
    Ok(())
}

fn shutdown_failure(error: io::Error) -> zbus::Error {
    eprintln!(
        "Resource teardown unconfirmed (kind {:?}); independent recovery must confirm process exit.",
        error.kind()
    );
    zbus::Error::Failure(
        "Resource teardown unconfirmed; guards retained for independent recovery.".into(),
    )
}

async fn await_worker(session: &mut Option<Session>) {
    match session {
        Some(session) => session.wait().await,
        None => std::future::pending().await,
    }
}

async fn await_cleanup(pending: &mut Option<AbortTask<io::Result<()>>>) -> io::Result<()> {
    match pending {
        Some(task) => (&mut task.0)
            .await
            .map_err(|_| io::Error::other("Cleanup task failed."))?,
        None => std::future::pending().await,
    }
}

pub(crate) async fn run(
    bus: zbus::Connection,
    state: Arc<AtomicU32>,
    mut requests: mpsc::Receiver<Request>,
    telemetry: Telemetry,
) -> zbus::Result<()> {
    let image = crate::executable::Image::capture()
        .map_err(|_| zbus::Error::Failure("Executable generation unavailable.".into()))?;
    let mut pending = None;
    let mut session: Option<Session> = None;
    // The applied configuration belongs to this admitted lifetime, not a saved
    // profile reread: editing a profile never changes a recovering connection.
    let mut intent: Option<WorkerConfig> = None;
    let mut authentication: Option<crate::authentication::Pending> = None;
    let mut cleanup = None;
    let mut failed = false;
    let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(2));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let dbus = zbus::fdo::DBusProxy::new(&bus).await?;
    let mut owners = dbus.receive_name_owner_changed().await?;
    let mut termination = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| zbus::Error::Failure("Signal handling unavailable.".into()))?;
    use futures_util::StreamExt;
    enum Event {
        Request(Option<Request>),
        Prepared(Result<Session, supervisor::Failure>),
        Worker,
        Cleaned(io::Result<()>),
        Shutdown,
        Heartbeat,
        AuthenticationExpired,
    }
    loop {
        let event = tokio::select! {
            request = requests.recv() => Event::Request(request),
            result = await_preparation(&mut pending) => Event::Prepared(result),
            _ = await_worker(&mut session) => Event::Worker,
            result = await_cleanup(&mut cleanup) => Event::Cleaned(result),
            _ = heartbeat.tick() => Event::Heartbeat,
            _ = await_authentication(&authentication) => Event::AuthenticationExpired,
            _ = tokio::signal::ctrl_c() => Event::Shutdown,
            _ = termination.recv() => Event::Shutdown,
            signal = owners.next() => {
                if signal.is_none_or(|signal| signal.args().is_ok_and(|args| args.name().as_str() == NM)) { Event::Shutdown } else { continue; }
            }
        };
        match event {
            Event::Heartbeat => {
                if idle_generation_boundary(
                    state.load(Ordering::SeqCst),
                    pending.is_some(),
                    session.is_some() || authentication.is_some(),
                    cleanup.is_some(),
                ) && image.replaced()
                {
                    return Ok(());
                }
                // Keep the admitted backend leased even after cleanup, while it
                // remains alive awaiting NM. Idle is not a hung lifecycle loop.
                if state.load(Ordering::SeqCst) != 1 {
                    guard_recovery::renew(&bus, cleanup.is_some())
                        .await
                        .map_err(|_| {
                            zbus::Error::Failure(
                                "Independent recovery liveness renewal failed.".into(),
                            )
                        })?;
                }
                if let (Some(active), Some(config)) = (session.as_ref(), intent.as_ref())
                    && config.persistent
                    && supervisor::changed(&bus, active, config).await
                {
                    let active = session.take().ok_or_else(|| {
                        zbus::Error::Failure("Session ownership unavailable.".into())
                    })?;
                    let (cancel, cancelled) = oneshot::channel();
                    pending = Some(Preparation {
                        cancel,
                        task: AbortTask(tokio::spawn(supervisor::resume(
                            bus.clone(),
                            active,
                            config.clone(),
                            telemetry.clone(),
                            cancelled,
                        ))),
                    });
                    telemetry.state("connecting");
                    // This is the same persistent NM packet-device lifetime,
                    // not a second activation. Keep NM's active state while
                    // capabilities are revoked; telemetry reports recovery.
                }
            }
            Event::Request(Some(Request::Start(config, reply))) => {
                if reply.is_closed() {
                    continue;
                }
                if idle_generation_boundary(
                    state.load(Ordering::SeqCst),
                    pending.is_some(),
                    session.is_some() || authentication.is_some(),
                    cleanup.is_some(),
                ) && image.replaced()
                {
                    let _ = reply.send(Err("Backend updated; retry through NetworkManager."));
                    return Ok(());
                }
                if let Err(error) = admit_start(
                    &state,
                    pending.is_some() || cleanup.is_some(),
                    session.is_some() || authentication.is_some(),
                ) {
                    let _ = reply.send(Err(error));
                    continue;
                }
                plugin::change(&bus, &state, 3).await?;
                failed = false;
                telemetry.begin();
                intent = Some(config.clone());
                pending = Some(launch(&bus, config, &telemetry));
                // Admission transfers ownership to this loop even if the caller disappears.
                let _ = reply.send(Ok(()));
            }
            Event::Request(Some(Request::Authenticate(id, config, reply))) => {
                if reply.is_closed() {
                    continue;
                }
                if idle_generation_boundary(
                    state.load(Ordering::SeqCst),
                    pending.is_some(),
                    session.is_some() || authentication.is_some(),
                    cleanup.is_some(),
                ) && image.replaced()
                {
                    let _ = reply.send(Err("Backend updated; retry through NetworkManager."));
                    return Ok(());
                }
                if let Err(error) = admit_start(
                    &state,
                    pending.is_some() || cleanup.is_some() || authentication.is_some(),
                    session.is_some(),
                ) {
                    let _ = reply.send(Err(error));
                    continue;
                }
                authentication = Some(crate::authentication::Pending::new(id, config));
                failed = false;
                telemetry.begin();
                plugin::change(&bus, &state, 3).await?;
                Plugin::secrets_required(
                    &SignalEmitter::new(&bus, PATH)?,
                    "VLESS UUID credential required.",
                    vec!["uuid"],
                )
                .await?;
                let _ = reply.send(Ok(()));
            }
            Event::Request(Some(Request::Secrets(id, config, reply))) => {
                if reply.is_closed() {
                    continue;
                }
                let completed = authentication
                    .as_ref()
                    .ok_or("No pending credential request.")
                    .and_then(|request| request.complete(&id, &config));
                match completed {
                    Ok(config) => {
                        authentication = None;
                        intent = Some(config.clone());
                        pending = Some(launch(&bus, config, &telemetry));
                        let _ = reply.send(Ok(()));
                    }
                    Err(error) => {
                        let _ = reply.send(Err(error));
                    }
                }
            }
            Event::AuthenticationExpired => {
                authentication = None;
                intent = None;
                failed = true;
                telemetry.state("failed");
                Plugin::failure(&SignalEmitter::new(&bus, PATH)?, 0).await?;
                plugin::change(&bus, &state, 6).await?;
            }
            Event::Prepared(result) => {
                pending = None;
                match result {
                    Ok(active) => {
                        failed = false;
                        plugin::announce(
                            &bus,
                            active.prepared.endpoint,
                            active.prepared.dns,
                            &active.prepared.lan,
                            active.prepared.source_policy.as_deref(),
                        )
                        .await?;
                        session = Some(active);
                        plugin::change(&bus, &state, 4).await?;
                        telemetry.stage("ready");
                        telemetry.state("running");
                        eprintln!("VPN worker ready; NM owns IP configuration.");
                    }
                    Err(supervisor::Failure::Shutdown(error)) => {
                        return Err(shutdown_failure(error));
                    }
                    Err(supervisor::Failure::Activation(error)) => {
                        intent = None;
                        failed = true;
                        telemetry.state("stopping");
                        Plugin::failure(&SignalEmitter::new(&bus, PATH)?, 1).await?;
                        plugin::change(&bus, &state, 5).await?;
                        let owner = bus.clone();
                        cleanup = Some(AbortTask(tokio::spawn(async move {
                            guard_recovery::retain(&owner).await
                        })));
                        eprintln!(
                            "VPN activation failed (kind {:?}, OS error {:?}); protection retained until explicit Disconnect.",
                            error.kind(),
                            error.raw_os_error()
                        );
                    }
                }
            }
            Event::Worker => {
                let active = session
                    .take()
                    .ok_or_else(|| zbus::Error::Failure("Session ownership unavailable.".into()))?;
                let config = intent
                    .clone()
                    .ok_or_else(|| zbus::Error::Failure("Session intent unavailable.".into()))?;
                let (cancel, cancelled) = oneshot::channel();
                pending = Some(Preparation {
                    cancel,
                    task: AbortTask(tokio::spawn(supervisor::resume(
                        bus.clone(),
                        active,
                        config,
                        telemetry.clone(),
                        cancelled,
                    ))),
                });
                telemetry.state("connecting");
                eprintln!(
                    "VPN worker stopped unexpectedly; recovering with protection retained until explicit Disconnect."
                );
            }
            Event::Request(Some(Request::Stop)) => {
                authentication = None;
                intent = None;
                telemetry.state("stopping");
                plugin::change(&bus, &state, 5).await?;
                cancel_preparation(&mut pending).await?;
                if let Some(active) = session.take() {
                    active.stop().await.map_err(shutdown_failure)?;
                }
                if cleanup.is_none() {
                    let owner = bus.clone();
                    cleanup = Some(AbortTask(tokio::spawn(async move {
                        guard_recovery::retain(&owner).await
                    })));
                }
            }
            Event::Cleaned(result) => {
                result.map_err(|_| {
                    zbus::Error::Failure(
                        "Automatic cleanup task failed; independent recovery will continue.".into(),
                    )
                })?;
                cleanup = None;
                plugin::change(&bus, &state, 6).await?;
                telemetry.state(if failed { "failed" } else { "stopped" });
                if image.replaced() {
                    return Ok(());
                }
            }
            Event::Shutdown | Event::Request(None) => {
                telemetry.state("stopping");
                cancel_preparation(&mut pending).await?;
                if let Some(active) = session.take() {
                    active.stop().await.map_err(shutdown_failure)?;
                }
                // A failed cleanup exits and relinquishes the bus name, allowing
                // the independent systemd owner to continue retries after shutdown.
                if let Some(mut task) = cleanup.take() {
                    task.0.abort();
                    let _ = (&mut task.0).await;
                }
                // Shutdown/NM loss is not user authorization to release guards.
                // The independent owner revokes stale exceptions after our exit.
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod tests;
