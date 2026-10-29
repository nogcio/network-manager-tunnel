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
    Stop,
}

struct Preparation {
    task: AbortTask<Result<Session, supervisor::Failure>>,
    cancel: oneshot::Sender<()>,
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
    }
    loop {
        let event = tokio::select! {
            request = requests.recv() => Event::Request(request),
            result = await_preparation(&mut pending) => Event::Prepared(result),
            _ = await_worker(&mut session) => Event::Worker,
            result = await_cleanup(&mut cleanup) => Event::Cleaned(result),
            _ = heartbeat.tick() => Event::Heartbeat,
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
                    session.is_some(),
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
            }
            Event::Request(Some(Request::Start(config, reply))) => {
                if reply.is_closed() {
                    continue;
                }
                if idle_generation_boundary(
                    state.load(Ordering::SeqCst),
                    pending.is_some(),
                    session.is_some(),
                    cleanup.is_some(),
                ) && image.replaced()
                {
                    let _ = reply.send(Err("Backend updated; retry through NetworkManager."));
                    return Ok(());
                }
                if let Err(error) = admit_start(
                    &state,
                    pending.is_some() || cleanup.is_some(),
                    session.is_some(),
                ) {
                    let _ = reply.send(Err(error));
                    continue;
                }
                plugin::change(&bus, &state, 3).await?;
                failed = false;
                telemetry.begin();
                let (cancel, cancelled) = oneshot::channel();
                pending = Some(Preparation {
                    cancel,
                    task: AbortTask(tokio::spawn(supervisor::prepare(
                        bus.clone(),
                        config,
                        telemetry.clone(),
                        cancelled,
                    ))),
                });
                // Admission transfers ownership to this loop even if the caller disappears.
                let _ = reply.send(Ok(()));
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
                        failed = true;
                        telemetry.state("stopping");
                        Plugin::failure(&SignalEmitter::new(&bus, PATH)?, 1).await?;
                        plugin::change(&bus, &state, 5).await?;
                        cleanup = Some(AbortTask(tokio::spawn(
                            guard_recovery::clear_until_confirmed(),
                        )));
                        eprintln!(
                            "VPN activation failed (kind {:?}, OS error {:?}); automatic cleanup started.",
                            error.kind(),
                            error.raw_os_error()
                        );
                    }
                }
            }
            Event::Worker => {
                failed = true;
                telemetry.state("stopping");
                if let Some(active) = session.take() {
                    active.stop().await.map_err(shutdown_failure)?;
                }
                Plugin::failure(&SignalEmitter::new(&bus, PATH)?, 1).await?;
                plugin::change(&bus, &state, 5).await?;
                cleanup = Some(AbortTask(tokio::spawn(
                    guard_recovery::clear_until_confirmed(),
                )));
                eprintln!("VPN worker stopped unexpectedly; automatic cleanup started.");
            }
            Event::Request(Some(Request::Stop)) => {
                telemetry.state("stopping");
                plugin::change(&bus, &state, 5).await?;
                cancel_preparation(&mut pending).await?;
                if let Some(active) = session.take() {
                    active.stop().await.map_err(shutdown_failure)?;
                }
                if cleanup.is_none() {
                    cleanup = Some(AbortTask(tokio::spawn(
                        guard_recovery::clear_until_confirmed(),
                    )));
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
                return match crate::network::guard::clear_session_guards().await {
                    Ok(()) => {
                        telemetry.state("stopped");
                        Ok(())
                    }
                    Err(_) => Err(zbus::Error::Failure(
                        "Shutdown cleanup transferred to automatic recovery.".into(),
                    )),
                };
            }
        }
    }
}

#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod tests;
