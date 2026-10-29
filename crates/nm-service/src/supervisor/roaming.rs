//! Persistent NM-session recovery. No profile activation, normal route writer or
//! application replay: one admitted lifetime retains its TUN and session guards.
use super::{Failure, Session, session};
use crate::{network::guard, telemetry::Telemetry, wire::WorkerConfig};
use std::{io, time::Duration};
use tokio::{sync::oneshot, time::timeout};

async fn observe(
    bus: &zbus::Connection,
    config: &WorkerConfig,
) -> io::Result<session::Observation> {
    let profile = crate::schema::decode(config.name.clone(), &config.data, &config.secrets)
        .map_err(io::Error::other)?;
    let source = profile.network().source().is_some();
    let bypass = profile.lan_bypass() == nm_tunnel_profile::LanBypass::Connected || source;
    timeout(Duration::from_secs(5), session::uplink(bus, bypass, source))
        .await
        .map_err(|_| io::Error::other("Network observation deadline."))?
        .map(|(_, observation)| observation)
}

/// Missing/uncertain NM authority revokes the old session's flow capabilities.
/// Only NM's checked physical-primary observation is used, never OS DNS or an
/// unmarked connectivity request. The lifecycle renews recovery independently.
pub(crate) async fn changed(
    bus: &zbus::Connection,
    active: &Session,
    config: &WorkerConfig,
) -> bool {
    observe(bus, config)
        .await
        .map_or(true, |current| current != active.prepared.uplink)
}

async fn quiesce(active: &Session) -> io::Result<()> {
    let mut resources = active.resources.lock().await;
    // Atomically remove LAN exceptions before joining old worker/broker/relays.
    // Marked old transports are then closed, not migrated onto the new uplink.
    guard::guard_with_lan(
        &crate::lan::Plan::default(),
        &active.prepared.uplink.interface,
        false,
        &mut resources.guard_writer,
    )
    .await?;
    resources.suspend().await
}

/// Recover the same NM-admitted applied profile indefinitely until cancelled.
/// Each observation/setup has a deadline; failed attempts join all owned tasks
/// and restore the restrictive guard before backing off. FakeIP reopens the same
/// journal; NM retains the packet device and owns all routing/DNS updates.
/// Cancellation transfers through confirmed full stop; uncertain teardown is
/// `Shutdown`, never a new attempt. No secret persistence or profile reread.
pub(crate) async fn resume(
    bus: zbus::Connection,
    mut active: Session,
    config: WorkerConfig,
    telemetry: Telemetry,
    mut cancel: oneshot::Receiver<()>,
) -> Result<Session, Failure> {
    let operation = async {
        quiesce(&active).await.map_err(Failure::Shutdown)?;
        let mut backoff = Duration::from_secs(2);
        loop {
            let result = timeout(Duration::from_secs(45), async {
                session::prepare(
                    bus.clone(),
                    config.clone(),
                    telemetry.clone(),
                    &mut *active.resources.lock().await,
                )
                .await
            })
            .await;
            if let Ok(Ok(prepared)) = result {
                active.prepared = prepared;
                if !changed(&bus, &active, &config).await {
                    return Ok(());
                }
            }
            quiesce(&active).await.map_err(Failure::Shutdown)?;
            telemetry.state("connecting");
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    };
    let result = tokio::select! {
        result = operation => result,
        _ = &mut cancel => Err(Failure::Activation(io::Error::new(io::ErrorKind::Interrupted, "Recovery cancelled."))),
    };
    match result {
        Ok(()) => Ok(active),
        Err(error @ Failure::Shutdown(_)) => Err(error),
        Err(error @ Failure::Activation(_)) => {
            active.stop().await.map_err(Failure::Shutdown)?;
            Err(error)
        }
    }
}
