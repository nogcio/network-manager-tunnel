//! Resources outlive cancellable preparation and broker futures.
use crate::task::AbortTask;
use std::{io, sync::Arc};
use tokio::{process::Child, sync::Mutex};

/// The broker borrows these sets. Its cancellation cannot destroy the only
/// handles needed to join nested tasks.
#[derive(Default)]
pub(super) struct Relays {
    pub tcp: tokio::task::JoinSet<io::Result<()>>,
    pub udp: tokio::task::JoinSet<io::Result<()>>,
}

#[derive(Default)]
pub(super) struct Resources {
    pub child: Option<Child>,
    pub guard_writer: Option<Child>,
    pub broker: Option<AbortTask<io::Result<()>>>,
    pub telemetry: Option<AbortTask<io::Result<()>>>,
    pub relays: Arc<Mutex<Relays>>,
    pub device: Option<tun_rs::SyncDevice>,
}

impl Resources {
    /// Only success permits guard cleanup or a preparation retry. Unconfirmed
    /// child termination must end the backend lifetime without clearing guards;
    /// independent process-pinned recovery owns that case. Cancellation retains
    /// ownership in `self`; dropping is not a shutdown barrier.
    pub async fn stop(&mut self) -> io::Result<()> {
        let worker = match &mut self.child {
            Some(child) => crate::task::terminate(child).await,
            None => Ok(()),
        };
        self.finish_stop(worker).await
    }

    async fn finish_stop(&mut self, worker: io::Result<()>) -> io::Result<()> {
        let guard = match &mut self.guard_writer {
            Some(child) => crate::task::terminate(child).await,
            None => Ok(()),
        };
        stop_task(&mut self.broker).await;
        let mut relays = self.relays.lock().await;
        relays.tcp.abort_all();
        relays.udp.abort_all();
        relays.tcp.shutdown().await;
        relays.udp.shutdown().await;
        drop(relays);
        stop_task(&mut self.telemetry).await;
        // Keep the TUN/child owned if worker termination was not confirmed.
        worker?;
        guard?;
        self.child = None;
        self.guard_writer = None;
        self.device = None;
        Ok(())
    }
}

async fn stop_task(task: &mut Option<AbortTask<io::Result<()>>>) {
    if let Some(task) = task.as_mut() {
        // Observation may already have consumed a completed handle. Completion
        // means it no longer borrows the sets or owns descriptors.
        if !task.0.is_finished() {
            task.0.abort();
            let _ = (&mut task.0).await;
        }
    }
    *task = None;
}

#[cfg(test)]
#[path = "resources_tests.rs"]
mod tests;
