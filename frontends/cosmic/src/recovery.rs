//! Independent helper progress. Observation never authorizes host cleanup or retry.
use super::{App, Message};
use crate::i18n::fl;
use cosmic::app::Task;
use nm_tunnel_client::{RecoveryError, RecoveryStatus};
use std::time::{Duration, Instant};

#[derive(Default)]
pub(super) struct Recovery {
    status: Option<RecoveryStatus>,
    error: Option<RecoveryError>,
    received: Option<Instant>,
}

impl Recovery {
    pub fn observe(&mut self, result: Result<Option<RecoveryStatus>, RecoveryError>) {
        self.error = result.as_ref().err().copied();
        self.status = result.ok().flatten();
        self.received = Some(Instant::now());
    }

    pub fn hint(&self) -> Option<String> {
        if self.error.is_some() {
            return Some(fl!("recovery-unavailable"));
        }
        let status = self.status?;
        if self
            .received
            .is_none_or(|time| time.elapsed() > Duration::from_secs(3))
        {
            return Some(fl!("recovery-stale"));
        }
        match status {
            RecoveryStatus::Starting => Some(fl!("recovery-starting")),
            RecoveryStatus::Watching => None,
            RecoveryStatus::Terminating => Some(fl!("recovery-terminating")),
            RecoveryStatus::Cleaning | RecoveryStatus::BackendCleanup => {
                Some(fl!("recovery-cleaning"))
            }
            RecoveryStatus::Retrying => Some(fl!("recovery-retrying")),
            RecoveryStatus::Cleaned => Some(fl!("recovery-cleaned")),
        }
    }
}

impl App {
    pub(super) fn poll_recovery(&mut self) -> Task<Message> {
        let Some(ticket) = self.reads.begin_recovery() else {
            return Task::none();
        };
        cosmic::task::future(async move {
            Message::RecoveryObserved(ticket, nm_tunnel_client::recovery_status().await)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_missing_and_stale_observations_never_certify_live_cleanup() {
        let mut recovery = Recovery::default();
        assert!(recovery.hint().is_none());
        recovery.observe(Ok(Some(RecoveryStatus::Cleaned)));
        assert!(
            recovery
                .hint()
                .is_some_and(|hint| hint.contains("without VPN"))
        );
        recovery.received = Some(Instant::now() - Duration::from_secs(4));
        assert!(
            recovery
                .hint()
                .is_some_and(|hint| hint.contains("not confirmed"))
        );
        recovery.observe(Err(RecoveryError::Unavailable));
        assert!(
            recovery
                .hint()
                .is_some_and(|hint| hint.contains("not confirmed"))
        );
        recovery.observe(Ok(None));
        assert!(recovery.hint().is_none());
    }
}
