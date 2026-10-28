//! Pure NM operation lifecycle. HTTP, widgets and observation tasks do not own it.
use super::connection::{Intent, Outcome};
use nm_tunnel_client::{ClientError, ConnectionState};

#[derive(Default)]
enum Phase {
    #[default]
    Idle,
    Adding(usize),
    Storage(StorageTicket),
    Requesting(Intent),
    AwaitingObservation(Intent),
}

/// One dispatched mutation at a time. Accepted control is not observed success.
/// A new explicit action supersedes old control feedback, not an in-flight request.
/// Ambiguous storage permanently blocks further storage for this app session;
/// control and read-only work remain available. No transition retries remote I/O.
#[derive(Default)]
pub(super) struct Operations {
    phase: Phase,
    storage_uncertain: bool,
    next_storage: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct StorageTicket(u64);

#[cfg(test)]
impl StorageTicket {
    pub(super) fn test_foreign() -> Self {
        Self(u64::MAX)
    }
}

impl Operations {
    pub(super) fn block_uncertain_storage(&mut self) {
        self.storage_uncertain = true;
    }
    pub fn busy(&self) -> bool {
        matches!(
            self.phase,
            Phase::Adding(_) | Phase::Storage(_) | Phase::Requesting(_)
        )
    }

    pub fn uncertain(&self) -> bool {
        self.storage_uncertain
    }

    pub fn control(&self) -> Option<&Intent> {
        match &self.phase {
            Phase::Requesting(intent) | Phase::AwaitingObservation(intent) => Some(intent),
            _ => None,
        }
    }

    pub fn begin_add(&mut self, index: usize) -> bool {
        if self.busy() || self.storage_uncertain {
            return false;
        }
        self.phase = Phase::Adding(index);
        true
    }

    pub fn begin_storage(&mut self) -> Option<StorageTicket> {
        if self.busy() || self.storage_uncertain {
            return None;
        }
        self.next_storage = self.next_storage.checked_add(1)?;
        let ticket = StorageTicket(self.next_storage);
        self.phase = Phase::Storage(ticket);
        Some(ticket)
    }

    pub fn finish_storage(&mut self, ticket: StorageTicket, error: Option<ClientError>) -> bool {
        if !matches!(self.phase, Phase::Storage(pending) if pending == ticket) {
            return false;
        }
        self.phase = Phase::Idle;
        self.storage_uncertain |= error == Some(ClientError::Timeout);
        true
    }

    pub fn begin_control(&mut self, intent: Intent) -> bool {
        if self.busy() {
            return false;
        }
        self.phase = Phase::Requesting(intent);
        true
    }

    /// Only the dispatched operation's completion may release its slot. The row
    /// comes from admission, not whichever selection a later view happens to show.
    pub fn finish_add(&mut self, error: Option<ClientError>) -> Option<usize> {
        let Phase::Adding(index) = self.phase else {
            return None;
        };
        self.phase = Phase::Idle;
        self.storage_uncertain |= error == Some(ClientError::Timeout);
        Some(index)
    }

    pub fn finish_control(&mut self, accepted: bool) -> bool {
        if !matches!(self.phase, Phase::Requesting(_)) {
            return false;
        }
        let Phase::Requesting(intent) = std::mem::take(&mut self.phase) else {
            return false;
        };
        if accepted {
            self.phase = Phase::AwaitingObservation(intent);
        }
        true
    }

    /// Only a post-acceptance NM observation can complete control feedback.
    pub fn observe<'a>(
        &mut self,
        active: impl Iterator<Item = (&'a str, ConnectionState)>,
    ) -> Option<Outcome> {
        let Phase::AwaitingObservation(intent) = &self.phase else {
            return None;
        };
        let outcome = intent.observe(active);
        if outcome.is_some() {
            self.phase = Phase::Idle;
        }
        outcome
    }
}

#[cfg(test)]
#[path = "operations_tests.rs"]
mod tests;
