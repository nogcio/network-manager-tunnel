//! Independent coalesced read lifetimes. Invalidation does not cancel remote work.

/// Opaque request identity. It contains no backend/profile identity or credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ticket(u64);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Slot {
    pending: Option<(Ticket, bool)>,
}

impl Slot {
    pub fn pending(&self) -> Option<Ticket> {
        self.pending.map(|(ticket, _)| ticket)
    }

    fn finish(&mut self, ticket: Ticket) -> bool {
        let Some((expected, obsolete)) = self.pending else {
            return false;
        };
        if expected != ticket {
            return false;
        }
        self.pending = None;
        !obsolete
    }

    fn invalidate(&mut self) {
        if let Some((_, obsolete)) = &mut self.pending {
            *obsolete = true;
        }
    }
}

/// NM metadata and backend usage never complete one another. Every admitted read
/// has a unique ticket; late/duplicate results cannot clear a newer pending slot.
/// Mutations invalidate both existing reads but leave them owned until completion.
/// Exhausted ticket space stops scheduling rather than reusing an old identity.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Reads {
    next: u64,
    pub nm: Slot,
    pub usage: Slot,
    pub recovery: Slot,
}

impl Reads {
    fn start(next: &mut u64, slot: &mut Slot) -> Option<Ticket> {
        if slot.pending.is_some() {
            return None;
        }
        *next = next.checked_add(1)?;
        let ticket = Ticket(*next);
        slot.pending = Some((ticket, false));
        Some(ticket)
    }

    pub fn begin_nm(&mut self) -> Option<Ticket> {
        Self::start(&mut self.next, &mut self.nm)
    }
    pub fn begin_usage(&mut self) -> Option<Ticket> {
        Self::start(&mut self.next, &mut self.usage)
    }
    pub fn begin_recovery(&mut self) -> Option<Ticket> {
        Self::start(&mut self.next, &mut self.recovery)
    }
    pub fn finish_recovery(&mut self, ticket: Ticket) -> bool {
        self.recovery.finish(ticket)
    }
    pub fn finish_nm(&mut self, ticket: Ticket) -> bool {
        self.nm.finish(ticket)
    }
    pub fn finish_usage(&mut self, ticket: Ticket) -> bool {
        self.usage.finish(ticket)
    }

    pub fn invalidate(&mut self) {
        self.nm.invalidate();
        self.usage.invalidate();
        self.recovery.invalidate();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalidation_releases_only_the_matching_slot_without_publishing_old_data() {
        let mut reads = Reads::default();
        let Some(nm) = reads.begin_nm() else {
            panic!("Missing NM ticket");
        };
        let Some(usage) = reads.begin_usage() else {
            panic!("Missing usage ticket");
        };
        let Some(recovery) = reads.begin_recovery() else {
            panic!("Missing recovery ticket");
        };
        assert!(reads.begin_nm().is_none());
        assert!(reads.begin_usage().is_none());
        assert!(reads.begin_recovery().is_none());
        reads.invalidate();
        let before = reads.clone();
        assert!(!reads.finish_nm(usage));
        assert!(!reads.finish_usage(nm));
        assert_eq!(reads, before);
        assert!(!reads.finish_recovery(usage));
        assert_eq!(reads.recovery.pending(), Some(recovery));
        assert!(!reads.finish_nm(nm));
        assert!(reads.nm.pending().is_none());
        assert_eq!(reads.usage.pending(), Some(usage));
        let Some(new_nm) = reads.begin_nm() else {
            panic!("Missing new NM ticket");
        };
        let before = reads.clone();
        assert!(!reads.finish_nm(nm));
        assert_eq!(reads, before);
        assert!(reads.finish_nm(new_nm));
        assert!(!reads.finish_usage(usage));
        let Some(new_usage) = reads.begin_usage() else {
            panic!("Missing new usage ticket");
        };
        assert!(reads.finish_usage(new_usage));
        assert!(!reads.finish_usage(new_usage));
        assert!(!reads.finish_recovery(recovery));
    }

    #[test]
    fn ticket_exhaustion_never_reuses_a_completed_request() {
        let mut reads = Reads {
            next: u64::MAX,
            ..Default::default()
        };
        let before = reads.clone();
        assert!(reads.begin_nm().is_none());
        assert!(reads.begin_usage().is_none());
        assert!(reads.begin_recovery().is_none());
        assert_eq!(reads, before);
    }
}
