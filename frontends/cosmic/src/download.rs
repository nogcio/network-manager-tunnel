//! One memory-only subscription request, independent of NM operations and reads.
use nm_tunnel_subscription::{Subscription, SubscriptionError, SubscriptionFormat, validate_url};
use secrecy::{ExposeSecret, SecretString};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ticket(u64);

pub(super) struct Download {
    source: SecretString,
    format: SubscriptionFormat,
    next: u64,
    pending: Option<Ticket>,
    error: Option<SubscriptionError>,
}

impl Default for Download {
    fn default() -> Self {
        Self {
            source: SecretString::from(String::new()),
            format: SubscriptionFormat::Complete,
            next: 0,
            pending: None,
            error: None,
        }
    }
}

impl Download {
    pub fn source(&self) -> &SecretString {
        &self.source
    }
    pub fn format(&self) -> SubscriptionFormat {
        self.format
    }
    pub fn pending(&self) -> Option<Ticket> {
        self.pending
    }
    pub fn error(&self) -> Option<SubscriptionError> {
        self.error
    }

    pub fn edit_source(&mut self, source: String) -> bool {
        if self.pending.is_some() {
            return false;
        }
        self.source = SecretString::from(source);
        self.error = None;
        true
    }

    pub fn choose_format(&mut self, format: SubscriptionFormat) -> bool {
        if self.pending.is_some() {
            return false;
        }
        self.format = format;
        self.error = None;
        true
    }

    /// Freeze source/format in an owned request. Admission failures start no I/O;
    /// tickets are never reused. Cancellation drops the task, not an NM operation.
    pub fn begin(&mut self) -> Option<(Ticket, SecretString, SubscriptionFormat)> {
        if self.pending.is_some() {
            return None;
        }
        if let Err(error) = validate_url(self.source.expose_secret()) {
            self.error = Some(error);
            return None;
        }
        let Some(next) = self.next.checked_add(1) else {
            self.error = Some(SubscriptionError::Download);
            return None;
        };
        self.next = next;
        let ticket = Ticket(next);
        self.pending = Some(ticket);
        self.error = None;
        Some((ticket, self.source.clone(), self.format))
    }

    /// Reject unsolicited/duplicate results without altering the current request,
    /// retained catalog admission, review, error or NM feedback.
    pub fn finish(
        &mut self,
        ticket: Ticket,
        result: Result<Subscription, SubscriptionError>,
    ) -> Option<Result<Subscription, SubscriptionError>> {
        if self.pending != Some(ticket) {
            return None;
        }
        self.pending = None;
        self.error = result.as_ref().err().copied();
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_matching_request_can_finish_or_change_admission_feedback() {
        let mut download = Download::default();
        assert!(download.begin().is_none());
        assert!(download.error().is_some());
        assert!(download.edit_source("https://subscription.example/synthetic".into()));
        let Some((old, source, format)) = download.begin() else {
            panic!("No admitted download");
        };
        assert_eq!(format, SubscriptionFormat::Complete);
        assert!(!download.edit_source("https://other.example/ignored".into()));
        assert!(!download.choose_format(SubscriptionFormat::NodesOnly));
        assert_eq!(download.source().expose_secret(), source.expose_secret());
        assert!(download.begin().is_none());
        assert!(
            download
                .finish(old, Err(SubscriptionError::Download))
                .is_some()
        );
        let Some((current, _, _)) = download.begin() else {
            panic!("No new download");
        };
        assert!(
            download
                .finish(old, Err(SubscriptionError::InvalidUrl))
                .is_none()
        );
        assert_eq!(download.pending(), Some(current));
        assert!(download.error().is_none());
        assert!(
            download
                .finish(current, Err(SubscriptionError::Download))
                .is_some()
        );
        assert_eq!(download.error(), Some(SubscriptionError::Download));
    }
}
