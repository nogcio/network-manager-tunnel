//! Read-only NM monitoring and explicit control. No optimistic Connected state.
use super::{App, Message, Notice};
use cosmic::app::Task;
use nm_tunnel_client::ConnectionState;

#[derive(Clone)]
pub(super) enum Intent {
    Connect(String),
    Disconnect(String),
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    Connected,
    Disconnected,
    Failed,
}

impl Intent {
    // Match the requested NM profile UUID, never an unrelated active entry.
    pub(super) fn observe<'a>(
        &self,
        active: impl Iterator<Item = (&'a str, ConnectionState)>,
    ) -> Option<Outcome> {
        let id = match self {
            Self::Connect(id) | Self::Disconnect(id) => id,
        };
        let mut present = false;
        let mut connected = false;
        for (active_id, state) in active {
            if active_id == id {
                present = true;
                connected |= state == ConnectionState::Connected;
            }
        }
        match self {
            Self::Connect(_) if !present => Some(Outcome::Failed),
            Self::Connect(_) if connected => Some(Outcome::Connected),
            Self::Disconnect(_) if !present => Some(Outcome::Disconnected),
            _ => None,
        }
    }
}

impl App {
    pub(super) fn can_disconnect(&self) -> bool {
        #[cfg(all(feature = "preview", debug_assertions))]
        if let Some(preview) = &self.preview {
            return !self.operations.busy() && preview.disconnect_enabled();
        }
        !self.operations.busy() && (self.snapshot.as_ref().is_some_and(|s| {
            matches!(s.active.as_slice(), [active] if active.state() != ConnectionState::Disconnecting)
        }) || (self.active_count() == 0 && self.recovery.can_disconnect()))
    }
    pub(super) fn active_count(&self) -> usize {
        #[cfg(all(feature = "preview", debug_assertions))]
        if let Some(preview) = &self.preview {
            return preview.active_count();
        }
        self.snapshot.as_ref().map_or(0, |s| s.active.len())
    }
    pub(super) fn can_connect(&self) -> bool {
        !self.operations.busy()
            && self.snapshot.as_ref().is_some_and(|s| {
                s.backend_registered
                    && s.active.is_empty()
                    && self
                        .saved_selected
                        .as_ref()
                        .is_some_and(|selected| s.profiles.contains(selected))
            })
    }
    pub(super) fn connection_title(&self) -> String {
        #[cfg(all(feature = "preview", debug_assertions))]
        if let Some(preview) = &self.preview {
            return preview.connection_title();
        }
        if self.operations.busy()
            && let Some(intent) = self.operations.control()
        {
            return match intent {
                Intent::Connect(_) => crate::i18n::fl!("requesting-connection"),
                Intent::Disconnect(_) => crate::i18n::fl!("requesting-disconnect"),
            };
        }
        let Some(snapshot) = &self.snapshot else {
            return if self.nm_error.is_some() {
                crate::i18n::fl!("nm-unavailable")
            } else {
                crate::i18n::fl!("checking-nm")
            };
        };
        match snapshot.active.as_slice() {
            [] => crate::i18n::fl!("disconnected"),
            [active] => match active.state() {
                ConnectionState::Connecting => crate::i18n::fl!("connecting"),
                ConnectionState::Connected => crate::i18n::fl!("connected"),
                ConnectionState::Disconnecting => crate::i18n::fl!("disconnecting"),
                ConnectionState::Unknown => crate::i18n::fl!("unknown-connection-state"),
            },
            _ => crate::i18n::fl!("multiple-connections"),
        }
    }
    pub(super) fn connection_hint(&self) -> String {
        #[cfg(all(feature = "preview", debug_assertions))]
        if let Some(preview) = &self.preview {
            return preview.connection_hint();
        }
        match self.snapshot.as_ref() {
            Some(snapshot) if !snapshot.active.is_empty() => {
                if snapshot.active.len() == 1 {
                    snapshot.active[0].profile().name().to_owned()
                } else {
                    crate::i18n::fl!("manage-in-nm")
                }
            }
            Some(snapshot) if !snapshot.backend_registered => {
                crate::i18n::fl!("backend-unavailable")
            }
            Some(_) => String::new(),
            None if self.nm_error.is_some() => crate::i18n::fl!("nm-read-failed"),
            None => String::new(),
        }
    }
    pub(super) fn connection_update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Poll => {
                if self.operations.busy() && !self.waiting_for_delete() {
                    return Task::none();
                }
                let Some(ticket) = self.reads.begin_nm() else {
                    return Task::none();
                };
                return cosmic::task::future(async move {
                    Message::Observed(ticket, nm_tunnel_client::snapshot().await)
                });
            }
            Message::Observed(ticket, result) => {
                if !self.reads.finish_nm(ticket) {
                    return Task::none();
                }
                match result {
                    Ok(snapshot) => {
                        let outcome = self.operations.observe(
                            snapshot
                                .active
                                .iter()
                                .map(|a| (a.profile().id(), a.state())),
                        );
                        match outcome {
                            Some(Outcome::Failed) => {
                                self.notice = Some(Notice::Error);
                                self.status = crate::i18n::fl!("vpn-ended-status");
                            }
                            Some(Outcome::Connected) => {
                                self.notice = Some(Notice::Info);
                                self.status = crate::i18n::fl!("vpn-connected-status");
                            }
                            Some(Outcome::Disconnected) => {
                                self.notice = Some(Notice::Info);
                                self.status = crate::i18n::fl!("vpn-disconnected-status");
                            }
                            _ => {}
                        }
                        self.reconcile_added(snapshot.profiles.iter().map(|p| p.id()));
                        // Keep selection by NM identity, not list position. Never
                        // select or activate a replacement profile automatically.
                        self.saved_selected = self.saved_selected.as_ref().and_then(|old| {
                            snapshot
                                .profiles
                                .iter()
                                .find(|p| p.id() == old.id())
                                .cloned()
                        });
                        self.snapshot = Some(snapshot);
                        self.nm_error = None;
                        return self.deletion_observed();
                    }
                    Err(error) => {
                        self.snapshot = None;
                        self.nm_error = Some(error);
                    }
                }
            }
            Message::SavedSelected(id) => {
                self.saved_selected = self
                    .snapshot
                    .as_ref()
                    .and_then(|s| s.profiles.iter().find(|p| p.id() == id))
                    .cloned();
            }
            Message::Connect if self.can_connect() => {
                if let Some(profile) = self.saved_selected.clone() {
                    if !self.begin_control(
                        Intent::Connect(profile.id().to_owned()),
                        &crate::i18n::fl!("requesting-nm-activation"),
                    ) {
                        return Task::none();
                    }
                    return cosmic::task::future(async move {
                        Message::Controlled(nm_tunnel_client::activate(&profile).await)
                    });
                }
            }
            Message::Disconnect if self.can_disconnect() => {
                let active = self
                    .snapshot
                    .as_ref()
                    .and_then(|s| match s.active.as_slice() {
                        [active] => Some(active.clone()),
                        _ => None,
                    });
                if let Some(active) = active {
                    if !self.begin_control(
                        Intent::Disconnect(active.profile().id().to_owned()),
                        &crate::i18n::fl!("requesting-nm-disconnection"),
                    ) {
                        return Task::none();
                    }
                    return cosmic::task::future(async move {
                        Message::Controlled(nm_tunnel_client::deactivate(&active).await)
                    });
                } else if self.recovery.can_disconnect() {
                    if !self.begin_control(
                        Intent::Disconnect(":protection".into()),
                        &crate::i18n::fl!("requesting-nm-disconnection"),
                    ) {
                        return Task::none();
                    }
                    return cosmic::task::future(async move {
                        Message::Controlled(nm_tunnel_client::disconnect_protection().await)
                    });
                }
            }
            Message::Controlled(result) => {
                if !self.operations.finish_control(result.is_ok()) {
                    return Task::none();
                }
                self.notice = result.as_ref().err().map(|_| Notice::Error);
                self.status = match result {
                    Ok(()) => crate::i18n::fl!("waiting-nm-status"),
                    Err(error) => crate::i18n::client_error(error),
                };
                // Disallow another request until a fresh observation, including
                // after ambiguous timeout. Nothing is automatically retried.
                self.snapshot = None;
                return self.connection_update(Message::Poll);
            }
            _ => {}
        }
        Task::none()
    }
    pub(super) fn begin_control(&mut self, intent: Intent, status: &str) -> bool {
        if !self.operations.begin_control(intent) {
            return false;
        }
        // Do not show a previous attempt's rates while changing connection state.
        self.traffic.observe(Ok(None));
        self.reads.invalidate();
        self.notice = None;
        self.status = status.into();
        true
    }
}
