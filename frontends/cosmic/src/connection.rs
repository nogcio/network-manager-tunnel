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
            return !self.busy && preview.disconnect_enabled();
        }
        !self.busy && self.snapshot.as_ref().is_some_and(|s| {
            matches!(s.active.as_slice(), [active] if active.state() != ConnectionState::Disconnecting)
        })
    }
    pub(super) fn active_count(&self) -> usize {
        #[cfg(all(feature = "preview", debug_assertions))]
        if let Some(preview) = &self.preview {
            return preview.active_count();
        }
        self.snapshot.as_ref().map_or(0, |s| s.active.len())
    }
    pub(super) fn can_connect(&self) -> bool {
        !self.busy
            && self.snapshot.as_ref().is_some_and(|s| {
                s.backend_registered
                    && s.active.is_empty()
                    && self
                        .saved_selected
                        .as_ref()
                        .is_some_and(|selected| s.profiles.contains(selected))
            })
    }
    pub(super) fn connection_title(&self) -> &'static str {
        #[cfg(all(feature = "preview", debug_assertions))]
        if let Some(preview) = &self.preview {
            return preview.connection_title();
        }
        if self.busy
            && let Some(intent) = &self.control
        {
            return match intent {
                Intent::Connect(_) => "Requesting connection…",
                Intent::Disconnect(_) => "Requesting disconnect…",
            };
        }
        let Some(snapshot) = &self.snapshot else {
            return if self.nm_error.is_some() {
                "NetworkManager unavailable"
            } else {
                "Checking NetworkManager…"
            };
        };
        match snapshot.active.as_slice() {
            [] => "Disconnected",
            [active] => match active.state() {
                ConnectionState::Connecting => "Connecting…",
                ConnectionState::Connected => "Connected",
                ConnectionState::Disconnecting => "Disconnecting…",
                ConnectionState::Unknown => "Unknown connection state",
            },
            _ => "Multiple VPN connections",
        }
    }
    pub(super) fn connection_hint(&self) -> &str {
        #[cfg(all(feature = "preview", debug_assertions))]
        if let Some(preview) = &self.preview {
            return preview.connection_hint();
        }
        match self.snapshot.as_ref() {
            Some(snapshot) if !snapshot.active.is_empty() => {
                if snapshot.active.len() == 1 {
                    snapshot.active[0].profile().name()
                } else {
                    "Manage the individual connections in NetworkManager."
                }
            }
            Some(snapshot) if !snapshot.backend_registered => "VPN backend unavailable",
            Some(_) => "",
            None if self.nm_error.is_some() => "Could not read NetworkManager state.",
            None => "",
        }
    }
    pub(super) fn connection_update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Poll => {
                if self.busy || self.monitor_pending {
                    return Task::none();
                }
                self.monitor_pending = true;
                let epoch = self.epoch;
                return cosmic::task::future(async move {
                    Message::Observed(epoch, nm_tunnel_client::snapshot().await)
                });
            }
            Message::Observed(epoch, result) => {
                self.monitor_pending = false;
                if epoch != self.epoch {
                    return Task::none();
                }
                match result {
                    Ok(snapshot) => {
                        let outcome = self.control.as_ref().and_then(|intent| {
                            intent.observe(
                                snapshot
                                    .active
                                    .iter()
                                    .map(|a| (a.profile().id(), a.state())),
                            )
                        });
                        match outcome {
                            Some(Outcome::Failed) => {
                                self.notice = Some(Notice::Error);
                                self.status = "The requested VPN is no longer active. Activation may have failed; the network guard can remain closed. No retry or guard removal was performed.".into();
                                self.control = None;
                            }
                            Some(Outcome::Connected) => {
                                self.notice = Some(Notice::Info);
                                self.status = "NetworkManager reports the VPN connected.".into();
                                self.control = None;
                            }
                            Some(Outcome::Disconnected) => {
                                self.notice = Some(Notice::Info);
                                self.status = "NetworkManager reports the VPN disconnected. This does not remove a retained crash guard.".into();
                                self.control = None;
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
                    self.begin_control(
                        Intent::Connect(profile.id().to_owned()),
                        "Requesting VPN activation from NetworkManager…",
                    );
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
                    self.begin_control(
                        Intent::Disconnect(active.profile().id().to_owned()),
                        "Requesting VPN disconnection from NetworkManager…",
                    );
                    return cosmic::task::future(async move {
                        Message::Controlled(nm_tunnel_client::deactivate(&active).await)
                    });
                }
            }
            Message::Controlled(result) => {
                self.busy = false;
                self.notice = Some(if result.is_ok() {
                    Notice::Info
                } else {
                    Notice::Error
                });
                if result.is_err() {
                    self.control = None;
                }
                self.status = match result {
                    Ok(()) => "Request accepted. The connection state above is read from NetworkManager; method completion is not tunnel readiness or cleanup.".into(),
                    Err(error) => error.to_string(),
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
    pub(super) fn begin_control(&mut self, intent: Intent, status: &str) {
        // Do not show a previous attempt's rates while changing connection state.
        self.traffic.observe(Ok(None));
        self.control = Some(intent);
        self.busy = true;
        self.epoch = self.epoch.wrapping_add(1);
        self.notice = None;
        self.status = status.into();
    }
}
