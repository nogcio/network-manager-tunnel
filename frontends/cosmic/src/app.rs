//! Subscription-only COSMIC UI using the toolkit's native settings/list controls.
use cosmic::{ApplicationExt, Core, Element, app::Task, executor};
use nm_tunnel_client::{ClientError, SavedProfile, Snapshot, Storage};
use nm_tunnel_subscription::{Subscription, SubscriptionError, fetch_subscription, validate_url};
use secrecy::{ExposeSecret, SecretString};
use std::collections::{BTreeMap, HashSet};

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[path = "view.rs"]
mod view;

#[path = "connection.rs"]
mod connection;

#[path = "traffic.rs"]
mod traffic;

#[path = "import.rs"]
mod import;

#[cfg(all(feature = "preview", debug_assertions))]
#[path = "preview.rs"]
mod preview;

#[derive(Clone, Default)]
pub(crate) struct Flags {
    #[cfg(all(feature = "preview", debug_assertions))]
    preview: Option<preview::Preview>,
}

impl Flags {
    pub(crate) fn theme(&self) -> cosmic::Theme {
        #[cfg(all(feature = "preview", debug_assertions))]
        if let Some(preview) = &self.preview {
            return preview.theme.clone();
        }
        cosmic::theme::system_preference()
    }
    pub(crate) fn window_size(&self) -> cosmic::iced::Size {
        #[cfg(all(feature = "preview", debug_assertions))]
        if let Some(preview) = &self.preview {
            return preview.size();
        }
        cosmic::iced::Size::new(760.0, 780.0)
    }

    pub(crate) fn from_env() -> Result<Self, &'static str> {
        #[cfg(all(feature = "preview", debug_assertions))]
        {
            Ok(Self {
                preview: preview::Preview::from_env()?,
            })
        }
        #[cfg(not(all(feature = "preview", debug_assertions)))]
        {
            Ok(Self::default())
        }
    }
}

pub(crate) struct App {
    core: Core,
    source: SecretString,
    subscription: Option<Subscription>,
    selected: Option<usize>,
    // Only additions made from the current loaded list; NM remains authoritative.
    added: BTreeMap<usize, String>,
    profile_page: usize,
    profile_search: String,
    uncertain: bool,
    busy: bool, // An NM mutation, independent of subscription HTTP ownership.
    fetching: bool,
    load_error: Option<SubscriptionError>,
    status: String,
    notice: Option<Notice>,
    snapshot: Option<Snapshot>,
    nm_error: Option<ClientError>,
    saved_selected: Option<SavedProfile>,
    remember: bool,
    monitor_pending: bool,
    epoch: u64,
    control: Option<connection::Intent>,
    page: Page,
    saved_search: String,
    details: Option<Details>,
    traffic: traffic::Traffic,
    ticks: u8,
    #[cfg(all(feature = "preview", debug_assertions))]
    preview: Option<preview::Preview>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Page {
    Connections,
    Import,
}

impl Page {
    fn header_title(self) -> &'static str {
        match self {
            Self::Connections => "NetworkManager Tunnel",
            Self::Import => "Import subscription",
        }
    }
}

#[derive(Clone)]
enum Details {
    Connection,
    Profile(String),
}

#[derive(Clone, Copy)]
enum Notice {
    Info,
    Error,
}

#[derive(Clone)]
pub(crate) enum Message {
    Navigate(Page),
    SearchSaved(String),
    ConnectProfile(String),
    AddProfile(usize),
    ShowDetails(Option<String>),
    CloseDetails,
    Tick,
    UsageObserved(
        u64,
        Result<Option<nm_tunnel_client::UsageSnapshot>, nm_tunnel_client::UsageError>,
    ),
    Source(String),
    Load,
    Loaded(Result<Subscription, SubscriptionError>),
    Select(usize),
    ProfilePage(usize),
    SearchProfiles(String),
    DismissNotice,
    Prepare,
    Prepared(Result<SavedProfile, ClientError>),
    Remember(bool),
    Poll,
    Observed(u64, Result<Snapshot, ClientError>),
    SavedSelected(String),
    Connect,
    Disconnect,
    Controlled(Result<(), ClientError>),
    #[cfg(all(feature = "preview", debug_assertions))]
    Frame(cosmic::iced::window::Id),
    #[cfg(all(feature = "preview", debug_assertions))]
    Captured(cosmic::iced::window::Screenshot),
}

// Toolkit diagnostics must not print subscription tokens, bodies or node credentials.
impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SubscriptionMessage([redacted])")
    }
}

impl cosmic::Application for App {
    type Executor = executor::Default;
    type Flags = Flags;
    type Message = Message;
    const APP_ID: &'static str = "io.github.nm_tunnel.Cosmic";

    fn core(&self) -> &Core {
        &self.core
    }
    fn core_mut(&mut self) -> &mut Core {
        &mut self.core
    }

    fn init(core: Core, _flags: Flags) -> (Self, Task<Message>) {
        let mut app = Self {
            core,
            source: SecretString::from(String::new()),
            subscription: None,
            selected: None,
            added: BTreeMap::new(),
            profile_page: 0,
            profile_search: String::new(),
            uncertain: false,
            busy: false,
            fetching: false,
            load_error: None,
            status: "Add a subscription to load your profiles.".into(),
            notice: None,
            snapshot: None,
            nm_error: None,
            saved_selected: None,
            remember: false,
            monitor_pending: false,
            epoch: 0,
            control: None,
            page: Page::Connections,
            saved_search: String::new(),
            details: None,
            traffic: traffic::Traffic::default(),
            ticks: 0,
            #[cfg(all(feature = "preview", debug_assertions))]
            preview: None,
        };
        #[cfg(all(feature = "preview", debug_assertions))]
        if let Some(preview) = _flags.preview {
            preview.seed(&mut app);
            app.preview = Some(preview);
        }
        // One title in the start slot; leave the toolkit's center title empty.
        app.set_header_title(String::new());
        let task = app
            .core
            .main_window_id()
            .map(|id| app.set_window_title("NetworkManager Tunnel".into(), id))
            .unwrap_or_else(Task::none);
        (
            app,
            Task::batch([
                task,
                cosmic::task::future(async { Message::Poll }),
                cosmic::task::future(async { Message::Tick }),
            ]),
        )
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        #[cfg(all(feature = "preview", debug_assertions))]
        if self.preview.is_some() {
            return preview::update(self, message);
        }
        if self.busy
            && !matches!(
                message,
                Message::Loaded(_)
                    | Message::Prepared(_)
                    | Message::Controlled(_)
                    | Message::Observed(_, _)
                    | Message::SearchProfiles(_)
                    | Message::ProfilePage(_)
                    | Message::DismissNotice
                    | Message::Navigate(_)
                    | Message::SearchSaved(_)
                    | Message::ShowDetails(_)
                    | Message::CloseDetails
                    | Message::Tick
                    | Message::UsageObserved(_, _)
            )
        {
            return Task::none();
        }
        match message {
            Message::Navigate(page) => {
                self.page = page;
                self.details = None;
                self.core.set_show_context(false);
                let scroll = self.reset_page_scroll();
                let focus = if page == Page::Import {
                    cosmic::widget::text_input::focus(cosmic::widget::Id::new("subscription-url"))
                } else {
                    Task::none()
                };
                return Task::batch([scroll, focus]);
            }
            Message::SearchSaved(value) => self.saved_search = value.chars().take(128).collect(),
            Message::ShowDetails(profile) => {
                self.details = Some(profile.map_or(Details::Connection, Details::Profile));
                self.core.set_show_context(true);
            }
            Message::CloseDetails => {
                self.details = None;
                self.core.set_show_context(false);
            }
            Message::ConnectProfile(id) => {
                let _ = self.connection_update(Message::SavedSelected(id));
                return self.connection_update(Message::Connect);
            }
            Message::AddProfile(index) => {
                if self.fetching || self.uncertain {
                    return Task::none();
                }
                // Reject stale/out-of-range rows without adding an older selection.
                if !self
                    .subscription
                    .as_ref()
                    .and_then(|s| s.entries().get(index))
                    .is_some_and(|e| e.profile().is_ok())
                {
                    return Task::none();
                }
                let _ = self.update(Message::Select(index));
                return self.update(Message::Prepare);
            }
            Message::Tick => {
                self.ticks = (self.ticks + 1) % 3;
                let usage = self.poll_usage();
                let nm = if self.ticks == 1 {
                    self.connection_update(Message::Poll)
                } else {
                    Task::none()
                };
                return Task::batch([usage, nm]);
            }
            Message::UsageObserved(epoch, result) => {
                self.traffic.pending = false;
                if epoch == self.epoch {
                    self.traffic.observe(result);
                }
            }
            Message::DismissNotice => {
                self.notice = None;
            }
            Message::SearchProfiles(value) => {
                self.profile_search = value.chars().take(128).collect();
                self.profile_page = 0;
            }
            #[cfg(all(feature = "preview", debug_assertions))]
            Message::Frame(_) | Message::Captured(_) => {}
            Message::Remember(value) => {
                self.remember = value;
            }
            Message::Poll
            | Message::Observed(_, _)
            | Message::SavedSelected(_)
            | Message::Connect
            | Message::Disconnect
            | Message::Controlled(_) => {
                return self.connection_update(message);
            }
            Message::Source(value) => {
                if self.fetching {
                    return Task::none();
                }
                self.load_error = None;
                self.notice = None;
                self.source = SecretString::from(value);
                self.status =
                    "Press Load to fetch this URL. The loaded profile list is unchanged.".into();
            }
            Message::Load => {
                if self.fetching {
                    return Task::none();
                }
                if let Err(error) = validate_url(self.source.expose_secret()) {
                    self.load_error = Some(error);
                    return Task::none();
                }
                self.fetching = true;
                self.load_error = None;
                let source = self.source.clone();
                return cosmic::task::future(async move {
                    Message::Loaded(fetch_subscription(source).await)
                });
            }
            Message::Loaded(result) => {
                self.fetching = false;
                self.load_error = None;
                match result {
                    Ok(subscription) => {
                        self.selected = subscription
                            .entries()
                            .iter()
                            .position(|entry| entry.profile().is_ok());
                        self.subscription = Some(subscription);
                        self.added.clear();
                        self.profile_page = 0;
                        // An ambiguous previous save is not cleared by an unrelated HTTP refresh.
                    }
                    Err(error) => {
                        self.load_error = Some(error);
                    }
                }
            }
            Message::Select(index) => {
                if self
                    .subscription
                    .as_ref()
                    .and_then(|list| list.entries().get(index))
                    .is_some_and(|entry| entry.profile().is_ok())
                {
                    self.selected = Some(index);
                    self.notice = None;
                    self.status = "Profile selected. No connection request was made.".into();
                }
            }
            Message::ProfilePage(page) => {
                if page < self.matching_profiles().len().div_ceil(view::PAGE_SIZE) {
                    self.profile_page = page;
                    return self.reset_page_scroll();
                }
            }
            Message::Prepare => {
                if self.fetching || self.uncertain || self.selected_added() {
                    return Task::none();
                }
                let profile = self
                    .subscription
                    .as_ref()
                    .and_then(|list| self.selected.and_then(|index| list.entries().get(index)))
                    .and_then(|entry| entry.profile().ok())
                    .cloned();
                if let Some(profile) = profile {
                    // A new explicit action owns feedback; an earlier accepted
                    // control must not overwrite this save's eventual failure.
                    self.control = None;
                    self.notice = None;
                    self.busy = true;
                    self.epoch = self.epoch.wrapping_add(1);
                    self.status = "Adding the selected profile to NetworkManager…".into();
                    let storage = if self.remember {
                        Storage::Persistent
                    } else {
                        Storage::Session
                    };
                    return cosmic::task::future(async move {
                        Message::Prepared(
                            nm_tunnel_client::save_profile_with_storage(profile, storage).await,
                        )
                    });
                }
            }
            Message::Prepared(result) => {
                self.busy = false;
                match result {
                    Ok(saved) => {
                        self.notice = Some(Notice::Info);
                        if let Some(index) = self.selected {
                            self.added.insert(index, saved.id().to_owned());
                        }
                        self.status = if saved.persistent() {
                            "Saved in NetworkManager, including system-stored credentials. Autoconnect is off; no connection was started."
                        } else {
                            "Added to NetworkManager for this session. Autoconnect is off; no connection was started."
                        }.into();
                        self.saved_selected = Some(saved);
                    }
                    Err(error) => {
                        self.uncertain = error == ClientError::Timeout;
                        self.notice = (!self.uncertain).then_some(Notice::Error);
                        self.status = error.to_string();
                    }
                }
                return self.connection_update(Message::Poll);
            }
        }
        Task::none()
    }

    fn subscription(&self) -> cosmic::iced::Subscription<Message> {
        #[cfg(all(feature = "preview", debug_assertions))]
        if self
            .preview
            .as_ref()
            .is_some_and(|preview| preview.needs_capture())
        {
            return cosmic::iced::window::frames().map(|(id, _)| Message::Frame(id));
        }
        #[cfg(all(feature = "preview", debug_assertions))]
        if self.preview.is_some() {
            return cosmic::iced::Subscription::none();
        }
        cosmic::iced::time::every(std::time::Duration::from_secs(1)).map(|_| Message::Tick)
    }

    fn view(&self) -> Element<'_, Message> {
        self.page()
    }

    fn header_start(&self) -> Vec<Element<'_, Message>> {
        let mut elements = Vec::new();
        if self.page == Page::Import {
            elements.push(
                cosmic::widget::button::icon(cosmic::widget::icon::from_name(
                    "go-previous-symbolic",
                ))
                .tooltip("Back to connections")
                .name("Back to connections")
                .on_press(Message::Navigate(Page::Connections))
                .into(),
            );
        }
        elements.push(
            cosmic::widget::text::heading(self.page.header_title())
                .wrapping(cosmic::iced::core::text::Wrapping::None)
                .ellipsize(cosmic::iced::core::text::Ellipsize::End(
                    cosmic::iced::core::text::EllipsizeHeightLimit::Lines(1),
                ))
                .into(),
        );
        elements
    }

    fn header_end(&self) -> Vec<Element<'_, Message>> {
        match self.page {
            Page::Connections => vec![
                cosmic::widget::button::standard("Import subscription…")
                    .on_press(Message::Navigate(Page::Import))
                    .into(),
            ],
            Page::Import => Vec::new(),
        }
    }

    fn context_drawer(&self) -> Option<cosmic::app::context_drawer::ContextDrawer<'_, Message>> {
        self.details_drawer()
    }

    fn on_escape(&mut self) -> Task<Message> {
        self.update(if self.details.is_some() {
            Message::CloseDetails
        } else {
            Message::Navigate(Page::Connections)
        })
    }
}

impl App {
    fn reset_page_scroll(&self) -> Task<Message> {
        cosmic::iced::widget::scrollable::snap_to(
            cosmic::widget::Id::new(match self.page {
                Page::Connections => "connections-page",
                Page::Import => "import-page",
            }),
            cosmic::iced::widget::scrollable::RelativeOffset {
                x: Some(0.0),
                y: Some(0.0),
            },
        )
    }
    fn selected_added(&self) -> bool {
        self.selected
            .is_some_and(|index| self.added.contains_key(&index))
    }

    fn reconcile_added<'a>(&mut self, profiles: impl Iterator<Item = &'a str>) {
        let ids: HashSet<_> = profiles.collect();
        self.added.retain(|_, id| ids.contains(id.as_str()));
    }
}
