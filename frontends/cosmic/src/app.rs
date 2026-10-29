//! Subscription-only COSMIC UI using the toolkit's native settings/list controls.
use crate::i18n::fl;
use cosmic::{ApplicationExt, Core, Element, app::Task, executor};
use nm_tunnel_client::{ClientError, SavedProfile, Snapshot};
use nm_tunnel_subscription::{
    Subscription, SubscriptionError, SubscriptionFormat, fetch_subscription_format,
};

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

#[path = "options.rs"]
mod options;
pub(crate) use options::DnsChoice;

#[path = "catalog.rs"]
mod catalog;

#[path = "operations.rs"]
mod operations;

#[path = "reads.rs"]
mod reads;

#[path = "recovery.rs"]
mod recovery;

#[path = "package_update.rs"]
mod package_update;

#[path = "download.rs"]
mod download;

#[path = "navigation.rs"]
mod navigation;

#[path = "profile_editor.rs"]
mod profile_editor;

#[path = "subscriptions.rs"]
mod subscriptions;

#[path = "source_store.rs"]
mod source_store;

#[cfg(all(feature = "preview", debug_assertions))]
#[path = "preview.rs"]
mod preview;

#[derive(Clone, Default)]
pub(crate) struct Flags {
    #[cfg(all(feature = "preview", debug_assertions))]
    preview: Option<preview::Preview>,
}

impl Flags {
    /// Only synthetic previews override the toolkit's live system theme.
    pub(crate) fn theme_override(&self) -> Option<cosmic::Theme> {
        #[cfg(all(feature = "preview", debug_assertions))]
        if let Some(preview) = &self.preview {
            return Some(preview.theme.clone());
        }
        None
    }
    pub(crate) fn window_size(&self) -> cosmic::iced::Size {
        #[cfg(all(feature = "preview", debug_assertions))]
        if let Some(preview) = &self.preview {
            return preview.size();
        }
        cosmic::iced::Size::new(1024.0, 840.0)
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
    download: download::Download,
    catalog: catalog::Catalog,
    operations: operations::Operations,
    options: options::ProfileOptions,
    sources: subscriptions::Sources,
    status: String,
    notice: Option<Notice>,
    snapshot: Option<Snapshot>,
    nm_error: Option<ClientError>,
    saved_selected: Option<SavedProfile>,
    reads: reads::Reads,
    page: Page,
    navigation: navigation::Navigation,
    editor: Option<profile_editor::Editor>,
    profile_save: Option<operations::StorageTicket>,
    deletion: Option<profile_editor::Deletion>,
    saved_search: String,
    details: Option<Details>,
    traffic: traffic::Traffic,
    recovery: recovery::Recovery,
    ticks: u8,
    package_update: package_update::Update,
    #[cfg(all(feature = "preview", debug_assertions))]
    preview: Option<preview::Preview>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Page {
    Connections,
    Import,
}

impl Page {
    fn scroll_id(self) -> &'static str {
        match self {
            Self::Connections => "connections-page",
            Self::Import => "import-page",
        }
    }

    fn title(self) -> String {
        match self {
            Self::Connections => fl!("connections"),
            Self::Import => fl!("subscriptions"),
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
    Profile(profile_editor::Action),
    Subscription(subscriptions::Action),
    Navigate(Page),
    PageScrolled(Page, cosmic::iced::widget::scrollable::AbsoluteOffset),
    SearchSaved(String),
    ConnectProfile(String),
    AddProfile(usize),
    ShowDetails(Option<String>),
    CloseDetails,
    Tick,
    PackageObserved(bool),
    UsageObserved(
        reads::Ticket,
        Result<Option<nm_tunnel_client::UsageSnapshot>, nm_tunnel_client::UsageError>,
    ),
    RecoveryObserved(
        reads::Ticket,
        Result<Option<nm_tunnel_client::RecoveryStatus>, nm_tunnel_client::RecoveryError>,
    ),
    Source(String),
    FetchComplete(bool),
    DnsChoice(DnsChoice),
    ManualDns(String),
    LanBypass(bool),
    DnsInterception(bool),
    FakeIp(bool),
    Load,
    Loaded(download::Ticket, Result<Subscription, SubscriptionError>),
    Select(usize),
    ProfilePage(usize),
    SearchProfiles(String),
    DismissNotice,
    Prepare,
    Prepared(Result<SavedProfile, ClientError>),
    Poll,
    Observed(reads::Ticket, Result<Snapshot, ClientError>),
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
            download: download::Download::default(),
            catalog: catalog::Catalog::default(),
            operations: operations::Operations::default(),
            options: options::ProfileOptions::default(),
            sources: subscriptions::Sources::default(),
            status: fl!("initial-status"),
            notice: None,
            snapshot: None,
            nm_error: None,
            saved_selected: None,
            reads: reads::Reads::default(),
            page: Page::Connections,
            navigation: navigation::Navigation::default(),
            editor: None,
            profile_save: None,
            deletion: None,
            saved_search: String::new(),
            details: None,
            traffic: traffic::Traffic::default(),
            recovery: recovery::Recovery::default(),
            ticks: 0,
            package_update: package_update::Update::installed(),
            #[cfg(all(feature = "preview", debug_assertions))]
            preview: None,
        };
        #[cfg(all(feature = "preview", debug_assertions))]
        if let Some(preview) = _flags.preview {
            preview.seed(&mut app);
            app.preview = Some(preview);
        }
        app.navigation.select(app.page);
        // Core owns the CSD/NavHandle; page titles belong in the content pane.
        // The fixed app label uses header_start on both Wayland and X11. Leaving
        // a second native title here duplicates branding on the X11 backend.
        app.set_header_title(String::new());
        app.core.window.context_is_overlay = false;
        let task = app
            .core
            .main_window_id()
            .map(|id| app.set_window_title("Tunnel".into(), id))
            .unwrap_or_else(Task::none);
        (
            app,
            Task::batch([
                task,
                cosmic::task::future(async { Message::Poll }),
                cosmic::task::future(async { Message::Tick }),
                cosmic::task::future(async {
                    Message::Subscription(subscriptions::Action::Restore(false))
                }),
            ]),
        )
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        #[cfg(all(feature = "preview", debug_assertions))]
        if self.preview.is_some() {
            return preview::update(self, message);
        }
        if let Message::Profile(action) = message {
            let task = self.profile_update(action);
            return Task::batch([task, self.persist_sources()]);
        }
        if let Message::Subscription(action) = message {
            let task = self.subscription_update(action);
            return Task::batch([task, self.persist_sources()]);
        }
        if self.operations.busy()
            && !matches!(
                message,
                Message::Loaded(_, _)
                    | Message::Prepared(_)
                    | Message::Controlled(_)
                    | Message::Observed(_, _)
                    | Message::SearchProfiles(_)
                    | Message::ProfilePage(_)
                    | Message::DismissNotice
                    | Message::Navigate(_)
                    | Message::PageScrolled(_, _)
                    | Message::SearchSaved(_)
                    | Message::ShowDetails(_)
                    | Message::CloseDetails
                    | Message::Tick
                    | Message::PackageObserved(_)
                    | Message::UsageObserved(_, _)
                    | Message::RecoveryObserved(_, _)
            )
        {
            return Task::none();
        }
        match message {
            Message::Navigate(page) => {
                self.page = page;
                self.editor = None;
                self.sources.settings = false;
                self.navigation.select(page);
                self.details = None;
                self.core.set_show_context(false);
                // Primary navigation preserves each pane's scroll/search/draft.
                return self.restore_page_scroll();
            }
            Message::PageScrolled(page, offset) => self.navigation.remember_scroll(page, offset),
            Message::SearchSaved(value) => self.saved_search = value.chars().take(128).collect(),
            Message::ShowDetails(profile) => {
                self.sources.settings = false;
                self.details = Some(profile.map_or(Details::Connection, Details::Profile));
                self.core.set_show_context(true);
            }
            Message::CloseDetails => {
                self.details = None;
                self.core.set_show_context(false);
                return self.restore_page_scroll();
            }
            Message::ConnectProfile(id) => {
                let _ = self.connection_update(Message::SavedSelected(id));
                return self.connection_update(Message::Connect);
            }
            Message::AddProfile(index) => {
                if self.download.pending().is_some()
                    || self.operations.uncertain()
                    || !self.catalog.admitted
                    || self.sources.screen == subscriptions::Screen::Add
                {
                    return Task::none();
                }
                // Reject stale/out-of-range rows without adding an older selection.
                if self.catalog.profile(index).is_none() {
                    return Task::none();
                }
                let _ = self.update(Message::Select(index));
                return self.update(Message::Prepare);
            }
            Message::Tick => {
                let package = self
                    .package_update
                    .begin()
                    .map_or_else(Task::none, |running| {
                        cosmic::task::future(async move {
                            Message::PackageObserved(package_update::replaced(running).await)
                        })
                    });
                if self.package_update.changed
                    && !self.package_update.notified
                    && self.notice.is_none()
                    && !self.operations.busy()
                    && self.download.pending().is_none()
                {
                    self.package_update.notified = true;
                    self.status = fl!("package-update-installed");
                    self.notice = Some(Notice::Info);
                }
                let deletion = self.deletion_observed();
                self.ticks = (self.ticks + 1) % 3;
                let usage = self.poll_usage();
                let nm = if self.ticks == 1 {
                    self.connection_update(Message::Poll)
                } else {
                    Task::none()
                };
                let recovery = self.poll_recovery();
                return Task::batch([usage, nm, recovery, deletion, package]);
            }
            Message::PackageObserved(changed) => self.package_update.finish(changed),
            Message::UsageObserved(ticket, result) => {
                if self.reads.finish_usage(ticket) {
                    self.traffic.observe(result);
                }
            }
            Message::RecoveryObserved(ticket, result) => {
                if self.reads.finish_recovery(ticket) {
                    self.recovery.observe(result);
                }
            }
            Message::DismissNotice => {
                self.notice = None;
            }
            Message::SearchProfiles(value) => {
                self.catalog.search(value);
            }
            #[cfg(all(feature = "preview", debug_assertions))]
            Message::Frame(_) | Message::Captured(_) => {}
            Message::Poll
            | Message::Observed(_, _)
            | Message::SavedSelected(_)
            | Message::Connect
            | Message::Disconnect
            | Message::Controlled(_) => {
                return self.connection_update(message);
            }
            Message::Source(value) => {
                if matches!(
                    self.sources.screen,
                    subscriptions::Screen::Nodes | subscriptions::Screen::Review
                ) {
                    return Task::none();
                }
                if !self.download.edit_source(value) {
                    return Task::none();
                }
                self.catalog.invalidate();
                self.notice = None;
                self.status = fl!("source-edited-status");
            }
            Message::FetchComplete(complete) => {
                if matches!(
                    self.sources.screen,
                    subscriptions::Screen::Nodes | subscriptions::Screen::Review
                ) {
                    return Task::none();
                }
                let format = if complete {
                    SubscriptionFormat::Complete
                } else {
                    SubscriptionFormat::NodesOnly
                };
                if !self.download.choose_format(format) {
                    return Task::none();
                }
                self.catalog.invalidate();
                self.status = fl!("reload-format-status");
            }
            Message::DnsChoice(choice) => self.options.dns_choice = choice,
            Message::ManualDns(value) => self.options.manual_dns = value.chars().take(64).collect(),
            Message::LanBypass(value) => {
                if !value
                    || !self
                        .catalog
                        .subscription
                        .as_ref()
                        .is_some_and(|list| list.native_policy_notice().is_some())
                {
                    self.options.lan_bypass = value;
                }
            }
            Message::DnsInterception(value) => {
                self.options.intercept(value);
            }
            Message::FakeIp(value) => {
                self.options.fake_ip(value);
            }
            Message::Load => {
                if matches!(
                    self.sources.screen,
                    subscriptions::Screen::Nodes | subscriptions::Screen::Review
                ) {
                    return Task::none();
                }
                if self.download.pending().is_some() {
                    return Task::none();
                }
                self.catalog.invalidate();
                let Some((ticket, source, format)) = self.download.begin() else {
                    return Task::none();
                };
                return cosmic::task::future(async move {
                    Message::Loaded(ticket, fetch_subscription_format(source, format).await)
                });
            }
            Message::Loaded(ticket, result) => {
                let Some(result) = self.download.finish(ticket, result) else {
                    return Task::none();
                };
                if self.sources.updating() {
                    self.source_downloaded(result);
                    return Task::none();
                }
                let adding = std::mem::take(&mut self.sources.adding);
                match result {
                    Ok(subscription) => {
                        self.catalog.admit(subscription);
                        if adding {
                            return self.subscription_update(subscriptions::Action::Save);
                        }
                        // An ambiguous previous save is not cleared by an unrelated HTTP refresh.
                    }
                    Err(_) => {
                        self.catalog.invalidate();
                    }
                }
            }
            Message::Select(index) => {
                if self.catalog.select(index) {
                    self.notice = None;
                    self.status = fl!("profile-selected-status");
                }
            }
            Message::ProfilePage(page) => {
                if page < self.matching_profiles().len().div_ceil(view::PAGE_SIZE) {
                    self.catalog.page = page;
                    return self.reset_page_scroll();
                }
            }
            Message::Prepare => {
                if self.download.pending().is_some()
                    || self.operations.uncertain()
                    || self.selected_added()
                    || !self.catalog.admitted
                    || self.sources.screen == subscriptions::Screen::Add
                {
                    return Task::none();
                }
                let profile = self.catalog.selected_profile().cloned();
                if let Some(profile) = profile {
                    let profile = match self.profile_with_dns(&profile) {
                        Ok(profile) => profile,
                        Err(error) => {
                            self.notice = Some(Notice::Error);
                            self.status = crate::i18n::dns_error(error);
                            return Task::none();
                        }
                    };
                    // A new explicit action owns feedback; an earlier accepted
                    // control must not overwrite this save's eventual failure.
                    let Some(index) = self.catalog.selected else {
                        return Task::none();
                    };
                    if !self.operations.begin_add(index) {
                        return Task::none();
                    }
                    self.notice = None;
                    self.reads.invalidate();
                    self.status = fl!("saving-profile-status");
                    return cosmic::task::future(async move {
                        Message::Prepared(nm_tunnel_client::save_profile(profile).await)
                    });
                }
            }
            Message::Prepared(result) => {
                let Some(index) = self.operations.finish_add(result.as_ref().err().copied()) else {
                    return Task::none();
                };
                match result {
                    Ok(saved) => {
                        self.notice = Some(Notice::Info);
                        self.catalog.added.insert(index, saved.id().to_owned());
                        if let Some(label) = self
                            .catalog
                            .subscription
                            .as_ref()
                            .and_then(|list| list.entries().get(index))
                            .map(|entry| entry.name().to_owned())
                        {
                            self.sources.added(index, saved.id().to_owned(), label);
                        }
                        self.status = fl!("profile-saved-status");
                        self.saved_selected = Some(saved);
                    }
                    Err(error) => {
                        self.notice = (!self.operations.uncertain()).then_some(Notice::Error);
                        self.status = crate::i18n::client_error(error);
                    }
                }
                let poll = self.connection_update(Message::Poll);
                return Task::batch([poll, self.persist_sources()]);
            }
            Message::Profile(_) | Message::Subscription(_) => {}
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

    fn nav_model(&self) -> Option<&cosmic::widget::nav_bar::Model> {
        Some(&self.navigation.model)
    }

    fn header_start(&self) -> Vec<Element<'_, Message>> {
        // The pinned toolkit's center/title slots are absent in native captures.
        // Keep branding visible in its standard start slot, without custom CSD.
        vec![cosmic::widget::text::heading("Tunnel").into()]
    }

    fn on_nav_select(&mut self, id: cosmic::widget::nav_bar::Id) -> Task<Message> {
        self.navigation
            .page(id)
            .map_or_else(Task::none, |page| self.update(Message::Navigate(page)))
    }

    fn context_drawer(&self) -> Option<cosmic::app::context_drawer::ContextDrawer<'_, Message>> {
        self.details_drawer()
    }

    fn dialog(&self) -> Option<Element<'_, Message>> {
        #[cfg(all(feature = "preview", debug_assertions))]
        if let Some(dialog) = self.preview.as_ref().and_then(|preview| preview.dialog()) {
            return Some(dialog);
        }
        self.delete_dialog().or_else(|| self.source_dialog())
    }

    fn on_escape(&mut self) -> Task<Message> {
        if self.sources.removing {
            return self.subscription_update(subscriptions::Action::CancelRemove);
        }
        if self.sources.settings {
            return self.subscription_update(subscriptions::Action::CloseSettings);
        }
        if matches!(self.deletion, Some(profile_editor::Deletion::Confirm(_))) {
            return self.profile_update(profile_editor::Action::CancelDelete);
        }
        if self.editor.is_some() {
            return self.profile_update(profile_editor::Action::Cancel);
        }
        if self.details.is_some() {
            return self.update(Message::CloseDetails);
        }
        if self.page == Page::Import && self.sources.screen != subscriptions::Screen::List {
            return self.subscription_update(subscriptions::Action::Back);
        }
        if self.core.is_condensed() && self.core.nav_bar_active() {
            self.core.nav_bar_toggle_condensed();
        }
        Task::none()
    }
}

impl App {
    fn synthetic_preview(&self) -> bool {
        #[cfg(all(feature = "preview", debug_assertions))]
        {
            self.preview.is_some()
        }
        #[cfg(not(all(feature = "preview", debug_assertions)))]
        {
            false
        }
    }
    fn restore_page_scroll(&self) -> Task<Message> {
        if self.page == Page::Import {
            return self.restore_source_scroll();
        }
        let offset = self.navigation.scroll(self.page);
        cosmic::iced::widget::scrollable::scroll_to(
            cosmic::widget::Id::new(self.page.scroll_id()),
            cosmic::iced::widget::scrollable::AbsoluteOffset {
                x: Some(offset.x),
                y: Some(offset.y),
            },
        )
    }

    fn reset_page_scroll(&mut self) -> Task<Message> {
        self.navigation
            .remember_scroll(self.page, Default::default());
        cosmic::iced::widget::scrollable::snap_to(
            cosmic::widget::Id::new(self.page.scroll_id()),
            cosmic::iced::widget::scrollable::RelativeOffset {
                x: Some(0.0),
                y: Some(0.0),
            },
        )
    }
    fn selected_added(&self) -> bool {
        self.catalog.selected_added()
    }

    fn reconcile_added<'a>(&mut self, profiles: impl Iterator<Item = &'a str>) {
        self.catalog.reconcile(profiles);
    }
}
