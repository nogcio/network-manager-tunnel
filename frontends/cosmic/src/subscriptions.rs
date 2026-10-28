//! Subscription catalogs and explicit, non-transactional update review.
//! URLs/metadata use the standard Secret Service adapter; downloaded nodes remain
//! memory-only. NetworkManager owns saved profiles, credentials and activation.
use super::{App, Message, Notice, Page, catalog::Catalog, operations::StorageTicket};
use crate::i18n::fl;
use cosmic::{Element, app::Task, iced::Length, theme, widget};
use nm_tunnel_client::{ClientError, SavedProfile};
use nm_tunnel_profile::Profile;
use nm_tunnel_subscription::{Subscription, SubscriptionError, SubscriptionFormat};
use secrecy::{ExposeSecret, SecretString};
use std::{collections::BTreeMap, time::SystemTime};

#[path = "source_persistence.rs"]
mod persistence;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SourceId(u64);

#[derive(Clone)]
pub(crate) enum Action {
    Restore(bool),
    Restored(
        u64,
        Result<
            (
                std::sync::Arc<super::source_store::Store>,
                super::source_store::Catalog,
            ),
            super::source_store::Error,
        >,
    ),
    Persist,
    Persisted(u64, Result<(), super::source_store::Error>),
    Scrolled(
        Option<SourceId>,
        Screen,
        cosmic::iced::widget::scrollable::AbsoluteOffset,
    ),
    Add,
    New,
    Back,
    Open(SourceId),
    Name(String),
    Save,
    Settings,
    CloseSettings,
    Rename(String),
    Url(String),
    SaveSettings,
    AskRemove,
    CancelRemove,
    Remove,
    Update,
    CancelReview,
    Map(String, usize),
    Apply,
    Applied(StorageTicket, String, Result<(), ClientError>),
}

#[cfg(test)]
#[path = "subscriptions_tests.rs"]
mod tests;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Screen {
    #[default]
    List,
    Add,
    Nodes,
    Review,
}

pub(super) struct Link {
    index: Option<usize>,
    label: String,
}
pub(super) struct Source {
    scroll: cosmic::iced::widget::scrollable::AbsoluteOffset,
    id: SourceId,
    pub name: String,
    url: SecretString,
    format: SubscriptionFormat,
    catalog: Catalog,
    links: BTreeMap<String, Link>,
    updated: Option<SystemTime>,
}

struct Mapping {
    target: SavedProfile,
    index: usize,
    candidate: Profile,
}
pub(super) struct Review {
    candidate: Subscription,
    choices: Vec<String>,
    indices: Vec<usize>,
    mappings: BTreeMap<String, Mapping>,
    completed: BTreeMap<String, usize>,
    pending: Option<(StorageTicket, String)>,
    url: SecretString,
    name: Option<String>,
}

#[derive(Default)]
pub(super) struct Sources {
    store: Option<std::sync::Arc<super::source_store::Store>>,
    store_loading: bool,
    store_load_ticket: Option<u64>,
    store_pending: Option<u64>,
    store_next: u64,
    store_error: Option<super::source_store::Error>,
    dirty: bool,
    list_scroll: cosmic::iced::widget::scrollable::AbsoluteOffset,
    pub adding: bool,
    pub screen: Screen,
    records: Vec<Source>,
    active: Option<SourceId>,
    next: u64,
    pub name: String,
    pub settings: bool,
    pub removing: bool,
    updating: bool,
    pub review: Option<Review>,
    settings_url: SecretString,
    pending_name: Option<String>,
}

fn message(action: Action) -> Message {
    Message::Subscription(action)
}

fn complete_step(
    pending: &mut Option<(StorageTicket, String)>,
    completed: &mut BTreeMap<String, usize>,
    ticket: StorageTicket,
    uuid: &str,
    index: usize,
    result: &Result<(), ClientError>,
) -> bool {
    if !pending
        .as_ref()
        .is_some_and(|(expected, target)| *expected == ticket && target == uuid)
        || completed.contains_key(uuid)
    {
        return false;
    }
    *pending = None;
    if result.is_ok() {
        completed.insert(uuid.to_owned(), index);
    }
    true
}

fn equivalent(a: &Profile, b: &Profile) -> bool {
    a.node() == b.node()
        && a.network().dns_override() == b.network().dns_override()
        && a.network().dns_handling() == b.network().dns_handling()
        && a.network().lan_bypass() == b.network().lan_bypass()
        && a.network().tcp_domains().map(|p| p.as_json())
            == b.network().tcp_domains().map(|p| p.as_json())
        && a.network().source().map(|p| p.as_json()) == b.network().source().map(|p| p.as_json())
        && a.credential().expose_uuid() == b.credential().expose_uuid()
}

fn unique_match(profile: &Profile, list: &Subscription) -> Option<usize> {
    let mut matching = list.entries().iter().enumerate().filter_map(|(i, entry)| {
        entry
            .profile()
            .ok()
            .filter(|candidate| equivalent(profile, candidate))
            .map(|_| i)
    });
    let first = matching.next()?;
    matching.next().is_none().then_some(first)
}

impl Sources {
    fn name_error(&self) -> Option<String> {
        (self.name.trim().is_empty()
            || self.name.len() > 128
            || self.name.chars().any(char::is_control))
        .then(|| fl!("error-name"))
    }
    fn active(&self) -> Option<&Source> {
        let id = self.active?;
        self.records.iter().find(|s| s.id == id)
    }
    fn active_mut(&mut self) -> Option<&mut Source> {
        let id = self.active?;
        self.records.iter_mut().find(|s| s.id == id)
    }
    pub fn updating(&self) -> bool {
        self.updating
    }
    pub fn active_name(&self) -> Option<&str> {
        self.active().map(|source| source.name.as_str())
    }
    pub fn source_name(&self, uuid: &str) -> Option<&str> {
        self.records
            .iter()
            .find(|source| source.links.contains_key(uuid))
            .map(|source| source.name.as_str())
    }
    pub fn added(&mut self, index: usize, uuid: String, label: String) {
        if let Some(source) = self.active_mut() {
            source.links.insert(
                uuid,
                Link {
                    index: Some(index),
                    label,
                },
            );
            self.dirty = true;
        }
    }
    pub fn deleted(&mut self, uuid: &str) {
        for source in &mut self.records {
            self.dirty |= source.links.remove(uuid).is_some();
        }
    }
}

impl App {
    #[cfg(all(feature = "preview", debug_assertions))]
    pub(super) fn seed_preview_storage(&mut self, state: &str) {
        self.page = Page::Import;
        self.sources.screen = Screen::List;
        match state {
            "storage-locked" => self.sources.store_error = Some(super::source_store::Error::Locked),
            "storage-failed" => {
                self.sources.store_error = Some(super::source_store::Error::Unavailable)
            }
            "storage-saving" => self.sources.store_pending = Some(1),
            "storage-unknown" => {
                self.sources.store_error = Some(super::source_store::Error::Unknown);
                self.operations.block_uncertain_storage();
            }
            "storage-restored" | "storage-restored-nodes" => {
                self.seed_preview_source();
                if let Some(source) = self.sources.active_mut() {
                    source.updated = None;
                }
                if state == "storage-restored" {
                    self.sources.screen = Screen::List;
                }
            }
            _ => {}
        }
    }
    pub(super) fn can_add_source(&self) -> bool {
        self.sources.records.len() < 128
            && !self.operations.uncertain()
            && !self.sources.store_loading
            && self.sources.store_pending.is_none()
            && self.download.pending().is_none()
            && !self.operations.busy()
    }
    #[cfg(all(feature = "preview", debug_assertions))]
    pub(super) fn seed_preview_source(&mut self) {
        let id = SourceId(1);
        self.sources.records.push(Source {
            scroll: Default::default(),
            id,
            name: "Northern".into(),
            url: "https://subscriptions.example/synthetic-preview".into(),
            format: self.download.format(),
            catalog: Catalog::default(),
            links: BTreeMap::new(),
            updated: Some(SystemTime::now()),
        });
        self.sources.active = Some(id);
        self.sources.next = 1;
        self.sources.screen = Screen::Nodes;
    }
    fn park_source(&mut self) {
        if let Some(source) = self.sources.active_mut() {
            source.catalog = std::mem::take(&mut self.catalog);
        }
    }

    pub(super) fn subscription_update(&mut self, action: Action) -> Task<Message> {
        if self.operations.uncertain()
            && matches!(
                action,
                Action::Add | Action::Save | Action::SaveSettings | Action::Remove | Action::Apply
            )
        {
            return Task::none();
        }
        if matches!(
            action,
            Action::Restore(_) | Action::Restored(..) | Action::Persist | Action::Persisted(..)
        ) {
            return self.source_store_update(action);
        }
        if self.sources.store_pending.is_some()
            && matches!(
                action,
                Action::Add
                    | Action::Save
                    | Action::SaveSettings
                    | Action::Remove
                    | Action::Apply
                    | Action::New
            )
        {
            return Task::none();
        }
        if self.operations.busy()
            && !matches!(
                action,
                Action::Applied(..)
                    | Action::Back
                    | Action::CloseSettings
                    | Action::CancelRemove
                    | Action::Scrolled(..)
            )
        {
            return Task::none();
        }
        match action {
            Action::Scrolled(id, screen, offset) => {
                if screen == Screen::List {
                    self.sources.list_scroll = offset;
                }
                if screen == Screen::Nodes
                    && let Some(source) = self
                        .sources
                        .records
                        .iter_mut()
                        .find(|source| Some(source.id) == id)
                {
                    source.scroll = offset;
                }
            }
            Action::Add
                if self.sources.screen == Screen::Add
                    && self.sources.name_error().is_none()
                    && self.download.pending().is_none() =>
            {
                if nm_tunnel_subscription::validate_url(self.download.source().expose_secret())
                    .is_err()
                {
                    return Task::none();
                }
                self.sources.adding = true;
                return cosmic::Application::update(self, Message::Load);
            }
            Action::New if self.can_add_source() => {
                self.details = None;
                self.sources.settings = false;
                self.core.set_show_context(false);
                self.park_source();
                self.sources.active = None;
                self.sources.name.clear();
                self.sources.screen = Screen::Add;
                self.sources.review = None;
                self.catalog = Catalog::default();
                self.options = Default::default();
                self.download.edit_source(String::new());
                self.download.choose_format(SubscriptionFormat::Complete);
                self.page = Page::Import;
                self.navigation.select(self.page);
                return Task::batch([
                    self.restore_source_scroll(),
                    widget::text_input::focus(widget::Id::new("subscription-name")),
                ]);
            }
            Action::Back => {
                self.sources.adding = false;
                self.details = None;
                self.sources.settings = false;
                self.core.set_show_context(false);
                if self.sources.screen == Screen::Review && !self.operations.busy() {
                    return self.subscription_update(Action::CancelReview);
                } else {
                    self.sources.screen = Screen::List;
                }
                return self.restore_page_scroll();
            }
            Action::Open(id) if self.download.pending().is_none() => {
                self.details = None;
                self.sources.settings = false;
                self.core.set_show_context(false);
                if self.sources.active != Some(id) {
                    if !self.sources.records.iter().any(|source| source.id == id) {
                        return Task::none();
                    }
                    self.park_source();
                    self.sources.active = Some(id);
                    if let Some(source) = self.sources.active_mut() {
                        self.catalog = std::mem::take(&mut source.catalog);
                        self.download
                            .edit_source(source.url.expose_secret().to_owned());
                        self.download.choose_format(source.format);
                    }
                    self.sources.review = None;
                }
                self.sources.screen = if self.sources.review.is_some() {
                    Screen::Review
                } else {
                    Screen::Nodes
                };
                if let Some(snapshot) = &self.snapshot {
                    self.catalog
                        .reconcile(snapshot.profiles.iter().map(|p| p.id()));
                }
                return self.restore_source_scroll();
            }
            Action::Name(value) => self.sources.name = value.chars().take(256).collect(),
            Action::Save
                if self.sources.screen == Screen::Add
                    && self.download.pending().is_none()
                    && self.catalog.admitted =>
            {
                if self.sources.name_error().is_some() || self.sources.records.len() >= 128 {
                    return Task::none();
                }
                let Some(next) = self.sources.next.checked_add(1) else {
                    return Task::none();
                };
                self.sources.next = next;
                let id = SourceId(next);
                self.sources.records.push(Source {
                    scroll: Default::default(),
                    id,
                    name: self.sources.name.trim().into(),
                    url: self.download.source().clone(),
                    format: self.download.format(),
                    catalog: Catalog::default(),
                    links: BTreeMap::new(),
                    updated: Some(SystemTime::now()),
                });
                self.sources.active = Some(id);
                self.sources.dirty = true;
                self.sources.screen = Screen::Nodes;
                self.notice = Some(Notice::Info);
                self.status = fl!("subscription-added-status");
                return self.restore_source_scroll();
            }
            Action::Settings if self.sources.active().is_some() => {
                self.sources.settings = true;
                self.sources.name = self.sources.active_name().unwrap_or_default().into();
                if let Some(source) = self.sources.active() {
                    self.sources.settings_url = source.url.clone();
                }
                self.details = None;
                self.core.set_show_context(true);
            }
            Action::CloseSettings => {
                self.sources.settings = false;
                self.core.set_show_context(false);
            }
            Action::Rename(value) => self.sources.name = value.chars().take(256).collect(),
            Action::Url(value) => self.sources.settings_url = value.into(),
            Action::SaveSettings => {
                if self.sources.name_error().is_some() {
                    return Task::none();
                }
                let name = self.sources.name.trim().to_owned();
                if nm_tunnel_subscription::validate_url(self.sources.settings_url.expose_secret())
                    .is_err()
                    || self.download.pending().is_some()
                {
                    return Task::none();
                }
                if self.sources.active().is_some_and(|source| {
                    source.url.expose_secret() != self.sources.settings_url.expose_secret()
                }) {
                    self.download
                        .edit_source(self.sources.settings_url.expose_secret().to_owned());
                    let Some((ticket, source, format)) = self.download.begin() else {
                        return Task::none();
                    };
                    self.sources.pending_name = Some(name);
                    self.sources.updating = true;
                    self.sources.settings = false;
                    self.core.set_show_context(false);
                    return cosmic::task::future(async move {
                        Message::Loaded(
                            ticket,
                            nm_tunnel_subscription::fetch_subscription_format(source, format).await,
                        )
                    });
                }
                if let Some(source) = self.sources.active_mut() {
                    source.name = name;
                }
                self.sources.dirty = true;
                self.sources.settings = false;
                self.core.set_show_context(false);
                self.notice = Some(Notice::Info);
                self.status = fl!("subscription-renamed-status");
            }
            Action::AskRemove
                if self.sources.active().is_some() && self.download.pending().is_none() =>
            {
                self.sources.removing = true
            }
            Action::CancelRemove => self.sources.removing = false,
            Action::Remove if self.sources.removing && self.download.pending().is_none() => {
                self.sources.dirty = true;
                if let Some(id) = self.sources.active.take() {
                    self.sources.records.retain(|source| source.id != id);
                }
                self.sources.removing = false;
                self.sources.settings = false;
                self.sources.review = None;
                self.sources.screen = Screen::List;
                self.catalog = Catalog::default();
                self.download.edit_source(String::new());
                self.sources.settings_url = String::new().into();
                self.core.set_show_context(false);
                self.notice = Some(Notice::Info);
                self.status = fl!("subscription-removed-status");
            }
            Action::Update
                if self.sources.active().is_some()
                    && self.sources.review.is_none()
                    && self.download.pending().is_none() =>
            {
                let Some((ticket, source, format)) = self.download.begin() else {
                    return Task::none();
                };
                self.sources.updating = true;
                return cosmic::task::future(async move {
                    Message::Loaded(
                        ticket,
                        nm_tunnel_subscription::fetch_subscription_format(source, format).await,
                    )
                });
            }
            Action::CancelReview if !self.operations.busy() => {
                if let Some(source) = self.sources.active() {
                    self.download
                        .edit_source(source.url.expose_secret().to_owned());
                }
                let completed = self
                    .sources
                    .review
                    .as_ref()
                    .map_or(0, |review| review.completed.len());
                if completed != 0 {
                    self.notice = Some(Notice::Info);
                    self.status = fl!("review-closed-status", count = completed);
                }
                self.sources.review = None;
                self.sources.screen = Screen::Nodes;
                return self.restore_source_scroll();
            }
            Action::Map(uuid, choice) if !self.operations.uncertain() => {
                let Some(source) = self.sources.active() else {
                    return Task::none();
                };
                if !source.links.contains_key(&uuid) {
                    return Task::none();
                }
                let target = self
                    .snapshot
                    .as_ref()
                    .filter(|_| self.nm_error.is_none())
                    .and_then(|s| {
                        s.profiles
                            .iter()
                            .find(|p| p.id() == uuid && p.checked_update_available())
                    })
                    .cloned();
                let Some(review) = &mut self.sources.review else {
                    return Task::none();
                };
                if review.completed.contains_key(&uuid) {
                    return Task::none();
                }
                review.mappings.remove(&uuid);
                if choice != 0
                    && let Some(target) = target
                    && let Some(index) = review.indices.get(choice - 1).copied()
                    && let Some(candidate) = review
                        .candidate
                        .entries()
                        .get(index)
                        .and_then(|e| e.profile().ok())
                        .cloned()
                {
                    review.mappings.insert(
                        uuid,
                        Mapping {
                            target,
                            index,
                            candidate,
                        },
                    );
                }
            }
            Action::Apply if !self.operations.uncertain() && self.sources.review.is_some() => {
                if self
                    .sources
                    .review
                    .as_ref()
                    .is_some_and(|r| r.mappings.is_empty())
                {
                    self.adopt_source_update();
                    return Task::none();
                }
                let Some(ticket) = self.operations.begin_storage() else {
                    return Task::none();
                };
                self.reads.invalidate();
                self.notice = None;
                return self.dispatch_source_update(ticket);
            }
            Action::Applied(ticket, response_uuid, result) => {
                let Some(review) = &mut self.sources.review else {
                    return Task::none();
                };
                let Some((pending, uuid)) = review.pending.clone() else {
                    return Task::none();
                };
                if pending != ticket
                    || response_uuid != uuid
                    || !review.mappings.contains_key(&uuid)
                {
                    return Task::none();
                }
                let Some(index) = review.mappings.get(&uuid).map(|mapping| mapping.index) else {
                    return Task::none();
                };
                if !complete_step(
                    &mut review.pending,
                    &mut review.completed,
                    ticket,
                    &response_uuid,
                    index,
                    &result,
                ) {
                    return Task::none();
                }
                if let Err(error) = result {
                    let count = review.completed.len();
                    self.operations.finish_storage(ticket, Some(error));
                    self.notice = (!self.operations.uncertain()).then_some(Notice::Error);
                    self.status = fl!(
                        "partial-update-status",
                        count = count,
                        error = crate::i18n::client_error(error)
                    );
                    self.snapshot = None;
                    return self.connection_update(Message::Poll);
                }
                if let Some(mapping) = review.mappings.remove(&uuid) {
                    let label = mapping.candidate.name().to_owned();
                    if let Some(source) = self.sources.active_mut() {
                        source.links.insert(uuid, Link { index: None, label });
                    }
                }
                return self.dispatch_source_update(ticket);
            }
            _ => {}
        }
        Task::none()
    }

    fn dispatch_source_update(&mut self, ticket: StorageTicket) -> Task<Message> {
        let mapping = self
            .sources
            .review
            .as_ref()
            .and_then(|review| review.mappings.iter().next())
            .map(|(uuid, mapping)| {
                (
                    uuid.clone(),
                    mapping.target.clone(),
                    mapping.candidate.clone(),
                )
            });
        let Some((uuid, target, candidate)) = mapping else {
            self.operations.finish_storage(ticket, None);
            self.adopt_source_update();
            self.snapshot = None;
            return self.connection_update(Message::Poll);
        };
        if let Some(review) = &mut self.sources.review {
            review.pending = Some((ticket, uuid.clone()));
        }
        self.status = fl!("applying-update-status");
        cosmic::task::future(async move {
            message(Action::Applied(
                ticket,
                uuid,
                nm_tunnel_client::update_from_source(&target, candidate).await,
            ))
        })
    }

    pub(super) fn source_downloaded(&mut self, result: Result<Subscription, SubscriptionError>) {
        self.sources.updating = false;
        match result {
            Ok(candidate) => {
                let indices: Vec<_> = candidate
                    .entries()
                    .iter()
                    .enumerate()
                    .filter_map(|(i, entry)| entry.profile().ok().map(|_| i))
                    .collect();
                let choices = std::iter::once(fl!("keep-current-profile"))
                    .chain(indices.iter().map(|index| {
                        fl!(
                            "source-server-choice",
                            name = candidate.entries()[*index].name(),
                            index = index + 1
                        )
                    }))
                    .collect();
                self.sources.review = Some(Review {
                    candidate,
                    choices,
                    indices,
                    mappings: BTreeMap::new(),
                    completed: BTreeMap::new(),
                    pending: None,
                    url: self.download.source().clone(),
                    name: self.sources.pending_name.take(),
                });
                if self.sources.screen != Screen::List {
                    self.sources.screen = Screen::Review;
                }
            }
            Err(error) => {
                self.sources.pending_name = None;
                if let Some(source) = self.sources.active() {
                    self.download
                        .edit_source(source.url.expose_secret().to_owned());
                }
                self.notice = Some(Notice::Error);
                self.status = fl!(
                    "update-failed-status",
                    error = crate::i18n::subscription_error(error)
                );
            }
        }
    }

    fn adopt_source_update(&mut self) {
        let Some(review) = self.sources.review.take() else {
            return;
        };
        self.sources.dirty = true;
        if let Some(source) = self.sources.active_mut() {
            source.url = review.url;
            if let Some(name) = review.name {
                source.name = name;
            }
            for (uuid, link) in &mut source.links {
                link.index = review.completed.get(uuid).copied().or_else(|| {
                    link.index
                        .and_then(|index| {
                            self.catalog
                                .subscription
                                .as_ref()?
                                .entries()
                                .get(index)?
                                .profile()
                                .ok()
                        })
                        .and_then(|old| unique_match(old, &review.candidate))
                });
            }
            source.updated = Some(SystemTime::now());
        }
        self.catalog.admit(review.candidate);
        if let Some(source) = self.sources.active() {
            for (uuid, link) in &source.links {
                if let Some(index) = link.index {
                    self.catalog.added.insert(index, uuid.clone());
                }
            }
        }
        if self.sources.screen == Screen::Review {
            self.sources.screen = Screen::Nodes;
        }
        self.notice = Some(Notice::Info);
        self.status = fl!("subscription-updated-status");
    }

    pub(super) fn source_dialog(&self) -> Option<Element<'_, Message>> {
        if !self.sources.removing {
            return None;
        }
        Some(
            widget::dialog()
                .title(fl!("remove-subscription-confirm"))
                .body(fl!("remove-subscription-body"))
                .primary_action(
                    widget::button::destructive(fl!("remove-subscription-action"))
                        .on_press(message(Action::Remove)),
                )
                .secondary_action(
                    widget::button::standard(fl!("cancel")).on_press(message(Action::CancelRemove)),
                )
                .into(),
        )
    }

    pub(super) fn source_settings(&self) -> Option<Element<'_, Message>> {
        if !self.sources.settings {
            return None;
        }
        let source = self.sources.active()?;
        Some(
            widget::column::with_capacity(4)
                .spacing(theme::spacing().space_m)
                .push(
                    widget::text_input(fl!("subscription-name"), &self.sources.name)
                        .label(fl!("name"))
                        .on_input(|value| message(Action::Rename(value))),
                )
                .push(
                    widget::text_input(
                        fl!("https-subscription-url"),
                        self.sources.settings_url.expose_secret(),
                    )
                    .label(fl!("subscription-url"))
                    .on_input(|value| message(Action::Url(value))),
                )
                .push(widget::text::caption(self.source_storage_caption()))
                .push(widget::text::caption(fl!("changed-url-review")))
                .push_maybe(
                    nm_tunnel_subscription::validate_url(self.sources.settings_url.expose_secret())
                        .err()
                        .map(|error| widget::text::caption(crate::i18n::subscription_error(error))),
                )
                .push_maybe(self.sources.name_error().map(widget::text::caption))
                .push(
                    widget::button::destructive(fl!("remove-subscription"))
                        .description(fl!("remove-source", name = source.name.clone()))
                        .on_press_maybe(
                            (!self.operations.uncertain()
                                && !self.operations.busy()
                                && self.sources.store_pending.is_none())
                            .then_some(message(Action::AskRemove)),
                        ),
                )
                .into(),
        )
    }

    pub(super) fn subscriptions_page(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let mut content = widget::column::with_capacity(6).spacing(spacing.space_m);
        if self.sources.settings && self.core.is_condensed() {
            return content
                .push(widget::button::text(fl!("back")).on_press(message(Action::CloseSettings)))
                .push(widget::text::title2(fl!("subscription-settings")))
                .push(
                    self.source_settings().unwrap_or_else(|| {
                        widget::text::body(fl!("subscription-unavailable")).into()
                    }),
                )
                .into();
        }
        match self.sources.screen {
            Screen::List => {
                content = content.push_maybe(self.source_storage_view());
                let mut list = widget::list::list_column();
                for source in &self.sources.records {
                    let count = if self.sources.active == Some(source.id) {
                        self.catalog
                            .subscription
                            .as_ref()
                            .map(|s| s.entries().len())
                    } else {
                        source
                            .catalog
                            .subscription
                            .as_ref()
                            .map(|s| s.entries().len())
                    };
                    let count_text = count.map_or_else(
                        || fl!("servers-not-loaded"),
                        |count| fl!("server-count", count = count),
                    );
                    let age = source.updated.and_then(|t| t.elapsed().ok()).map_or_else(
                        || fl!("not-updated"),
                        |age| {
                            if age.as_secs() < 60 {
                                fl!("updated-just-now")
                            } else {
                                fl!("updated-minutes", count = age.as_secs() / 60)
                            }
                        },
                    );
                    list = list.add(
                        widget::list::button(
                            widget::row::with_capacity(2)
                                .push(
                                    widget::column::with_capacity(2)
                                        .width(Length::Fill)
                                        .push(widget::text::body(&source.name).wrapping(
                                            cosmic::iced::core::text::Wrapping::WordOrGlyph,
                                        ))
                                        .push(widget::text::caption(fl!(
                                            "source-summary",
                                            count = count_text,
                                            age = age
                                        ))),
                                )
                                .push(widget::icon::from_name("go-next-symbolic").icon()),
                        )
                        .on_press_maybe(
                            (self.download.pending().is_none() && !self.operations.busy())
                                .then_some(message(Action::Open(source.id))),
                        ),
                    );
                }
                if self.sources.records.is_empty() {
                    content = content.push(widget::text::body(fl!("no-subscriptions")));
                }
                content = content
                    .push(list)
                    .push(widget::text::caption(self.source_storage_caption()));
            }
            Screen::Add => {
                content = content
                    .push(
                        widget::button::text(fl!("back"))
                            .leading_icon(widget::icon::from_name("go-previous-symbolic"))
                            .on_press(message(Action::Back)),
                    )
                    .push(widget::text::title2(fl!("add-subscription")))
                    .push(
                        widget::text_input(fl!("subscription-name"), &self.sources.name)
                            .label(fl!("name"))
                            .id(widget::Id::new("subscription-name"))
                            .on_input(|value| message(Action::Name(value))),
                    )
                    .push_maybe(
                        (!self.sources.name.is_empty())
                            .then(|| self.sources.name_error())
                            .flatten()
                            .map(widget::text::caption),
                    )
                    .push(self.import_page());
            }
            Screen::Nodes => {
                content = content
                    .push(
                        widget::button::text(fl!("back"))
                            .leading_icon(widget::icon::from_name("go-previous-symbolic"))
                            .on_press(message(Action::Back)),
                    )
                    .push(widget::text::title2(
                        self.sources
                            .active_name()
                            .map_or_else(|| fl!("subscription"), str::to_owned),
                    ))
                    .push(
                        widget::settings::section()
                            .title(fl!("subscription"))
                            .add(widget::settings::item(
                                fl!("servers"),
                                widget::text::body(self.catalog.subscription.as_ref().map_or_else(
                                    || fl!("not-loaded"),
                                    |list| list.entries().len().to_string(),
                                )),
                            ))
                            .add(widget::settings::item(
                                fl!("import-mode"),
                                widget::text::body(
                                    if self.download.format() == SubscriptionFormat::Complete {
                                        fl!("complete-ipv4")
                                    } else {
                                        fl!("node-only")
                                    },
                                ),
                            )),
                    )
                    .push(self.source_controls())
                    .push(self.import_page());
                if let Some(source) = self.sources.active() {
                    for link in source.links.values().filter(|link| link.index.is_none()) {
                        content = content.push(widget::text::body(fl!(
                            "unmatched-profile-kept",
                            name = link.label.clone()
                        )));
                    }
                }
            }
            Screen::Review => {
                let Some(review) = &self.sources.review else {
                    return content.into();
                };
                content = content
                    .push(
                        widget::button::text(fl!("back"))
                            .leading_icon(widget::icon::from_name("go-previous-symbolic"))
                            .on_press_maybe(
                                (!self.operations.busy()).then_some(message(Action::CancelReview)),
                            ),
                    )
                    .push(widget::text::title2(fl!("review-subscription-update")))
                    .push(widget::text::body(fl!("source-identity-disclosure")));
                let mut changes = widget::settings::section().title(fl!("source-changes"));
                if let Some(old) = &self.catalog.subscription {
                    for entry in review.candidate.entries() {
                        if let Ok(profile) = entry.profile()
                            && unique_match(profile, old).is_none()
                        {
                            changes = changes.add(widget::settings::item(
                                entry.name(),
                                widget::text::caption(fl!("new-unmatched-server")),
                            ));
                        }
                    }
                    for entry in old.entries() {
                        if let Ok(profile) = entry.profile()
                            && unique_match(profile, &review.candidate).is_none()
                        {
                            changes = changes.add(widget::settings::item(
                                entry.name(),
                                widget::text::caption(fl!("no-longer-matched")),
                            ));
                        }
                    }
                }
                content = content.push(changes);
                if let Some(source) = self.sources.active() {
                    for uuid in source.links.keys() {
                        let saved = self
                            .snapshot
                            .as_ref()
                            .and_then(|s| s.profiles.iter().find(|p| p.id() == uuid));
                        let Some(saved) = saved else {
                            continue;
                        };
                        let selected = review
                            .mappings
                            .get(uuid)
                            .and_then(|mapping| {
                                review
                                    .indices
                                    .iter()
                                    .position(|index| *index == mapping.index)
                            })
                            .map_or(0, |position| position + 1);
                        let row = widget::column::with_capacity(2)
                            .push(widget::text::heading(saved.name()));
                        content = content.push(if review.completed.contains_key(uuid) {
                            row.push(widget::text::caption(fl!("update-confirmed")))
                        } else {
                            row.push(widget::dropdown(&review.choices, Some(selected), {
                                let uuid = uuid.clone();
                                move |choice| message(Action::Map(uuid.clone(), choice))
                            }))
                        });
                    }
                }
                content = content.push(widget::text::body(fl!("apply-update-disclosure")));
            }
        }
        content.into()
    }

    pub(super) fn source_review_footer(&self) -> Option<Element<'_, Message>> {
        if self.page != Page::Import || self.details.is_some() {
            return None;
        }
        if self.sources.settings {
            return self
                .core
                .is_condensed()
                .then(|| self.source_settings_footer());
        }
        let (cancel, action, label, enabled) = match self.sources.screen {
            Screen::Add => (
                Action::Back,
                Action::Add,
                fl!("add-subscription"),
                self.sources.name_error().is_none()
                    && nm_tunnel_subscription::validate_url(self.download.source().expose_secret())
                        .is_ok()
                    && self.download.pending().is_none(),
            ),
            Screen::Review => (
                Action::CancelReview,
                Action::Apply,
                fl!("apply-update"),
                !self.operations.uncertain(),
            ),
            _ => return None,
        };
        Some(
            widget::row::with_capacity(3)
                .spacing(theme::spacing().space_s)
                .push(widget::space::horizontal())
                .push(
                    widget::button::text(fl!("cancel"))
                        .on_press_maybe((!self.operations.busy()).then_some(message(cancel))),
                )
                .push(
                    widget::button::suggested(label).on_press_maybe(
                        (!self.operations.busy() && !self.operations.uncertain() && enabled)
                            .then_some(message(action)),
                    ),
                )
                .into(),
        )
    }

    fn source_controls(&self) -> Element<'_, Message> {
        let settings = widget::button::standard(fl!("subscription-settings"))
            .on_press(message(Action::Settings));
        let update = widget::button::suggested(fl!("update-subscription")).on_press_maybe(
            (self.download.pending().is_none()
                && self.sources.review.is_none()
                && !self.operations.busy())
            .then_some(message(Action::Update)),
        );
        if self.core.window.show_context || self.core.is_condensed() {
            widget::column::with_capacity(2)
                .spacing(theme::spacing().space_s)
                .push(settings)
                .push(update)
                .into()
        } else {
            widget::row::with_capacity(3)
                .spacing(theme::spacing().space_s)
                .push(widget::space::horizontal())
                .push(settings)
                .push(update)
                .into()
        }
    }

    pub(super) fn source_settings_footer(&self) -> Element<'_, Message> {
        widget::row::with_capacity(3)
            .spacing(theme::spacing().space_s)
            .push(widget::space::horizontal())
            .push(widget::button::text(fl!("cancel")).on_press(message(Action::CloseSettings)))
            .push(
                widget::button::suggested(fl!("save-subscription")).on_press_maybe(
                    (!self.operations.busy()
                        && !self.operations.uncertain()
                        && self.sources.name_error().is_none()
                        && nm_tunnel_subscription::validate_url(
                            self.sources.settings_url.expose_secret(),
                        )
                        .is_ok()
                        && self.download.pending().is_none())
                    .then_some(message(Action::SaveSettings)),
                ),
            )
            .into()
    }

    pub(super) fn source_viewport(&self) -> (Option<SourceId>, Screen) {
        (self.sources.active, self.sources.screen)
    }

    pub(super) fn restore_source_scroll(&self) -> Task<Message> {
        let offset = match self.sources.screen {
            Screen::List => self.sources.list_scroll,
            Screen::Nodes => self
                .sources
                .active()
                .map(|source| source.scroll)
                .unwrap_or_default(),
            _ => Default::default(),
        };
        cosmic::iced::widget::scrollable::scroll_to(
            widget::Id::new("import-page"),
            cosmic::iced::widget::scrollable::AbsoluteOffset {
                x: Some(offset.x),
                y: Some(offset.y),
            },
        )
    }
}
