//! Draft-only editing and disconnect-before-delete. No firewall or secret authority.
use super::{
    App, Details, DnsChoice, Message, Notice, operations::StorageTicket, options::ProfileOptions,
};
use crate::i18n::fl;
use cosmic::{Element, app::Task, iced::Length, theme, widget};
use nm_tunnel_client::{ClientError, LanBypass, ProfileChanges, SavedProfile};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub(crate) enum Action {
    Edit(String),
    Name(String),
    Dns(DnsChoice),
    Manual(String),
    Lan(LanBypass),
    Intercept(bool),
    FakeIp(bool),
    Cancel,
    Save,
    Saved(StorageTicket, Result<(), ClientError>),
    AskDelete(String),
    CancelDelete,
    ConfirmDelete,
    Disconnected(StorageTicket, Result<(), ClientError>),
    Deleted(StorageTicket, Result<(), ClientError>),
}

pub(super) struct Editor {
    target: Option<SavedProfile>,
    required: bool,
    name: String,
    options: ProfileOptions,
    lan: LanBypass,
    pub return_page: super::Page,
    return_details: Option<Details>,
}

pub(super) enum Deletion {
    Confirm(SavedProfile),
    Disconnecting(SavedProfile, StorageTicket),
    Waiting(SavedProfile, StorageTicket, Instant),
    Deleting(SavedProfile, StorageTicket),
}

impl Editor {
    #[cfg(all(feature = "preview", debug_assertions))]
    pub(super) fn preview(invalid_dns: bool) -> Self {
        Self {
            target: None,
            required: false,
            name: "North · TCP".into(),
            options: ProfileOptions {
                dns_choice: DnsChoice::Manual,
                manual_dns: if invalid_dns {
                    "192.168.1.1"
                } else {
                    "8.8.8.8"
                }
                .into(),
                dns_interception: true,
                fake_ip: true,
                ..Default::default()
            },
            lan: LanBypass::None,
            return_page: super::Page::Connections,
            return_details: Some(Details::Profile("preview-a".into())),
        }
    }
    fn new(
        target: SavedProfile,
        return_page: super::Page,
        return_details: Option<Details>,
    ) -> Self {
        let (dns_choice, manual_dns) = match target.dns_override() {
            nm_tunnel_profile::DnsOverride::Inherit => (DnsChoice::Inherit, String::new()),
            nm_tunnel_profile::DnsOverride::CurrentNetwork => {
                (DnsChoice::CurrentNetwork, String::new())
            }
            nm_tunnel_profile::DnsOverride::ProxyIpv4(ip) => (DnsChoice::Manual, ip.to_string()),
        };
        Self {
            name: target.name().into(),
            lan: if target.private_lan_bypass() {
                LanBypass::Private
            } else if target.lan_bypass() {
                LanBypass::Connected
            } else {
                LanBypass::None
            },
            options: ProfileOptions {
                dns_choice,
                manual_dns,
                dns_interception: target.dns_interception(),
                fake_ip: target.fake_ip(),
                ..Default::default()
            },
            required: target.native_source_policy(),
            target: Some(target),
            return_page,
            return_details,
        }
    }

    fn changes(&self) -> Result<ProfileChanges, String> {
        checked_changes(&self.name, &self.options, self.lan, self.required)
    }
}

fn checked_changes(
    name: &str,
    options: &ProfileOptions,
    lan: LanBypass,
    source_policy: bool,
) -> Result<ProfileChanges, String> {
    if name.trim().is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        return Err(fl!("error-name"));
    }
    let dns = options
        .dns_override()
        .map_err(|_| fl!("error-public-dns"))?;
    if options.fake_ip && !options.dns_interception {
        return Err(fl!("error-fakeip-intercept"));
    }
    if source_policy && (!options.dns_interception || !options.fake_ip) {
        return Err(fl!("error-required-policy"));
    }
    if source_policy && lan != LanBypass::None {
        return Err(fl!("error-separate-lan"));
    }
    Ok(ProfileChanges {
        name: name.to_owned(),
        dns,
        lan,
        intercept: options.dns_interception,
        fake_ip: options.fake_ip,
    })
}

/// Missing observation never authorizes deletion. Clocks are supplied by the owner.
fn disconnected_for_delete(
    now: Instant,
    deadline: Instant,
    unchanged: Option<bool>,
    active: bool,
) -> Result<bool, String> {
    if now >= deadline {
        return Err(fl!("delete-disconnection-timeout"));
    }
    match unchanged {
        None => Ok(false),
        Some(false) => Err(fl!("delete-profile-changed")),
        Some(true) => Ok(!active),
    }
}

fn message(action: Action) -> Message {
    Message::Profile(action)
}

impl App {
    fn editable_target(&self, id: &str) -> Option<SavedProfile> {
        if self.nm_error.is_some() || self.operations.uncertain() {
            return None;
        }
        self.snapshot
            .as_ref()?
            .profiles
            .iter()
            .find(|p| p.id() == id && p.checked_update_available())
            .cloned()
    }

    pub(super) fn waiting_for_delete(&self) -> bool {
        matches!(self.deletion, Some(Deletion::Waiting(..)))
    }

    pub(super) fn profile_update(&mut self, action: Action) -> Task<Message> {
        match action {
            Action::Edit(id) if !self.operations.busy() => {
                if let Some(target) = self.editable_target(&id) {
                    self.editor = Some(Editor::new(target, self.page, self.details.clone()));
                    self.details = None;
                    self.core.set_show_context(false);
                    return widget::text_input::focus(widget::Id::new("profile-name"));
                }
            }
            Action::Cancel => {
                // Closing a draft is always possible; it never cancels dispatched NM work.
                if let Some(editor) = self.editor.take() {
                    self.page = editor.return_page;
                    self.navigation.select(self.page);
                    self.details = editor.return_details;
                    self.core.set_show_context(self.details.is_some());
                }
                return self.restore_page_scroll();
            }
            Action::Saved(ticket, result) => {
                if self.profile_save != Some(ticket) {
                    return Task::none();
                }
                if !self
                    .operations
                    .finish_storage(ticket, result.as_ref().err().copied())
                {
                    return Task::none();
                }
                self.profile_save = None;
                self.notice = (!self.operations.uncertain()).then_some(if result.is_ok() {
                    Notice::Info
                } else {
                    Notice::Error
                });
                self.status = match result {
                    Ok(()) => {
                        if let Some(editor) = self.editor.take() {
                            self.details = editor.return_details;
                            self.core.set_show_context(self.details.is_some());
                        }
                        fl!("profile-settings-saved-status")
                    }
                    Err(error) => crate::i18n::client_error(error),
                };
                self.snapshot = None;
                return self.connection_update(Message::Poll);
            }
            Action::Save if !self.operations.busy() && !self.operations.uncertain() => {
                let Some(editor) = &self.editor else {
                    return Task::none();
                };
                let Ok(changes) = editor.changes() else {
                    return Task::none();
                };
                let Some(target) = editor.target.clone() else {
                    return Task::none();
                };
                if self.editable_target(target.id()).as_ref() != Some(&target) {
                    self.notice = Some(Notice::Error);
                    self.status = fl!("profile-changed-before-save");
                    return Task::none();
                }
                let Some(ticket) = self.operations.begin_storage() else {
                    return Task::none();
                };
                self.profile_save = Some(ticket);
                self.reads.invalidate();
                self.notice = None;
                self.status = fl!("saving-settings-status");
                return cosmic::task::future(async move {
                    message(Action::Saved(
                        ticket,
                        nm_tunnel_client::edit_profile(&target, changes).await,
                    ))
                });
            }
            Action::AskDelete(id) if !self.operations.busy() => {
                if let Some(target) = self.editable_target(&id) {
                    self.deletion = Some(Deletion::Confirm(target));
                }
            }
            Action::CancelDelete => {
                if matches!(self.deletion, Some(Deletion::Confirm(_))) {
                    self.deletion = None;
                }
            }
            Action::ConfirmDelete if !self.operations.busy() && !self.operations.uncertain() => {
                let Some(Deletion::Confirm(target)) = &self.deletion else {
                    return Task::none();
                };
                let target = target.clone();
                if self.editable_target(target.id()).as_ref() != Some(&target) {
                    self.deletion = None;
                    self.notice = Some(Notice::Error);
                    self.status = fl!("profile-changed-before-delete");
                    return Task::none();
                }
                let active = self
                    .snapshot
                    .as_ref()
                    .and_then(|s| s.active.iter().find(|a| a.profile().id() == target.id()))
                    .cloned();
                let Some(ticket) = self.operations.begin_storage() else {
                    return Task::none();
                };
                self.reads.invalidate();
                self.notice = None;
                if let Some(active) = active {
                    self.status = fl!("disconnecting-before-delete");
                    self.deletion = Some(Deletion::Disconnecting(target, ticket));
                    return cosmic::task::future(async move {
                        message(Action::Disconnected(
                            ticket,
                            nm_tunnel_client::deactivate(&active).await,
                        ))
                    });
                }
                return self.dispatch_delete(target, ticket);
            }
            Action::Disconnected(ticket, result) => {
                let Some(Deletion::Disconnecting(target, pending)) = &self.deletion else {
                    return Task::none();
                };
                if *pending != ticket {
                    return Task::none();
                }
                let target = target.clone();
                if let Err(error) = result {
                    self.operations.finish_storage(ticket, None);
                    self.deletion = None;
                    self.notice = Some(Notice::Error);
                    self.status = fl!(
                        "delete-not-requested-status",
                        error = crate::i18n::client_error(error)
                    );
                } else {
                    self.deletion = Some(Deletion::Waiting(
                        target,
                        ticket,
                        Instant::now() + Duration::from_secs(45),
                    ));
                    self.status = fl!("waiting-disconnection-status");
                }
                self.snapshot = None;
                return self.connection_update(Message::Poll);
            }
            Action::Deleted(ticket, result) => {
                let Some(Deletion::Deleting(target, pending)) = &self.deletion else {
                    return Task::none();
                };
                if *pending != ticket {
                    return Task::none();
                }
                let id = target.id().to_owned();
                if !self
                    .operations
                    .finish_storage(ticket, result.as_ref().err().copied())
                {
                    return Task::none();
                }
                self.deletion = None;
                self.notice = (!self.operations.uncertain()).then_some(if result.is_ok() {
                    Notice::Info
                } else {
                    Notice::Error
                });
                self.status = match result {
                    Ok(()) => {
                        self.sources.deleted(&id);
                        if matches!(&self.details, Some(Details::Profile(profile)) if profile == &id)
                        {
                            self.details = None;
                            self.core.set_show_context(false);
                        }
                        fl!("profile-deleted-status")
                    }
                    Err(error) => crate::i18n::client_error(error),
                };
                self.snapshot = None;
                return self.connection_update(Message::Poll);
            }
            action if !self.operations.busy() => {
                if let Some(editor) = &mut self.editor {
                    let required = editor.required;
                    match action {
                        Action::Name(value) => editor.name = value.chars().take(256).collect(),
                        Action::Dns(choice) => editor.options.dns_choice = choice,
                        Action::Manual(value) => {
                            editor.options.manual_dns = value.chars().take(64).collect()
                        }
                        Action::Lan(value) => editor.lan = value,
                        Action::Intercept(value) if !required => editor.options.intercept(value),
                        Action::FakeIp(value) if !required => editor.options.fake_ip(value),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        Task::none()
    }

    fn dispatch_delete(&mut self, target: SavedProfile, ticket: StorageTicket) -> Task<Message> {
        self.deletion = Some(Deletion::Deleting(target.clone(), ticket));
        self.status = fl!("deleting-profile-status");
        cosmic::task::future(async move {
            message(Action::Deleted(
                ticket,
                nm_tunnel_client::delete_profile(&target).await,
            ))
        })
    }

    /// Called only after a valid, post-disconnect observation; errors never authorize Delete.
    pub(super) fn deletion_observed(&mut self) -> Task<Message> {
        let Some(Deletion::Waiting(target, ticket, deadline)) = &self.deletion else {
            return Task::none();
        };
        let (target, ticket, deadline) = (target.clone(), *ticket, *deadline);
        let unchanged = self.snapshot.as_ref().map(|snapshot| {
            snapshot
                .profiles
                .iter()
                .find(|profile| profile.id() == target.id())
                == Some(&target)
        });
        let active = self.snapshot.as_ref().is_some_and(|snapshot| {
            snapshot
                .active
                .iter()
                .any(|active| active.profile().id() == target.id())
        });
        match disconnected_for_delete(Instant::now(), deadline, unchanged, active) {
            Err(error) => {
                self.operations.finish_storage(ticket, None);
                self.deletion = None;
                self.notice = Some(Notice::Error);
                self.status = error;
            }
            Ok(true) => return self.dispatch_delete(target, ticket),
            Ok(false) => {}
        }
        Task::none()
    }

    pub(super) fn delete_dialog(&self) -> Option<Element<'_, Message>> {
        let Deletion::Confirm(target) = self.deletion.as_ref()? else {
            return None;
        };
        let active = self
            .snapshot
            .as_ref()?
            .active
            .iter()
            .any(|a| a.profile().id() == target.id());
        Some(delete_confirmation(target.name(), active))
    }

    pub(super) fn editor_page(&self) -> Option<Element<'_, Message>> {
        let editor = self.editor.as_ref()?;
        let spacing = theme::spacing();
        let enabled = !self.operations.busy();
        let mut name = widget::text_input(fl!("profile-name"), &editor.name)
            .label(fl!("profile-name"))
            .id(widget::Id::new("profile-name"));
        if enabled {
            name = name.on_input(|v| message(Action::Name(v)));
        }
        let mut form = widget::column::with_capacity(8)
            .spacing(spacing.space_m)
            .push(
                widget::button::text(fl!("back"))
                    .leading_icon(widget::icon::from_name("go-previous-symbolic"))
                    .on_press(message(Action::Cancel)),
            )
            .push(widget::text::title2(fl!("edit-profile")));
        let active = editor.target.as_ref().is_some_and(|target| {
            self.snapshot
                .as_ref()
                .is_some_and(|s| s.active.iter().any(|a| a.profile().id() == target.id()))
        });
        if active || (self.synthetic_preview() && self.active_count() == 1) {
            form = form.push(widget::text::body(fl!("edit-next-connection")));
        }
        form = form.push(name);
        let mut dns = widget::settings::section().title(fl!("dns-resolver"));
        for (choice, label, description) in [
            (
                DnsChoice::Inherit,
                fl!("dns-source-short"),
                fl!("dns-source-short-description"),
            ),
            (
                DnsChoice::CurrentNetwork,
                fl!("dns-current"),
                fl!("dns-current-short-description"),
            ),
            (
                DnsChoice::Manual,
                fl!("dns-manual-short"),
                fl!("no-direct-fallback"),
            ),
        ] {
            dns = dns.add(widget::radio(
                widget::column::with_capacity(2)
                    .push(widget::text::body(label))
                    .push(widget::text::caption(description)),
                choice,
                Some(editor.options.dns_choice),
                |v| message(Action::Dns(v)),
            ));
        }
        if editor.options.dns_choice == DnsChoice::Manual {
            let mut input =
                widget::text_input(fl!("public-dns-address"), &editor.options.manual_dns);
            if enabled {
                input = input.on_input(|v| message(Action::Manual(v)));
            }
            let invalid = editor.options.dns_override().is_err();
            if invalid {
                input = input.error(fl!("error-public-ipv4"));
            }
            dns = dns.add(input.label(fl!("public-resolver")));
            if invalid {
                // The native error outline/tooltip must not be the only
                // explanation: keep the rejection visible without hover.
                dns = dns.add(widget::text::caption(fl!("error-public-ipv4")));
            }
        }
        form = form.push(dns);
        let mut network = widget::settings::section().title(fl!("private-networks"));
        for (value, label) in [
            (LanBypass::None, fl!("use-source-routing")),
            (LanBypass::Connected, fl!("bypass-connected")),
            (LanBypass::Private, fl!("bypass-all-private")),
        ] {
            network = network.add(widget::radio(
                widget::text::body(label),
                value,
                Some(editor.lan),
                |v| message(Action::Lan(v)),
            ));
        }
        let required = editor.required;
        network = network
            .add(
                widget::settings::item::builder(fl!("intercept-ipv4-dns"))
                    .description(fl!("intercept-ipv4-description"))
                    .toggler_maybe(
                        editor.options.dns_interception,
                        (enabled && !editor.options.fake_ip && !required)
                            .then_some(|v| message(Action::Intercept(v))),
                    ),
            )
            .add(
                widget::settings::item::builder(fl!("persistent-fakeip-short"))
                    .description(fl!("persistent-fakeip-short-description"))
                    .toggler_maybe(
                        editor.options.fake_ip,
                        (enabled && editor.options.dns_interception && !required)
                            .then_some(|v| message(Action::FakeIp(v))),
                    ),
            );
        form = form.push(network);
        if let Err(error) = editor.changes()
            && editor.options.dns_override().is_ok()
        {
            form = form.push(widget::text::body(error));
        }
        let current = editor
            .target
            .as_ref()
            .is_some_and(|target| self.editable_target(target.id()).as_ref() == Some(target))
            || self.synthetic_preview();
        if !current {
            form = form.push(widget::text::body(fl!("profile-observation-changed")));
        }
        let footer = widget::row::with_capacity(3)
            .spacing(spacing.space_xxs)
            .push(widget::space::horizontal())
            .push(widget::button::text(fl!("cancel")).on_press(message(Action::Cancel)))
            .push(
                widget::button::suggested(fl!("save-changes")).on_press_maybe(
                    (enabled
                        && current
                        && !self.operations.uncertain()
                        && editor.changes().is_ok())
                    .then_some(message(Action::Save)),
                ),
            );
        Some(
            widget::column::with_capacity(2)
                .spacing(spacing.space_m)
                .push(
                    widget::scrollable(form)
                        .height(Length::Fill)
                        .id(widget::Id::new("profile-editor")),
                )
                .push(footer)
                .height(Length::Fill)
                .into(),
        )
    }
}

pub(super) fn delete_confirmation(name: &str, active: bool) -> Element<'static, Message> {
    widget::dialog()
        .title(if active {
            fl!("disconnect-delete-profile-confirm")
        } else {
            fl!("delete-profile-confirm")
        })
        .body(if active {
            fl!("delete-active-profile-body", name = name)
        } else {
            fl!("delete-profile-body", name = name)
        })
        .primary_action(
            widget::button::destructive(if active {
                fl!("disconnect-and-delete")
            } else {
                fl!("delete-profile-action")
            })
            .on_press(message(Action::ConfirmDelete)),
        )
        .secondary_action(
            widget::button::standard(fl!("cancel")).on_press(message(Action::CancelDelete)),
        )
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_dns_and_required_policy_reject_without_changing_the_draft() {
        let mut options = ProfileOptions {
            dns_choice: DnsChoice::Manual,
            manual_dns: "192.168.1.1".into(),
            ..Default::default()
        };
        assert!(checked_changes("Name", &options, LanBypass::None, false).is_err());
        assert_eq!(options.manual_dns, "192.168.1.1");
        options.manual_dns = "8.8.8.8".into();
        assert!(checked_changes("Name", &options, LanBypass::Connected, false).is_ok());
        assert!(checked_changes("", &options, LanBypass::None, false).is_err());
        assert!(checked_changes("Name", &options, LanBypass::None, true).is_err());
        options.dns_interception = true;
        options.fake_ip = true;
        assert!(checked_changes("Name", &options, LanBypass::Private, true).is_err());
        assert!(checked_changes("Name", &options, LanBypass::None, true).is_ok());
        assert!(options.fake_ip && options.dns_interception);
    }

    #[test]
    fn deletion_requires_observed_matching_profile_and_disconnection_before_its_deadline() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(45);
        assert_eq!(
            disconnected_for_delete(now, deadline, None, false),
            Ok(false)
        );
        assert_eq!(
            disconnected_for_delete(now, deadline, Some(true), true),
            Ok(false)
        );
        assert!(disconnected_for_delete(now, deadline, Some(false), false).is_err());
        assert_eq!(
            disconnected_for_delete(now, deadline, Some(true), false),
            Ok(true)
        );
        assert!(disconnected_for_delete(deadline, deadline, Some(true), false).is_err());
    }
}
