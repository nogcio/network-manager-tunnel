//! Connection-first COSMIC layout. NM remains authoritative for every control.
use super::{App, Details, Message, Notice, Page, traffic::bytes};
use crate::i18n::fl;
use cosmic::{
    Element,
    app::context_drawer::{self, ContextDrawer},
    iced::{Alignment, Length},
    theme, widget,
};
use nm_tunnel_client::ConnectionState;

pub(super) const PAGE_SIZE: usize = 24;

/// Display-only projection: previews never fabricate actionable NM handles.
pub(super) struct ProfileRow<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub persistent: bool,
    pub dns_override: nm_tunnel_profile::DnsOverride,
    pub lan_bypass: bool,
    pub private_lan_bypass: bool,
    pub dns_interception: bool,
    pub fake_ip: bool,
    pub source_policy: bool,
    pub state: Option<ConnectionState>,
}

impl App {
    pub(super) fn details_include_usage(&self) -> bool {
        matches!(self.details, Some(Details::Connection))
    }
    pub(super) fn profile_rows(&self) -> Option<Vec<ProfileRow<'_>>> {
        #[cfg(all(feature = "preview", debug_assertions))]
        if let Some(preview) = &self.preview {
            return preview.profile_rows();
        }
        self.snapshot.as_ref().map(|snapshot| {
            snapshot
                .profiles
                .iter()
                .map(|profile| ProfileRow {
                    id: profile.id(),
                    name: profile.name(),
                    persistent: profile.persistent(),
                    dns_override: profile.dns_override(),
                    lan_bypass: profile.lan_bypass(),
                    private_lan_bypass: profile.private_lan_bypass(),
                    dns_interception: profile.dns_interception(),
                    fake_ip: profile.fake_ip(),
                    source_policy: profile.native_source_policy(),
                    state: snapshot
                        .active
                        .iter()
                        .find(|a| a.profile().id() == profile.id())
                        .map(|a| a.state()),
                })
                .collect()
        })
    }

    pub(super) fn page(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        if let Some(editor) = self.editor_page() {
            let mut page = widget::column::with_capacity(2).spacing(spacing.space_m);
            if let Some(feedback) = self.feedback_view() {
                page = page.push(feedback);
            }
            let horizontal = if self.core.is_condensed() {
                spacing.space_m
            } else {
                spacing.space_xl
            };
            return widget::container(
                widget::container(page.push(editor))
                    .padding([spacing.space_m, horizontal])
                    .max_width(860)
                    .width(Length::Fill),
            )
            .align_x(Alignment::Center)
            .width(Length::Fill)
            .height(Length::Fill)
            .into();
        }
        let mut content = widget::column::with_capacity(4)
            .spacing(spacing.space_m)
            .width(Length::Fill);
        let compact_details = self.core.is_condensed() && self.details.is_some();
        let mut header = widget::column::with_capacity(2).spacing(spacing.space_xxs);
        if compact_details {
            header = header.push(
                widget::button::text(fl!("back"))
                    .leading_icon(widget::icon::from_name("go-previous-symbolic"))
                    .on_press(Message::CloseDetails),
            );
        }
        if compact_details
            || self.page != Page::Import
            || self.sources.screen == super::subscriptions::Screen::List
        {
            let title = if compact_details {
                self.details_title()
            } else {
                self.page.title()
            };
            let mut row = widget::row::with_capacity(2)
                .align_y(Alignment::Center)
                .push(widget::text::title2(title).width(Length::Fill));
            if !compact_details && self.page == Page::Import {
                row = row.push(
                    widget::button::standard(fl!("add-subscription")).on_press_maybe(
                        self.can_add_source()
                            .then_some(Message::Subscription(super::subscriptions::Action::New)),
                    ),
                );
            }
            content = content.push(header.push(row));
        }
        if !matches!(self.details, Some(Details::Profile(_)))
            && let Some(feedback) = self.feedback_view()
        {
            content = content.push(feedback);
        }
        content = content.push(if compact_details {
            self.details_content()
                .unwrap_or_else(|| widget::space::vertical().into())
        } else {
            match self.page {
                Page::Connections => self.connections_page(),
                Page::Import => self.subscriptions_page(),
            }
        });
        let horizontal_padding = if self.core.is_condensed() {
            spacing.space_m
        } else if self.core.window.show_context {
            spacing.space_s
        } else {
            spacing.space_xl
        };
        let mut scroll = widget::scrollable(
            widget::container(content).padding([spacing.space_m, horizontal_padding]),
        )
        .id(widget::Id::new(if compact_details {
            "details-page"
        } else {
            self.page.scroll_id()
        }))
        .height(Length::Fill);
        if !compact_details {
            let page = self.page;
            let (source, screen) = self.source_viewport();
            scroll = scroll.on_scroll(move |viewport| {
                if page == Page::Import {
                    Message::Subscription(super::subscriptions::Action::Scrolled(
                        source,
                        screen,
                        viewport.absolute_offset(),
                    ))
                } else {
                    Message::PageScrolled(page, viewport.absolute_offset())
                }
            });
        }
        let body = widget::column::with_capacity(2).push(scroll).push_maybe(
            (if compact_details {
                self.profile_actions()
            } else {
                self.source_review_footer()
            })
            .map(|footer| widget::container(footer).padding([spacing.space_m, horizontal_padding])),
        );
        widget::container(widget::container(body).max_width(860).width(Length::Fill))
            .align_x(Alignment::Center)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn feedback_view(&self) -> Option<Element<'_, Message>> {
        if !self.operations.uncertain() && !self.operations.busy() && self.notice.is_none() {
            return None;
        }
        let spacing = theme::spacing();
        let mut content = widget::column::with_capacity(3).spacing(spacing.space_m);
        if self.operations.uncertain() {
            content = content.push(
                widget::settings::section().add(
                    widget::row::with_capacity(2)
                        .spacing(spacing.space_s)
                        .align_y(Alignment::Start)
                        .push(
                            widget::icon::from_name("dialog-warning-symbolic")
                                .size(20)
                                .icon(),
                        )
                        .push(widget::text::body(fl!("write-unconfirmed")).width(Length::Fill)),
                ),
            );
        }
        if self.operations.busy() {
            content = content.push(
                widget::row::with_capacity(2)
                    .spacing(spacing.space_s)
                    .align_y(Alignment::Center)
                    .push(widget::progress_bar::circular::Circular::new().size(16.0))
                    .push(widget::text::body(&self.status).width(Length::Fill)),
            );
        }
        if let Some(notice) = self.notice {
            content = content.push(
                widget::settings::section().add(
                    widget::row::with_capacity(3)
                        .spacing(spacing.space_s)
                        .align_y(Alignment::Start)
                        .push(
                            widget::icon::from_name(match notice {
                                Notice::Info => "dialog-information-symbolic",
                                Notice::Error => "dialog-warning-symbolic",
                            })
                            .size(20)
                            .icon(),
                        )
                        .push(widget::text::body(&self.status).width(Length::Fill))
                        .push(
                            widget::button::text(fl!("dismiss")).on_press(Message::DismissNotice),
                        ),
                ),
            );
        }
        Some(content.into())
    }

    fn connections_page(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let mut summary = widget::row::with_capacity(3)
            .spacing(spacing.space_m)
            .align_y(Alignment::Center)
            .push(
                widget::column::with_capacity(2)
                    .spacing(spacing.space_xxxs)
                    .width(Length::Fill)
                    .push(widget::text::title4(self.connection_title()))
                    .push_maybe((!self.connection_hint().is_empty()).then(|| {
                        widget::text::body(self.connection_hint())
                            .wrapping(if self.active_count() == 1 {
                                cosmic::iced::core::text::Wrapping::WordOrGlyph
                            } else {
                                cosmic::iced::core::text::Wrapping::Word
                            })
                            .width(Length::Fill)
                    }))
                    .push_maybe(
                        self.recovery
                            .hint()
                            .map(|hint| widget::text::body(hint).width(Length::Fill)),
                    ),
            );
        if self.active_count() == 1 {
            summary = summary.push(
                widget::button::standard(fl!("disconnect"))
                    .on_press_maybe(self.can_disconnect().then_some(Message::Disconnect)),
            );
        }
        if self.nm_error.is_some() {
            summary = summary.push(
                widget::button::standard(fl!("refresh")).on_press_maybe(
                    (!self.operations.busy() && self.reads.nm.pending().is_none())
                        .then_some(Message::Poll),
                ),
            );
        }
        let page = widget::column::with_capacity(6)
            .spacing(spacing.space_l)
            .push(widget::settings::section().add(summary));
        let page = if self.show_traffic_chart() {
            page.push(self.traffic_view()).push(self.saved_profiles())
        } else {
            page.push(self.saved_profiles()).push(
                widget::button::text(fl!("backend-statistics"))
                    .on_press(Message::ShowDetails(None)),
            )
        };
        page.push(
            widget::row::with_capacity(2)
                .push(widget::space::horizontal())
                .push(
                    widget::button::standard(fl!("add-subscription")).on_press_maybe(
                        self.can_add_source()
                            .then_some(Message::Subscription(super::subscriptions::Action::New)),
                    ),
                ),
        )
        .into()
    }

    pub(super) fn show_traffic_chart(&self) -> bool {
        self.nm_error.is_none()
            && self.active_count() == 1
            && self.profile_rows().is_some_and(|rows| {
                rows.iter()
                    .any(|profile| profile.state == Some(ConnectionState::Connected))
            })
            && self
                .traffic
                .snapshot
                .as_ref()
                .is_some_and(|data| data.available)
    }

    fn saved_profiles(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let mut section = widget::settings::section().title(fl!("profiles"));
        let Some(profiles) = self.profile_rows() else {
            return section
                .add(widget::text::body(fl!("profiles-unavailable")).width(Length::Fill))
                .into();
        };
        if profiles.is_empty() {
            return section
                .add(
                    widget::column::with_capacity(2)
                        .spacing(spacing.space_s)
                        .push(widget::text::heading(fl!("no-profiles")))
                        .push(widget::text::body(fl!("first-profile-hint")).width(Length::Fill)),
                )
                .into();
        }
        section = section.add(
            widget::text_input::search_input(fl!("search-profiles"), &self.saved_search)
                .on_input(Message::SearchSaved)
                .on_clear(Message::SearchSaved(String::new())),
        );
        let query = self.saved_search.trim().to_lowercase();
        let mut found = false;
        for profile in profiles
            .iter()
            .filter(|p| p.name.to_lowercase().contains(&query))
        {
            found = true;
            let status = profile.state.map(|state| match state {
                ConnectionState::Connected => fl!("connected"),
                ConnectionState::Connecting => fl!("connecting"),
                ConnectionState::Disconnecting => fl!("disconnecting"),
                ConnectionState::Unknown => fl!("unknown-state"),
            });
            let mut controls = widget::row::with_capacity(2)
                .spacing(spacing.space_xxs)
                .align_y(Alignment::Center);
            if let Some(status) = status {
                controls = controls.push(widget::text::caption(status));
            } else {
                controls = controls.push(
                    widget::button::text(fl!("connect"))
                        .description(fl!("connect-profile", name = profile.name))
                        .tooltip(if self.active_count() == 0 {
                            fl!("connect-this-profile")
                        } else {
                            fl!("disconnect-before-switch")
                        })
                        .on_press_maybe(
                            (!self.operations.busy()
                                && self.snapshot.as_ref().is_some_and(|s| s.backend_registered)
                                && self.active_count() == 0)
                                .then(|| Message::ConnectProfile(profile.id.to_owned())),
                        ),
                );
            }
            controls = controls.push(
                widget::button::text(fl!("settings"))
                    .description(fl!("settings-for-profile", name = profile.name))
                    .on_press(Message::ShowDetails(Some(profile.id.to_owned()))),
            );
            let name = widget::column::with_capacity(2)
                .width(Length::Fill)
                .push(
                    widget::text::body(profile.name)
                        .wrapping(cosmic::iced::core::text::Wrapping::WordOrGlyph)
                        .width(Length::Fill),
                )
                .push(widget::text::caption(
                    self.sources
                        .source_name(profile.id)
                        .map_or_else(|| fl!("local-profile"), str::to_owned),
                ));
            if self.core.window.show_context || self.core.is_condensed() {
                section = section.add(
                    widget::column::with_capacity(2)
                        .spacing(spacing.space_s)
                        .push(name)
                        .push(controls),
                );
            } else {
                section = section.add(widget::settings::item_row(vec![
                    name.into(),
                    controls.into(),
                ]));
            }
        }
        if !found {
            section = section.add(widget::text::body(fl!("no-matching-profiles")));
        }
        section.into()
    }

    pub(super) fn details_drawer(&self) -> Option<ContextDrawer<'_, Message>> {
        if !self.core.window.show_context || self.core.is_condensed() {
            return None;
        }
        if let Some(settings) = self.source_settings() {
            return Some(
                context_drawer::context_drawer(
                    settings,
                    Message::Subscription(super::subscriptions::Action::CloseSettings),
                )
                .title(fl!("subscription-settings"))
                .footer(self.source_settings_footer()),
            );
        }
        let mut drawer =
            context_drawer::context_drawer(self.details_content()?, Message::CloseDetails)
                .title(self.details_title());
        if let Some(actions) = self.profile_actions() {
            drawer = drawer.footer(actions);
        }
        Some(drawer)
    }

    fn profile_actions(&self) -> Option<Element<'_, Message>> {
        let Some(Details::Profile(id)) = &self.details else {
            return None;
        };
        let current = self.snapshot.as_ref().is_some_and(|s| {
            s.profiles
                .iter()
                .any(|p| p.id() == id && p.checked_update_available())
        });
        if !current
            && !(self.synthetic_preview()
                && self
                    .profile_rows()
                    .is_some_and(|rows| rows.iter().any(|profile| profile.id == id)))
        {
            return None;
        }
        let enabled = current
            && !self.operations.busy()
            && !self.operations.uncertain()
            && self.nm_error.is_none();
        Some(
            widget::column::with_capacity(2)
                .spacing(theme::spacing().space_s)
                .push(
                    widget::button::suggested(fl!("edit-settings")).on_press_maybe(enabled.then(
                        || Message::Profile(super::profile_editor::Action::Edit(id.clone())),
                    )),
                )
                .push(
                    widget::button::destructive(fl!("delete-profile")).on_press_maybe(
                        enabled.then(|| {
                            Message::Profile(super::profile_editor::Action::AskDelete(id.clone()))
                        }),
                    ),
                )
                .into(),
        )
    }

    fn details_title(&self) -> String {
        if matches!(self.details, Some(Details::Connection)) {
            fl!("backend-statistics")
        } else {
            fl!("profile-settings")
        }
    }

    fn details_content(&self) -> Option<Element<'_, Message>> {
        let details = self.details.as_ref()?;
        let spacing = theme::spacing();
        let mut content = widget::column::with_capacity(7).spacing(spacing.space_m);
        if matches!(details, Details::Profile(_))
            && let Some(feedback) = self.feedback_view()
        {
            content = content.push(feedback);
        }
        match details {
            Details::Connection => {
                content = content.push(widget::text::heading(fl!("backend-last-attempt")));
            }
            Details::Profile(id) => {
                let profile = self
                    .profile_rows()
                    .and_then(|rows| rows.into_iter().find(|p| p.id == id));
                if let Some(profile) = profile {
                    let item = |label: String, value: String| {
                        widget::settings::item(
                            label,
                            widget::text::body(value)
                                .wrapping(cosmic::iced::core::text::Wrapping::WordOrGlyph),
                        )
                    };
                    content = content
                        .push(
                            widget::text::title4(profile.name)
                                .wrapping(cosmic::iced::core::text::Wrapping::WordOrGlyph)
                                .width(Length::Fill),
                        )
                        .push(
                            widget::settings::section()
                                .add(item(
                                    fl!("source"),
                                    self.sources
                                        .source_name(id)
                                        .map_or_else(|| fl!("local-profile"), str::to_owned),
                                ))
                                .add(item(
                                    fl!("storage"),
                                    if profile.persistent {
                                        fl!("saved-in-nm")
                                    } else {
                                        fl!("session-only-profile")
                                    },
                                ))
                                .add(item(
                                    fl!("dns"),
                                    match profile.dns_override {
                                        nm_tunnel_profile::DnsOverride::Inherit => {
                                            fl!("dns-default-detail")
                                        }
                                        nm_tunnel_profile::DnsOverride::CurrentNetwork => {
                                            fl!("dns-current-detail")
                                        }
                                        nm_tunnel_profile::DnsOverride::ProxyIpv4(ip) => {
                                            fl!("dns-proxy-detail", ip = ip.to_string())
                                        }
                                    },
                                ))
                                .add(item(
                                    fl!("private-bypass"),
                                    if profile.private_lan_bypass {
                                        fl!("all-private-routes")
                                    } else if profile.lan_bypass {
                                        fl!("connected-private-subnets")
                                    } else {
                                        fl!("source-routing")
                                    },
                                ))
                                .add(item(
                                    fl!("dns-interception"),
                                    if profile.dns_interception {
                                        fl!("dns-interception-detail")
                                    } else {
                                        fl!("off")
                                    },
                                ))
                                .add(item(
                                    fl!("fakeip"),
                                    if profile.fake_ip {
                                        fl!("persistent-identities")
                                    } else {
                                        fl!("off")
                                    },
                                )),
                        )
                        .push(widget::text::caption(fl!("saved-not-enforcement")));
                    if profile.source_policy {
                        content =
                            content.push(widget::text::caption(fl!("required-policy-preserved")));
                    }
                } else {
                    content = content.push(widget::text::body(fl!("profile-unavailable")));
                }
                let state = self
                    .profile_rows()
                    .and_then(|rows| rows.into_iter().find(|p| p.id == id).map(|p| p.state));
                content = content.push(widget::text::caption(match state {
                    Some(Some(ConnectionState::Connected)) => fl!("active"),
                    Some(Some(ConnectionState::Connecting)) => fl!("connecting"),
                    Some(Some(ConnectionState::Disconnecting)) => fl!("disconnecting"),
                    Some(None) => fl!("inactive"),
                    _ => fl!("state-unavailable"),
                }));
            }
        }
        if self.details_include_usage() {
            content = content.push(widget::text::caption(self.traffic.freshness()));
            if let Some(data) = self.traffic.snapshot.as_ref() {
                let item = |title: String, value: String| {
                    widget::settings::item(title, widget::text::body(value))
                };
                if data.available {
                    content = content.push(
                        widget::settings::section()
                            .title(fl!("last-observed-usage"))
                            .add(item(fl!("downloaded"), bytes(data.counters.download_bytes)))
                            .add(item(fl!("uploaded"), bytes(data.counters.upload_bytes)))
                            .add(item(fl!("tcp-flows"), data.counters.tcp_active.to_string()))
                            .add(item(
                                fl!("udp-associations"),
                                data.counters.udp_active.to_string(),
                            ))
                            .add(item(
                                fl!("failed-flows"),
                                format!(
                                    "{} / {}",
                                    data.counters.tcp_failed, data.counters.udp_failed
                                ),
                            ))
                            .add(item(
                                fl!("dropped-packets"),
                                data.counters.dropped_packets.to_string(),
                            )),
                    );
                }
                content = content.push(
                    widget::settings::section()
                        .title(fl!("backend"))
                        .add(item(fl!("state"), data.state.clone()))
                        .add(item(fl!("setup-stage"), data.setup_stage.clone()))
                        .add(item(fl!("worker-stage"), data.worker_stage.to_string())),
                );
            }
        }
        Some(content.into())
    }
}
