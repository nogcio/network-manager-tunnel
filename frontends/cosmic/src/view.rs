//! Connection-first COSMIC layout. NM remains authoritative for every control.
use super::{App, Details, Message, Notice, Page, traffic::bytes};
use cosmic::{
    Element,
    app::context_drawer::{self, ContextDrawer},
    iced::{Alignment, Length},
    theme, widget,
};
use nm_tunnel_client::ConnectionState;

pub(super) const PAGE_SIZE: usize = 24;

fn route_icon() -> widget::icon::Handle {
    widget::icon::from_svg_bytes(
        &include_bytes!("../resources/icons/io.github.nm_tunnel.Cosmic-symbolic.svg")[..],
    )
    .symbolic(true)
}

/// Display-only projection: previews never fabricate actionable NM handles.
pub(super) struct ProfileRow<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub persistent: bool,
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
        let mut content = widget::column::with_capacity(4)
            .spacing(spacing.space_m)
            .width(Length::Fill);
        if self.uncertain {
            content = content.push(widget::settings::section().add(widget::row::with_capacity(2)
                .spacing(spacing.space_s).align_y(Alignment::Start)
                .push(widget::icon::from_name("dialog-warning-symbolic").size(20).icon())
                .push(widget::text::body("Save not confirmed. Additions are disabled for this app session; check NetworkManager before retrying.").width(Length::Fill))));
        }
        if self.busy {
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
                        .push(widget::button::text("Dismiss").on_press(Message::DismissNotice)),
                ),
            );
        }
        content = content.push(match self.page {
            Page::Connections => self.connections_page(),
            Page::Import => self.import_page(),
        });
        widget::container(
            widget::container(
                widget::scrollable(
                    widget::container(content).padding([spacing.space_m, spacing.space_l]),
                )
                .id(widget::Id::new(match self.page {
                    Page::Connections => "connections-page",
                    Page::Import => "import-page",
                }))
                .height(Length::Fill),
            )
            .max_width(860)
            .width(Length::Fill),
        )
        .align_x(Alignment::Center)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }

    fn connections_page(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let mut summary = widget::row::with_capacity(3)
            .spacing(spacing.space_m)
            .align_y(Alignment::Center)
            .push(route_icon().icon().size(28))
            .push(
                widget::column::with_capacity(2)
                    .spacing(spacing.space_xxxs)
                    .width(Length::Fill)
                    .push(widget::text::heading(self.connection_title()))
                    .push_maybe((!self.connection_hint().is_empty()).then(|| {
                        widget::text::body(self.connection_hint())
                            .wrapping(if self.active_count() == 1 {
                                cosmic::iced::core::text::Wrapping::Glyph
                            } else {
                                cosmic::iced::core::text::Wrapping::Word
                            })
                            .width(Length::Fill)
                    })),
            );
        if self.active_count() == 1 {
            summary = summary.push(
                widget::button::standard("Disconnect")
                    .on_press_maybe(self.can_disconnect().then_some(Message::Disconnect)),
            );
        }
        if self.nm_error.is_some() {
            summary = summary
                .push(widget::button::standard("Refresh").on_press_maybe(
                    (!self.busy && !self.monitor_pending).then_some(Message::Poll),
                ));
        }
        let page = widget::column::with_capacity(6)
            .spacing(spacing.space_l)
            .push(widget::settings::section().add(summary));
        if self.active_count() == 0 {
            page.push(self.saved_profiles())
                .push(self.traffic_view())
                .into()
        } else {
            page.push(self.traffic_view())
                .push(self.saved_profiles())
                .into()
        }
    }

    fn saved_profiles(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let mut section = widget::settings::section().title("Profiles");
        let Some(profiles) = self.profile_rows() else {
            return section
                .add(widget::text::body("Profiles unavailable").width(Length::Fill))
                .into();
        };
        if profiles.is_empty() {
            return section
                .add(
                    widget::column::with_capacity(2)
                        .spacing(spacing.space_s)
                        .push(widget::text::heading("No profiles yet"))
                        .push(
                            widget::text::body("Import a subscription to add profiles.")
                                .width(Length::Fill),
                        ),
                )
                .into();
        }
        section = section.add(
            widget::text_input::search_input("Search profiles", &self.saved_search)
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
                ConnectionState::Connected => "Connected",
                ConnectionState::Connecting => "Connecting…",
                ConnectionState::Disconnecting => "Disconnecting…",
                ConnectionState::Unknown => "Unknown state",
            });
            let mut controls = widget::row::with_capacity(2)
                .spacing(spacing.space_xxs)
                .align_y(Alignment::Center);
            if let Some(status) = status {
                controls = controls.push(widget::text::caption(status));
            } else {
                controls = controls.push(
                    widget::button::text("Connect")
                        .description(format!("Connect {}", profile.name))
                        .tooltip(if self.active_count() == 0 {
                            "Connect this profile"
                        } else {
                            "Disconnect the current VPN before switching profiles"
                        })
                        .on_press_maybe(
                            (!self.busy
                                && self.snapshot.as_ref().is_some_and(|s| s.backend_registered)
                                && self.active_count() == 0)
                                .then(|| Message::ConnectProfile(profile.id.to_owned())),
                        ),
                );
            }
            controls = controls.push(
                widget::button::icon(widget::icon::from_name("dialog-information-symbolic"))
                    .name(format!("Details for {}", profile.name))
                    .tooltip("Profile details")
                    .on_press(Message::ShowDetails(Some(profile.id.to_owned()))),
            );
            section = section.add(widget::settings::item_row(vec![
                route_icon().icon().size(20).into(),
                widget::text::body(profile.name)
                    .wrapping(cosmic::iced::core::text::Wrapping::Glyph)
                    .width(Length::Fill)
                    .into(),
                controls.into(),
            ]));
        }
        if !found {
            section = section.add(widget::text::body("No matching profiles"));
        }
        section.into()
    }

    pub(super) fn details_drawer(&self) -> Option<ContextDrawer<'_, Message>> {
        if !self.core.window.show_context {
            return None;
        }
        let details = self.details.as_ref()?;
        let spacing = theme::spacing();
        let mut content = widget::column::with_capacity(7).spacing(spacing.space_m);
        match details {
            Details::Connection => {
                content = content.push(widget::text::heading("Backend · last attempt"));
            }
            Details::Profile(id) => {
                let profile = self
                    .profile_rows()
                    .and_then(|rows| rows.into_iter().find(|p| p.id == id));
                if let Some(profile) = profile {
                    content = content
                        .push(
                            widget::text::title4(profile.name)
                                .wrapping(cosmic::iced::core::text::Wrapping::Glyph)
                                .width(Length::Fill),
                        )
                        .push(
                            widget::text::body(if profile.persistent {
                                "Saved on disk by NetworkManager."
                            } else {
                                "Session-only profile. Lost when NetworkManager restarts."
                            })
                            .width(Length::Fill),
                        );
                } else {
                    content = content.push(widget::text::body("This profile is no longer available in the current NetworkManager observation."));
                }
                let active = self
                    .profile_rows()
                    .is_some_and(|rows| rows.iter().any(|p| p.id == id && p.state.is_some()));
                content = content.push(widget::text::caption(if active {
                    "Active"
                } else {
                    "Inactive"
                }));
            }
        }
        if self.details_include_usage() {
            content = content.push(widget::text::caption(self.traffic.freshness()));
            if let Some(data) = self.traffic.snapshot.as_ref() {
                let item = |title: &'static str, value: String| {
                    widget::settings::item(title, widget::text::body(value))
                };
                if data.available {
                    content = content.push(
                        widget::settings::section()
                            .title("Last observed usage")
                            .add(item("Downloaded", bytes(data.counters.download_bytes)))
                            .add(item("Uploaded", bytes(data.counters.upload_bytes)))
                            .add(item("TCP flows", data.counters.tcp_active.to_string()))
                            .add(item(
                                "UDP associations",
                                data.counters.udp_active.to_string(),
                            ))
                            .add(item(
                                "Failed TCP / UDP",
                                format!(
                                    "{} / {}",
                                    data.counters.tcp_failed, data.counters.udp_failed
                                ),
                            ))
                            .add(item(
                                "Dropped packets",
                                data.counters.dropped_packets.to_string(),
                            )),
                    );
                }
                content = content.push(
                    widget::settings::section()
                        .title("Backend")
                        .add(item("State", data.state.clone()))
                        .add(item("Setup stage", data.setup_stage.clone()))
                        .add(item("Worker stage", data.worker_stage.to_string())),
                );
            }
        }
        Some(
            context_drawer::context_drawer(content, Message::CloseDetails).title(
                if matches!(details, Details::Connection) {
                    "Backend statistics"
                } else {
                    "Profile details"
                },
            ),
        )
    }
}
