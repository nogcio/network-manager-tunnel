//! Explicit subscription import is a separate task, never a connection side effect.
use super::{App, Message, view::PAGE_SIZE};
use cosmic::{
    Element,
    iced::{Alignment, Length},
    theme, widget,
};
use nm_tunnel_profile::{Security, Transport};
use secrecy::ExposeSecret;

impl App {
    pub(super) fn matching_profiles(&self) -> Vec<usize> {
        let query = self.profile_search.trim().to_lowercase();
        self.subscription.as_ref().map_or_else(Vec::new, |list| {
            list.entries()
                .iter()
                .enumerate()
                .filter_map(|(index, entry)| {
                    (query.is_empty() || entry.name().to_lowercase().contains(&query))
                        .then_some(index)
                })
                .collect()
        })
    }

    pub(super) fn import_page(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let mut input = widget::text_input::secure_input(
            "HTTPS subscription URL",
            self.source.expose_secret(),
            None,
            true,
        )
        .id(widget::Id::new("subscription-url"))
        .width(Length::Fill);
        if !self.fetching && !self.busy {
            input = input.on_input(Message::Source).on_submit(|_| Message::Load);
        }
        let source = widget::settings::section()
            .title("Subscription URL")
            .add(input)
            .add(
                widget::row::with_capacity(2)
                    .align_y(Alignment::Center)
                    .push(widget::space::horizontal())
                    .push(
                        widget::button::suggested(if self.subscription.is_some() {
                            "Reload subscription"
                        } else {
                            "Load subscription"
                        })
                        .on_press_maybe((!self.fetching && !self.busy).then_some(Message::Load)),
                    ),
            );
        let mut content = widget::column::with_capacity(6)
            .spacing(spacing.space_l)
            .push(source);
        if self.fetching {
            content = content.push(
                widget::row::with_capacity(2)
                    .spacing(spacing.space_s)
                    .align_y(Alignment::Center)
                    .push(widget::progress_bar::circular::Circular::new().size(16.0))
                    .push(widget::text::body("Loading subscription…")),
            );
        }
        if let Some(error) = &self.load_error {
            content = content.push(
                widget::text::body(if self.subscription.is_some() {
                    format!("{error} Previously loaded nodes are unchanged.")
                } else {
                    error.to_string()
                })
                .width(Length::Fill),
            );
        }
        let Some(list) = &self.subscription else {
            return content.into();
        };
        content = content.push(
            widget::settings::section().add(
                widget::settings::item::builder("Remember added profiles")
                    .description("Save profiles and credentials on disk in NetworkManager.")
                    .toggler_maybe(self.remember, (!self.busy).then_some(Message::Remember)),
            ),
        );
        let supported = list.supported_count();
        let counts = format!(
            "{supported} supported · {} unsupported",
            list.entries().len() - supported
        );
        let mut nodes = widget::settings::section()
            .header(
                widget::column::with_capacity(2)
                    .spacing(spacing.space_xxxs)
                    .push(widget::text::heading("Available nodes"))
                    .push(widget::text::caption(counts)),
            )
            .add(
                widget::text_input::search_input("Search nodes by name", &self.profile_search)
                    .on_input(Message::SearchProfiles)
                    .on_clear(Message::SearchProfiles(String::new())),
            );
        let matching = self.matching_profiles();
        let pages = matching.len().div_ceil(PAGE_SIZE);
        if pages > 1 {
            nodes = nodes.add(self.import_pager(pages));
        }
        if matching.is_empty() {
            nodes = nodes.add(widget::text::body("No matching nodes"));
        }
        for &index in matching
            .iter()
            .skip(self.profile_page * PAGE_SIZE)
            .take(PAGE_SIZE)
        {
            let entry = &list.entries()[index];
            nodes = match entry.profile() {
                Ok(profile) => {
                    let fields = profile.fields();
                    let transport = match fields.transport {
                        Transport::Tcp => "TCP",
                        Transport::WebSocket { .. } => "WebSocket",
                    };
                    let security = match fields.security {
                        Security::Tls => "TLS",
                        Security::Reality => "REALITY",
                    };
                    let added = self.added.contains_key(&index);
                    nodes.add(widget::settings::item_row(vec![
                        widget::column::with_capacity(2)
                            .width(Length::Fill)
                            .push(
                                widget::text::body(entry.name())
                                    .width(Length::Fill)
                                    .wrapping(cosmic::iced::core::text::Wrapping::Glyph),
                            )
                            .push(widget::text::caption(format!(
                                "VLESS · {security} · {transport}"
                            )))
                            .into(),
                        widget::button::text(if added { "Added" } else { "Add profile" })
                            .description(format!("Add {} to NetworkManager", entry.name()))
                            .on_press_maybe(
                                (!added && !self.busy && !self.fetching && !self.uncertain)
                                    .then_some(Message::AddProfile(index)),
                            )
                            .into(),
                    ]))
                }
                Err(reason) => nodes.add(widget::settings::item_row(vec![
                    widget::column::with_capacity(2)
                        .width(Length::Fill)
                        .push(
                            widget::text::body(entry.name())
                                .width(Length::Fill)
                                .wrapping(cosmic::iced::core::text::Wrapping::Glyph),
                        )
                        .push(widget::text::caption(reason).width(Length::Fill))
                        .into(),
                    widget::text::caption("Unsupported").into(),
                ])),
            };
        }
        if pages > 1 {
            nodes = nodes.add(self.import_pager(pages));
        }
        content.push(nodes).into()
    }

    fn import_pager(&self, pages: usize) -> Element<'_, Message> {
        widget::row::with_capacity(3)
            .spacing(theme::spacing().space_s)
            .align_y(Alignment::Center)
            .push(widget::button::standard("Previous").on_press_maybe(
                (self.profile_page > 0).then(|| Message::ProfilePage(self.profile_page - 1)),
            ))
            .push(
                widget::text::caption(format!("Page {} of {pages}", self.profile_page + 1))
                    .width(Length::Fill)
                    .align_x(Alignment::Center),
            )
            .push(
                widget::button::standard("Next").on_press_maybe(
                    (self.profile_page + 1 < pages)
                        .then_some(Message::ProfilePage(self.profile_page + 1)),
                ),
            )
            .into()
    }
}
