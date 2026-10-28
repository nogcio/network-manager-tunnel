//! Explicit subscription import is a separate task, never a connection side effect.
use super::{App, DnsChoice, Message, view::PAGE_SIZE};
use crate::i18n::fl;
use cosmic::{
    Element,
    iced::{Alignment, Length},
    theme, widget,
};
use nm_tunnel_profile::{PeerSecurity, Transport};
use secrecy::ExposeSecret;

impl App {
    pub(super) fn selected_dns_override(
        &self,
    ) -> Result<nm_tunnel_profile::DnsOverride, nm_tunnel_profile::DnsOverrideError> {
        self.options.dns_override()
    }

    pub(super) fn profile_with_dns(
        &self,
        profile: &nm_tunnel_profile::Profile,
    ) -> Result<nm_tunnel_profile::Profile, nm_tunnel_profile::DnsOverrideError> {
        self.options.apply(profile)
    }

    fn dns_options(&self) -> Element<'_, Message> {
        let native = self
            .catalog
            .subscription
            .as_ref()
            .is_some_and(|list| list.native_policy_notice().is_some());
        let mut options = widget::settings::section().title(fl!("dns-lan-next-profile"));
        options = options.add(
            widget::settings::item::builder(fl!("keep-private-outside"))
                .description(fl!("keep-private-description"))
                .toggler_maybe(
                    self.options.lan_bypass,
                    (!self.operations.busy() && (!native || self.options.lan_bypass))
                        .then_some(Message::LanBypass),
                ),
        );
        if native {
            options =
                options.add(widget::text::body(fl!("source-routing-conflict")).width(Length::Fill));
        }
        options = options.add(
            widget::settings::item::builder(fl!("intercept-tunnel-dns"))
                .description(fl!("intercept-tunnel-description"))
                .toggler_maybe(
                    self.options.dns_interception,
                    (!self.operations.busy() && !self.options.fake_ip)
                        .then_some(Message::DnsInterception),
                ),
        );
        options = options.add(
            widget::settings::item::builder(fl!("persistent-fakeip"))
                .description(fl!("persistent-fakeip-description"))
                .toggler_maybe(
                    self.options.fake_ip,
                    (!self.operations.busy() && self.options.dns_interception)
                        .then_some(Message::FakeIp),
                ),
        );
        if self.operations.busy() {
            return options
                .add(widget::text::body(fl!("dns-fixed-during-request")).width(Length::Fill))
                .into();
        }
        for (choice, title, description) in [
            (
                DnsChoice::Inherit,
                fl!("dns-source-policy"),
                fl!("dns-source-description"),
            ),
            (
                DnsChoice::CurrentNetwork,
                fl!("dns-current"),
                fl!("dns-current-description"),
            ),
            (
                DnsChoice::Manual,
                fl!("dns-manual"),
                fl!("dns-manual-description"),
            ),
        ] {
            options = options.add(
                widget::settings::item::builder(title)
                    .description(description)
                    .radio(choice, Some(self.options.dns_choice), Message::DnsChoice),
            );
        }
        if self.options.dns_choice == DnsChoice::Manual {
            options = options.add(
                widget::text_input(fl!("ipv4-dns-server"), &self.options.manual_dns)
                    .on_input(Message::ManualDns)
                    .width(Length::Fill),
            );
            if let Err(error) = self.selected_dns_override() {
                options = options
                    .add(widget::text::caption(crate::i18n::dns_error(error)).width(Length::Fill));
            }
        }
        options
            .add(widget::text::caption(fl!("next-profile-only")).width(Length::Fill))
            .into()
    }
    pub(super) fn matching_profiles(&self) -> Vec<usize> {
        self.catalog.matching()
    }

    pub(super) fn source_connect_action(&self, index: usize) -> Option<Message> {
        let uuid = self.catalog.added.get(&index)?;
        let snapshot = self.snapshot.as_ref()?;
        (self.nm_error.is_none()
            && snapshot.backend_registered
            && snapshot.active.is_empty()
            && !self.operations.busy()
            && snapshot.profiles.iter().any(|profile| profile.id() == uuid))
        .then(|| Message::ConnectProfile(uuid.clone()))
    }

    pub(super) fn import_page(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let mut input = widget::text_input(
            fl!("https-subscription-url"),
            self.download.source().expose_secret(),
        )
        .label(fl!("subscription-url"))
        .id(widget::Id::new("subscription-url"))
        .width(Length::Fill);
        if self.download.pending().is_none() && !self.operations.busy() {
            input = input
                .on_input(Message::Source)
                .on_submit(|_| Message::Subscription(super::subscriptions::Action::Add));
        }
        let complete =
            self.download.format() == nm_tunnel_subscription::SubscriptionFormat::Complete;
        let choice = |label: String, description: String, value| {
            widget::radio(
                widget::column::with_capacity(2)
                    .push(widget::text::body(label))
                    .push(widget::text::caption(description)),
                value,
                Some(complete),
                Message::FetchComplete,
            )
        };
        let source = widget::column::with_capacity(5)
            .spacing(spacing.space_m)
            .push(input)
            .push(widget::text::caption(self.source_storage_caption()))
            .push(
                widget::settings::section()
                    .title(fl!("import-mode"))
                    .add(choice(
                        fl!("complete-configuration"),
                        fl!("complete-configuration-description"),
                        true,
                    ))
                    .add(choice(
                        fl!("node-only"),
                        fl!("node-only-description"),
                        false,
                    )),
            );
        let mut content = widget::column::with_capacity(6).spacing(spacing.space_l);
        if self.sources.screen != super::subscriptions::Screen::Nodes {
            content = content.push(source);
        }
        if self.download.pending().is_some() {
            content = content.push(
                widget::row::with_capacity(2)
                    .spacing(spacing.space_s)
                    .align_y(Alignment::Center)
                    .push(widget::progress_bar::circular::Circular::new().size(16.0))
                    .push(widget::text::body(fl!("loading-subscription"))),
            );
        }
        if let Some(error) = self.download.error() {
            content = content.push(
                widget::text::body(
                    if self.sources.screen == super::subscriptions::Screen::Nodes {
                        fl!(
                            "error-previous-source",
                            error = crate::i18n::subscription_error(error)
                        )
                    } else if self.catalog.subscription.is_some() {
                        fl!(
                            "error-retained-nodes",
                            error = crate::i18n::subscription_error(error)
                        )
                    } else {
                        crate::i18n::subscription_error(error)
                    },
                )
                .width(Length::Fill),
            );
        }
        let Some(list) = &self.catalog.subscription else {
            return content.into();
        };
        if self.sources.screen == super::subscriptions::Screen::Add {
            return content
                .push(widget::text::body(fl!(
                    "source-check-counts",
                    supported = list.supported_count(),
                    unsupported = list.entries().len() - list.supported_count()
                )))
                .into();
        }
        if list.native_policy_notice().is_some() {
            content = content.push(
                widget::settings::section()
                    .add(widget::text::body(fl!("native-policy-disclosure")).width(Length::Fill)),
            );
        }
        if !self.catalog.admitted {
            content = content.push(widget::text::body(fl!("retained-nodes")).width(Length::Fill));
        }
        content =
            content.push(widget::text::body(fl!("save-profile-disclosure")).width(Length::Fill));
        let supported = list.supported_count();
        let counts = fl!(
            "node-counts",
            supported = supported,
            unsupported = list.entries().len() - supported
        );
        let mut nodes = widget::settings::section()
            .header(
                widget::column::with_capacity(2)
                    .spacing(spacing.space_xxxs)
                    .push(widget::text::heading(fl!("available-nodes")))
                    .push(widget::text::caption(counts)),
            )
            .add(
                widget::text_input::search_input(fl!("search-nodes"), &self.catalog.search)
                    .on_input(Message::SearchProfiles)
                    .on_clear(Message::SearchProfiles(String::new())),
            );
        let matching = self.matching_profiles();
        let pages = matching.len().div_ceil(PAGE_SIZE);
        if pages > 1 {
            nodes = nodes.add(self.import_pager(pages));
        }
        if matching.is_empty() {
            nodes = nodes.add(widget::text::body(fl!("no-matching-nodes")));
        }
        for &index in matching
            .iter()
            .skip(self.catalog.page * PAGE_SIZE)
            .take(PAGE_SIZE)
        {
            let entry = &list.entries()[index];
            nodes = match entry.profile() {
                Ok(profile) => {
                    let node = profile.node();
                    let transport = match node.transport() {
                        Transport::Tcp => "TCP",
                        Transport::WebSocket { .. } => "WebSocket",
                    };
                    let security = match node.security() {
                        PeerSecurity::Tls => "TLS",
                        PeerSecurity::Reality(_) => "REALITY",
                    };
                    let added = self.catalog.added.contains_key(&index);
                    let active = self
                        .catalog
                        .added
                        .get(&index)
                        .and_then(|uuid| {
                            self.snapshot
                                .as_ref()?
                                .active
                                .iter()
                                .find(|active| active.profile().id() == uuid)
                        })
                        .map(|active| active.state());
                    let (label, action) = if added {
                        let label = match active {
                            Some(nm_tunnel_client::ConnectionState::Connected) => fl!("connected"),
                            Some(nm_tunnel_client::ConnectionState::Connecting) => {
                                fl!("connecting")
                            }
                            Some(nm_tunnel_client::ConnectionState::Disconnecting) => {
                                fl!("disconnecting")
                            }
                            Some(nm_tunnel_client::ConnectionState::Unknown) => {
                                fl!("state-unavailable")
                            }
                            None => fl!("connect"),
                        };
                        (label, self.source_connect_action(index))
                    } else {
                        (
                            fl!("save-profile"),
                            (!self.operations.busy()
                                && self.download.pending().is_none()
                                && !self.operations.uncertain()
                                && self.catalog.admitted
                                && self.selected_dns_override().is_ok())
                            .then_some(Message::AddProfile(index)),
                        )
                    };
                    nodes.add(widget::settings::item_row(vec![
                        widget::column::with_capacity(2)
                            .width(Length::Fill)
                            .push(
                                widget::text::body(entry.name())
                                    .width(Length::Fill)
                                    .wrapping(cosmic::iced::core::text::Wrapping::WordOrGlyph),
                            )
                            .push(widget::text::caption(fl!(
                                "node-description",
                                saved = if added {
                                    format!("{} ", fl!("saved-profile-prefix"))
                                } else {
                                    String::new()
                                },
                                security = security,
                                transport = transport
                            )))
                            .into(),
                        widget::button::text(label.clone())
                            .description(fl!("node-action", action = label, name = entry.name()))
                            .on_press_maybe(action)
                            .into(),
                    ]))
                }
                Err(reason) => nodes.add(widget::settings::item_row(vec![
                    widget::column::with_capacity(2)
                        .width(Length::Fill)
                        .push(
                            widget::text::body(entry.name())
                                .width(Length::Fill)
                                .wrapping(cosmic::iced::core::text::Wrapping::WordOrGlyph),
                        )
                        .push(widget::text::caption(reason).width(Length::Fill))
                        .into(),
                    widget::text::caption(fl!("unsupported")).into(),
                ])),
            };
        }
        if pages > 1 {
            nodes = nodes.add(self.import_pager(pages));
        }
        content.push(nodes).push(self.dns_options()).into()
    }

    fn import_pager(&self, pages: usize) -> Element<'_, Message> {
        widget::row::with_capacity(3)
            .spacing(theme::spacing().space_s)
            .align_y(Alignment::Center)
            .push(widget::button::standard(fl!("previous")).on_press_maybe(
                (self.catalog.page > 0).then(|| Message::ProfilePage(self.catalog.page - 1)),
            ))
            .push(
                widget::text::caption(fl!(
                    "page-count",
                    page = self.catalog.page + 1,
                    pages = pages
                ))
                .width(Length::Fill)
                .align_x(Alignment::Center),
            )
            .push(
                widget::button::standard(fl!("next")).on_press_maybe(
                    (self.catalog.page + 1 < pages)
                        .then_some(Message::ProfilePage(self.catalog.page + 1)),
                ),
            )
            .into()
    }
}
