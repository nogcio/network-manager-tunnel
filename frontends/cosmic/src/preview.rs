//! Opt-in debug-only native previews. Captures our own rendered window, never the desktop.
use super::{App, Details, Message, Notice, Page, view::ProfileRow};
use cosmic::app::Task;
use nm_tunnel_client::{ClientError, ConnectionState};
use nm_tunnel_subscription::parse_subscription;
use std::path::PathBuf;

#[derive(Clone)]
pub(super) struct Preview {
    state: String,
    capture: Option<PathBuf>,
    requested: bool,
    frames_seen: u8,
    scroll_bottom: bool,
    size: cosmic::iced::Size,
    pub theme: cosmic::Theme,
}

pub(super) const STATES: &[&str] = &[
    "storage-restored",
    "storage-restored-nodes",
    "storage-locked",
    "storage-failed",
    "storage-saving",
    "storage-unknown",
    "edit-active",
    "profile-settings",
    "profile-delete-waiting",
    "subscription-unsupported",
    "subscriptions-empty",
    "subscription-remove",
    "subscription-removed",
    "subscription-updated",
    "connections-uncertain",
    "profile-uncertain",
    "profile-saved",
    "profile-saved-active",
    "profile-delete-error",
    "profile-deleted",
    "subscriptions",
    "subscription-review",
    "subscription-settings",
    "edit",
    "edit-invalid",
    "delete-profile",
    "delete-active",
    "empty",
    "profiles",
    "long",
    "loading",
    "error",
    "search",
    "traffic",
    "details",
    "saved",
    "connected",
    "connecting",
    "disconnecting",
    "unknown",
    "multiple",
    "nm-unavailable",
    "backend-missing",
    "saved-search-empty",
    "saved-long",
    "profile-details",
    "profile-missing",
    "import-empty",
    "import-no-matches",
    "import-added",
    "import-saving",
    "import-uncertain",
    "import-error",
    "import-many",
    "import-page-two",
    "usage-missing",
    "usage-error",
    "usage-stale",
    "usage-zero",
    "usage-large",
    "usage-gaps",
    "failed",
    "details-stale",
    "import-reloading",
];

impl Preview {
    pub(super) fn from_env() -> Result<Option<Self>, &'static str> {
        let Some(state) = std::env::var_os("NM_TUNNEL_PREVIEW") else {
            if std::env::var_os("NM_TUNNEL_CAPTURE").is_some() {
                return Err("NM_TUNNEL_CAPTURE requires an explicit synthetic NM_TUNNEL_PREVIEW.");
            }
            return Ok(None);
        };
        let state = state.into_string().map_err(|_| "Invalid preview state.")?;
        if !STATES.contains(&state.as_str()) {
            return Err("Unknown synthetic preview state; see the frontend README.");
        }
        let capture = std::env::var_os("NM_TUNNEL_CAPTURE")
            .map(|name| {
                let name = name
                    .into_string()
                    .map_err(|_| "Invalid capture filename.")?;
                if name.len() > 64
                    || !name.ends_with(".png")
                    || name.starts_with('.')
                    || !name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
                {
                    return Err("Capture must be a simple PNG filename under target/ui/.");
                }
                Ok(PathBuf::from("target/ui").join(name))
            })
            .transpose()?;
        let size = if let Ok(value) = std::env::var("NM_TUNNEL_PREVIEW_SIZE") {
            let (width, height) = value
                .split_once('x')
                .ok_or("Preview size must be WIDTHxHEIGHT.")?;
            let width: u16 = width.parse().map_err(|_| "Invalid preview width.")?;
            let height: u16 = height.parse().map_err(|_| "Invalid preview height.")?;
            if !(520..=1600).contains(&width) || !(520..=1200).contains(&height) {
                return Err("Preview size must be between 520x520 and 1600x1200.");
            }
            cosmic::iced::Size::new(f32::from(width), f32::from(height))
        } else {
            cosmic::iced::Size::new(1024.0, 840.0)
        };
        Ok(Some(Self {
            state,
            capture,
            requested: false,
            frames_seen: 0,
            scroll_bottom: std::env::var("NM_TUNNEL_PREVIEW_SCROLL").as_deref() == Ok("bottom"),
            size,
            theme: match std::env::var("NM_TUNNEL_PREVIEW_THEME").as_deref() {
                Ok("light") => cosmic::Theme::light(),
                Ok("dark") | Err(_) => cosmic::Theme::dark(),
                Ok("light-hc") => cosmic::Theme::light_hc(),
                Ok("dark-hc") => cosmic::Theme::dark_hc(),
                _ => return Err("Preview theme must be light, dark, light-hc or dark-hc."),
            },
        }))
    }

    pub(super) fn seed(&self, app: &mut App) {
        if self.state.starts_with("storage-") {
            app.seed_preview_storage(&self.state);
        }
        if self.import_state() {
            app.page = Page::Import;
            app.sources.screen = super::subscriptions::Screen::Add;
        }
        app.snapshot = Some(nm_tunnel_client::Snapshot {
            profiles: vec![],
            active: vec![],
            backend_registered: self.state != "backend-missing",
        });
        if matches!(
            self.state.as_str(),
            "profiles"
                | "long"
                | "search"
                | "import-no-matches"
                | "import-added"
                | "import-saving"
                | "import-uncertain"
                | "import-error"
                | "import-many"
                | "import-page-two"
                | "import-reloading"
        ) {
            app.download.edit_source(
                "https://subscriptions.example/v1/synthetic-preview-token-not-a-credential"
                    .to_owned(),
            );
            let names = if self.state == "long" {
                [
                    "NetherlandsAmsterdamPremiumConnectionWithAnIntentionallyUnbrokenVeryLongNodeLabelForLayoutReview",
                    "Germany — Frankfurt — A second very long subscription profile label",
                    "Unsupported node with a long descriptive name",
                ]
            } else {
                [
                    "Netherlands · Amsterdam",
                    "Germany · Frankfurt",
                    "United States · New York",
                ]
            };
            let body = format!(
                "vless://12345678-1234-4234-8234-123456789abc@nl.example:443?security=tls&sni=www.example.com#{}\nvless://12345678-1234-4234-8234-123456789abd@de.example:443?security=tls&sni=www.example.com#{}\ntrojan://synthetic@us.example:443#{}",
                names[0], names[1], names[2]
            );
            if let Ok(list) = parse_subscription(body.as_bytes()) {
                app.catalog.subscription = Some(list);
                app.download
                    .choose_format(nm_tunnel_subscription::SubscriptionFormat::NodesOnly);
                app.catalog.admitted = true;
                app.catalog.selected = Some(0);
                app.status = crate::i18n::fl!("node-counts", supported = 2, unsupported = 1);
            }
        }
        if self.state == "search" {
            app.catalog.search = "Germany".into();
        }
        if self.state == "loading" {
            app.download
                .edit_source("https://subscriptions.example/synthetic-preview".to_owned());
            let _ = app.download.begin();
            app.status = crate::i18n::fl!("loading-subscription");
        }
        if self.state == "error" {
            app.status = crate::i18n::subscription_error(
                nm_tunnel_subscription::SubscriptionError::Download,
            );
            app.notice = Some(Notice::Error);
        }
        if !self.import_state()
            && !matches!(
                self.state.as_str(),
                "empty" | "nm-unavailable" | "backend-missing" | "usage-missing" | "usage-error"
            )
        {
            app.traffic.observe(Ok(Some(usage_sample())));
        }
        if matches!(self.state.as_str(), "details" | "details-stale") {
            app.details = Some(Details::Connection);
            app.core.set_show_context(true);
        }
        if self.state == "nm-unavailable" {
            app.snapshot = None;
            app.nm_error = Some(ClientError::Unavailable);
        }
        if self.state == "saved-search-empty" {
            app.saved_search = "No matching profile".into();
        }
        if self.state == "import-no-matches" {
            app.catalog.search = "No matching node".into();
        }
        if self.state == "import-added" {
            app.catalog.added.insert(0, "preview-added".into());
        }
        if self.state == "import-saving" {
            app.operations.begin_add(0);
            app.status = crate::i18n::fl!("saving-profile-status");
        }
        if self.state == "import-uncertain" {
            app.operations.begin_add(0);
            app.operations.finish_add(Some(ClientError::Timeout));
            app.notice = None;
            app.status = crate::i18n::client_error(ClientError::Timeout);
        }
        if self.state == "import-reloading" {
            let _ = app.download.begin();
        }
        if self.state == "import-error"
            && let Some((ticket, _, _)) = app.download.begin()
        {
            let _ = app.download.finish(
                ticket,
                Err(nm_tunnel_subscription::SubscriptionError::Download),
            );
        }
        if matches!(self.state.as_str(), "import-many" | "import-page-two") {
            let body = (0..49).map(|i| format!("vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=www.example.com#Node%20{i:02}")).collect::<Vec<_>>().join("\n");
            if let Ok(list) = parse_subscription(body.as_bytes()) {
                app.catalog.subscription = Some(list);
            }
            if self.state == "import-page-two" {
                app.catalog.page = 1;
            }
        }
        if self.state == "failed" {
            app.notice = Some(Notice::Error);
            app.status = crate::i18n::fl!("vpn-ended-status");
            if let Some(data) = &mut app.traffic.snapshot {
                data.live = false;
                data.state = "failed".into();
            }
        }
        if matches!(self.state.as_str(), "profile-details" | "profile-missing") {
            app.details = Some(Details::Profile(
                if self.state == "profile-details" {
                    "preview-b"
                } else {
                    "removed-profile"
                }
                .into(),
            ));
            app.core.set_show_context(true);
        }
        if self.state == "usage-error" {
            app.traffic
                .observe(Err(nm_tunnel_client::UsageError::Unavailable));
        }
        if (self.state.starts_with("usage-") || self.state == "details-stale")
            && let Some(data) = &mut app.traffic.snapshot
        {
            match self.state.as_str() {
                "usage-stale" | "details-stale" => {
                    data.live = false;
                    data.age_ms = 8500;
                    data.elapsed_ms += 8500;
                    let elapsed = data.elapsed_ms;
                    data.history
                        .retain(|sample| elapsed.saturating_sub(sample.elapsed_ms) <= 60_000);
                }
                "usage-zero" => {
                    data.counters = Default::default();
                    data.upload_bytes_per_second = 0;
                    data.download_bytes_per_second = 0;
                    for s in &mut data.history {
                        s.upload_bytes_per_second = 0;
                        s.download_bytes_per_second = 0;
                    }
                }
                "usage-large" => {
                    data.counters.download_bytes = u64::MAX;
                    data.counters.upload_bytes = 1 << 60;
                    data.download_bytes_per_second = 1 << 50;
                    for s in &mut data.history {
                        s.download_bytes_per_second = 1 << 50;
                    }
                }
                "usage-gaps" => data
                    .history
                    .retain(|s| !(15_000..35_000).contains(&s.elapsed_ms)),
                _ => {}
            }
        }
        if self.import_state() && app.catalog.subscription.is_some() {
            app.seed_preview_source();
        }
        if matches!(
            self.state.as_str(),
            "subscriptions"
                | "subscription-review"
                | "subscription-settings"
                | "subscription-remove"
                | "subscription-updated"
                | "subscription-unsupported"
        ) {
            app.page = Page::Import;
            let body = "vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example#North";
            if let Ok(list) = parse_subscription(body.as_bytes()) {
                app.catalog.admit(list);
            }
            app.seed_preview_source();
            if self.state == "subscriptions" {
                app.sources.screen = super::subscriptions::Screen::List;
            }
            let updated = "vless://12345678-1234-4234-8234-123456789abc@updated.example:443?security=tls&sni=peer.example#North\nvless://12345678-1234-4234-8234-123456789abd@south.example:443?security=tls&sni=peer.example#South";
            if self.state == "subscription-review"
                && let Ok(candidate) = parse_subscription(updated.as_bytes())
            {
                app.source_downloaded(Ok(candidate));
            }
            if self.state == "subscription-settings" {
                let _ = app.subscription_update(super::subscriptions::Action::Settings);
            }
            if self.state == "subscription-remove" {
                app.sources.screen = super::subscriptions::Screen::List;
                let _ = app.subscription_update(super::subscriptions::Action::AskRemove);
            }
            if self.state == "subscription-unsupported" {
                app.source_downloaded(Err(
                    nm_tunnel_subscription::SubscriptionError::UnsupportedPolicy(
                        nm_tunnel_subscription::PolicyIssue::Configuration,
                    ),
                ));
            }
            if self.state == "subscription-updated" {
                if let Ok(candidate) = parse_subscription(updated.as_bytes()) {
                    app.catalog.admit(candidate);
                }
                app.notice = Some(Notice::Info);
                app.status = crate::i18n::fl!("subscription-updated-status");
            }
        }
        if matches!(
            self.state.as_str(),
            "subscriptions-empty" | "subscription-removed"
        ) {
            app.page = Page::Import;
            if self.state == "subscription-removed" {
                app.notice = Some(Notice::Info);
                app.status = crate::i18n::fl!("subscription-removed-status");
            }
        }
        if matches!(
            self.state.as_str(),
            "connections-uncertain" | "profile-uncertain"
        ) {
            app.operations.begin_add(0);
            app.operations.finish_add(Some(ClientError::Timeout));
        }
        if matches!(
            self.state.as_str(),
            "profile-uncertain" | "profile-saved" | "profile-saved-active" | "profile-settings"
        ) {
            app.details = Some(Details::Profile("preview-a".into()));
            app.core.set_show_context(true);
            if matches!(
                self.state.as_str(),
                "profile-saved" | "profile-saved-active"
            ) {
                app.notice = Some(Notice::Info);
                app.status = crate::i18n::fl!("profile-settings-saved-status");
            }
        }
        if self.state == "profile-delete-error" {
            app.notice = Some(Notice::Error);
            app.status = crate::i18n::fl!("delete-disconnection-timeout");
        }
        if self.state == "profile-delete-waiting" {
            let _ = app.operations.begin_storage();
            app.status = crate::i18n::fl!("waiting-disconnection-status");
        }
        if self.state == "profile-deleted" {
            app.notice = Some(Notice::Info);
            app.status = crate::i18n::fl!("profile-deleted-status");
        }
        if matches!(self.state.as_str(), "edit" | "edit-invalid" | "edit-active") {
            app.editor = Some(super::profile_editor::Editor::preview(
                self.state == "edit-invalid",
            ));
        }
    }

    fn import_state(&self) -> bool {
        self.state.starts_with("import-")
            || matches!(
                self.state.as_str(),
                "profiles" | "long" | "loading" | "error" | "search"
            )
    }

    pub(super) fn active_count(&self) -> usize {
        match self.state.as_str() {
            "multiple" => 2,
            "connected"
            | "traffic"
            | "details"
            | "details-stale"
            | "connecting"
            | "disconnecting"
            | "unknown"
            | "profile-details"
            | "delete-active"
            | "profile-saved-active"
            | "profile-delete-error" => 1,
            "profile-delete-waiting" | "edit-active" => 1,
            s if s.starts_with("usage-") => 1,
            _ => 0,
        }
    }

    pub(super) fn disconnect_enabled(&self) -> bool {
        self.active_count() == 1 && self.state != "disconnecting"
    }

    pub(super) fn connection_title(&self) -> String {
        match self.state.as_str() {
            "nm-unavailable" => crate::i18n::fl!("nm-unavailable"),
            "connecting" => crate::i18n::fl!("connecting"),
            "disconnecting" | "profile-delete-waiting" => crate::i18n::fl!("disconnecting"),
            "unknown" => crate::i18n::fl!("unknown-connection-state"),
            "multiple" => crate::i18n::fl!("multiple-connections"),
            _ if self.active_count() == 1 => crate::i18n::fl!("connected"),
            _ => crate::i18n::fl!("disconnected"),
        }
    }

    pub(super) fn connection_hint(&self) -> String {
        match self.state.as_str() {
            "nm-unavailable" => crate::i18n::fl!("nm-read-failed"),
            "backend-missing" => crate::i18n::fl!("backend-unavailable"),
            "saved-long" => {
                "A synthetic profile with a deliberately long name for responsive layout review"
                    .into()
            }
            "multiple" => crate::i18n::fl!("manage-in-nm"),
            _ if self.active_count() == 1 => "North · Amsterdam".into(),
            _ => String::new(),
        }
    }

    pub(super) fn profile_rows(&self) -> Option<Vec<ProfileRow<'static>>> {
        if self.state == "nm-unavailable" {
            return None;
        }
        if self.import_state() || self.state == "empty" {
            return Some(vec![]);
        }
        let state = match self.state.as_str() {
            "connecting" => Some(ConnectionState::Connecting),
            "disconnecting" | "profile-delete-waiting" => Some(ConnectionState::Disconnecting),
            "unknown" => Some(ConnectionState::Unknown),
            _ if self.active_count() > 0 => Some(ConnectionState::Connected),
            _ => None,
        };
        let mut rows = vec![
            ProfileRow {
                id: "preview-a",
                name: if self.state == "saved-long" {
                    "NorthAmsterdamPremiumConnectionWithAnIntentionallyUnbrokenVeryLongProfileNameForLayoutReview"
                } else {
                    "North · Amsterdam"
                },
                persistent: true,
                dns_override: nm_tunnel_profile::DnsOverride::Inherit,
                lan_bypass: false,
                private_lan_bypass: false,
                dns_interception: false,
                fake_ip: false,
                source_policy: false,
                state,
            },
            ProfileRow {
                id: "preview-b",
                name: "West · Frankfurt",
                persistent: false,
                dns_override: nm_tunnel_profile::DnsOverride::CurrentNetwork,
                lan_bypass: true,
                private_lan_bypass: false,
                dns_interception: false,
                fake_ip: false,
                source_policy: false,
                state: (self.state == "multiple").then_some(ConnectionState::Connected),
            },
            ProfileRow {
                id: "preview-c",
                name: "Coast · Helsinki",
                persistent: true,
                dns_override: nm_tunnel_profile::DnsOverride::Inherit,
                lan_bypass: false,
                private_lan_bypass: false,
                dns_interception: true,
                fake_ip: true,
                source_policy: false,
                state: None,
            },
        ];
        if self.state == "profile-deleted" {
            rows.retain(|row| row.id != "preview-a");
        }
        Some(rows)
    }

    pub(super) fn needs_capture(&self) -> bool {
        self.capture.is_some() && !self.requested
    }
    pub(super) fn size(&self) -> cosmic::iced::Size {
        self.size
    }
    pub(super) fn dialog(&self) -> Option<cosmic::Element<'static, Message>> {
        matches!(self.state.as_str(), "delete-profile" | "delete-active").then(|| {
            super::profile_editor::delete_confirmation("North · TCP", self.state == "delete-active")
        })
    }
}

pub(super) fn update(app: &mut App, message: Message) -> Task<Message> {
    match message {
        Message::Source(value)
            if app.sources.screen == super::subscriptions::Screen::Add
                && !app.operations.busy()
                && app.download.pending().is_none() =>
        {
            if app.download.edit_source(value) {
                app.catalog.invalidate();
            }
        }
        Message::FetchComplete(complete)
            if app.sources.screen == super::subscriptions::Screen::Add
                && !app.operations.busy()
                && app.download.pending().is_none() =>
        {
            let format = if complete {
                nm_tunnel_subscription::SubscriptionFormat::Complete
            } else {
                nm_tunnel_subscription::SubscriptionFormat::NodesOnly
            };
            if app.download.choose_format(format) {
                app.catalog.invalidate();
            }
        }
        Message::Profile(
            action @ (super::profile_editor::Action::Name(_)
            | super::profile_editor::Action::Dns(_)
            | super::profile_editor::Action::Manual(_)
            | super::profile_editor::Action::Lan(_)
            | super::profile_editor::Action::Intercept(_)
            | super::profile_editor::Action::FakeIp(_)
            | super::profile_editor::Action::Cancel),
        ) => return app.profile_update(action),
        Message::Subscription(
            action @ (super::subscriptions::Action::Scrolled(..)
            | super::subscriptions::Action::New
            | super::subscriptions::Action::Back
            | super::subscriptions::Action::Open(_)
            | super::subscriptions::Action::Name(_)
            | super::subscriptions::Action::Settings
            | super::subscriptions::Action::CloseSettings
            | super::subscriptions::Action::Rename(_)
            | super::subscriptions::Action::Url(_)
            | super::subscriptions::Action::AskRemove
            | super::subscriptions::Action::CancelRemove
            | super::subscriptions::Action::Remove
            | super::subscriptions::Action::CancelReview
            | super::subscriptions::Action::Map(_, _)),
        ) => return app.subscription_update(action),
        Message::Navigate(page) => {
            app.editor = None;
            app.sources.settings = false;
            app.page = page;
            app.navigation.select(page);
            app.details = None;
            app.core.set_show_context(false);
            return app.restore_page_scroll();
        }
        Message::PageScrolled(page, offset) => app.navigation.remember_scroll(page, offset),
        Message::CloseDetails => {
            app.details = None;
            app.core.set_show_context(false);
            return app.restore_page_scroll();
        }
        Message::ShowDetails(profile) => {
            app.sources.settings = false;
            app.details = Some(profile.map_or(Details::Connection, Details::Profile));
            app.core.set_show_context(true);
        }
        Message::SearchProfiles(value) => {
            app.catalog.search(value);
        }
        Message::SearchSaved(value) => app.saved_search = value.chars().take(128).collect(),
        Message::Frame(id) if app.core.main_window_id() == Some(id) => {
            if let Some(preview) = &mut app.preview
                && preview.needs_capture()
            {
                // Allow layout/theme/font state to survive an additional redraw.
                // Frame messages drive redraws; no timing sleeps are involved.
                if preview.frames_seen < 2 {
                    if preview.frames_seen == 0 && preview.scroll_bottom {
                        preview.frames_seen += 1;
                        return cosmic::iced::widget::scrollable::snap_to(
                            cosmic::widget::Id::new(match app.page {
                                Page::Connections => "connections-page",
                                Page::Import => "import-page",
                            }),
                            cosmic::iced::widget::scrollable::RelativeOffset {
                                x: Some(0.0),
                                y: Some(1.0),
                            },
                        );
                    }
                    preview.frames_seen += 1;
                    return Task::none();
                }
                preview.requested = true;
                return cosmic::iced::window::screenshot(id)
                    .map(|screenshot| cosmic::Action::App(Message::Captured(screenshot)));
            }
        }
        Message::Captured(screenshot) => {
            if let Some(path) = app
                .preview
                .as_ref()
                .and_then(|preview| preview.capture.as_ref())
            {
                let result = std::fs::create_dir_all("target/ui")
                    .map_err(|error| error.to_string())
                    .and_then(|()| {
                        image::save_buffer_with_format(
                            path,
                            &screenshot.rgba,
                            screenshot.size.width,
                            screenshot.size.height,
                            image::ColorType::Rgba8,
                            image::ImageFormat::Png,
                        )
                        .map_err(|error| error.to_string())
                    });
                match result {
                    Ok(()) => println!(
                        "Saved own-window capture: {} ({} × {})",
                        path.display(),
                        screenshot.size.width,
                        screenshot.size.height
                    ),
                    Err(error) => {
                        eprintln!("Capture failed: {error}");
                        std::process::exit(1);
                    }
                }
                // Follow the native window lifecycle so the compositor releases
                // its surface/renderer before the event loop exits. Do not bypass
                // renderer teardown with process::exit after producing a PNG.
                return app
                    .core
                    .main_window_id()
                    .map_or_else(cosmic::iced::exit, cosmic::iced::window::close);
            }
        }
        // Synthetic previews never execute HTTP or NetworkManager actions.
        _ => {}
    }
    Task::none()
}

pub(super) fn usage_sample() -> nm_tunnel_client::UsageSnapshot {
    use nm_tunnel_client::{TrafficCounters, TrafficSample, UsageSnapshot};
    UsageSnapshot {
        version: 1,
        generation: 1,
        state: "running".into(),
        setup_stage: "ready".into(),
        worker_stage: 7,
        elapsed_ms: 60_000,
        available: true,
        live: true,
        age_ms: 0,
        counters: TrafficCounters {
            upload_bytes: 84_000_000,
            download_bytes: 1_240_000_000,
            tcp_active: 18,
            udp_active: 4,
            ..TrafficCounters::default()
        },
        upload_bytes_per_second: 640 * 1024,
        download_bytes_per_second: 12_400_000,
        history: (0..=60)
            .map(|i| TrafficSample {
                elapsed_ms: i * 1000,
                counters: TrafficCounters::default(),
                download_bytes_per_second: 5_000_000 + (i * 712_371 % 11_000_000),
                upload_bytes_per_second: 200_000 + (i * 17_333 % 700_000),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmic::Application;

    #[test]
    fn every_synthetic_scene_builds_without_actionable_handles_or_dispatched_reads() {
        for state in STATES {
            let preview = Preview {
                state: (*state).into(),
                capture: None,
                requested: false,
                frames_seen: 0,
                scroll_bottom: false,
                size: cosmic::iced::Size::new(1024.0, 840.0),
                theme: cosmic::Theme::dark(),
            };
            let (app, _) = App::init(
                cosmic::Core::default(),
                super::super::Flags {
                    preview: Some(preview),
                },
            );
            let _ = app.view();
            let _ = app.context_drawer();
            let _ = app.dialog();
            assert!(
                app.snapshot.as_ref().is_none_or(
                    |snapshot| snapshot.profiles.is_empty() && snapshot.active.is_empty()
                ) && app.saved_selected.is_none(),
                "{state}"
            );
            assert!(app.reads.nm.pending().is_none(), "{state}");
            assert!(
                app.profile_save.is_none() && app.deletion.is_none(),
                "{state}"
            );
        }
    }

    #[test]
    fn primary_chart_requires_one_observed_connected_profile_not_a_live_old_backend_sample() {
        for state in [
            "connected",
            "connecting",
            "disconnecting",
            "unknown",
            "multiple",
            "saved",
        ] {
            let preview = Preview {
                state: state.into(),
                capture: None,
                requested: false,
                frames_seen: 0,
                scroll_bottom: false,
                size: cosmic::iced::Size::new(1024.0, 840.0),
                theme: cosmic::Theme::dark(),
            };
            let (app, _) = App::init(
                cosmic::Core::default(),
                super::super::Flags {
                    preview: Some(preview),
                },
            );
            assert_eq!(app.show_traffic_chart(), state == "connected", "{state}");
            assert!(
                app.traffic
                    .snapshot
                    .as_ref()
                    .is_some_and(|sample| sample.available)
            );
        }
    }

    #[test]
    fn synthetic_profile_and_source_actions_never_dispatch_nm_or_http_even_after_url_edits() {
        let preview = Preview {
            state: "subscription-settings".into(),
            capture: None,
            requested: false,
            frames_seen: 0,
            scroll_bottom: false,
            size: cosmic::iced::Size::new(1024.0, 840.0),
            theme: cosmic::Theme::dark(),
        };
        let (mut app, _) = App::init(
            cosmic::Core::default(),
            super::super::Flags {
                preview: Some(preview),
            },
        );
        let _ = app.update(Message::Subscription(
            super::super::subscriptions::Action::Url(
                "https://changed.example/synthetic-token".into(),
            ),
        ));
        for message in [
            Message::Subscription(super::super::subscriptions::Action::Add),
            Message::Load,
            Message::Subscription(super::super::subscriptions::Action::SaveSettings),
            Message::Subscription(super::super::subscriptions::Action::Update),
            Message::Subscription(super::super::subscriptions::Action::Apply),
            Message::Profile(super::super::profile_editor::Action::Save),
            Message::Profile(super::super::profile_editor::Action::ConfirmDelete),
            Message::Connect,
            Message::Disconnect,
            Message::Poll,
            Message::Tick,
        ] {
            let _ = app.update(message);
            assert!(app.download.pending().is_none());
            assert!(!app.operations.busy());
            assert!(app.operations.control().is_none());
            assert!(app.profile_save.is_none() && app.deletion.is_none());
            assert!(app.reads.nm.pending().is_none());
        }
        let _ = app.update(Message::Subscription(
            super::super::subscriptions::Action::New,
        ));
        let source = "https://subscriptions.example/synthetic-native-lab";
        let _ = app.update(Message::Source(source.into()));
        assert_eq!(
            secrecy::ExposeSecret::expose_secret(app.download.source()),
            source
        );
        let _ = app.update(Message::FetchComplete(false));
        assert_eq!(
            app.download.format(),
            nm_tunnel_subscription::SubscriptionFormat::NodesOnly
        );
        let _ = app.update(Message::Load);
        assert!(app.download.pending().is_none() && !app.operations.busy());
        assert!(app.reads.nm.pending().is_none());
    }
}
