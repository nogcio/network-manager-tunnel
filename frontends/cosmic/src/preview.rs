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
            cosmic::iced::Size::new(760.0, 780.0)
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
        if self.import_state() {
            app.page = Page::Import;
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
            app.source = secrecy::SecretString::from(
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
                app.subscription = Some(list);
                app.selected = Some(0);
                app.status = "2 available, 1 unsupported. Nothing has been connected.".into();
            }
        }
        if self.state == "search" {
            app.profile_search = "Germany".into();
        }
        if self.state == "loading" {
            app.source = secrecy::SecretString::from(
                "https://subscriptions.example/synthetic-preview".to_owned(),
            );
            app.fetching = true;
            app.status = "Loading subscription…".into();
        }
        if self.state == "error" {
            app.status = "Could not load the subscription. Check the URL and try again.".into();
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
            app.profile_search = "No matching node".into();
        }
        if self.state == "import-added" {
            app.added.insert(0, "preview-added".into());
        }
        if self.state == "import-saving" {
            app.busy = true;
            app.status = "Adding profile…".into();
        }
        if self.state == "import-uncertain" {
            app.uncertain = true;
            app.notice = None;
            app.status = ClientError::Timeout.to_string();
        }
        if self.state == "import-reloading" {
            app.fetching = true;
        }
        if self.state == "import-error" {
            app.load_error = Some(nm_tunnel_subscription::SubscriptionError::Download);
        }
        if matches!(self.state.as_str(), "import-many" | "import-page-two") {
            let body = (0..49).map(|i| format!("vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=www.example.com#Node%20{i:02}")).collect::<Vec<_>>().join("\n");
            if let Ok(list) = parse_subscription(body.as_bytes()) {
                app.subscription = Some(list);
            }
            if self.state == "import-page-two" {
                app.profile_page = 1;
            }
        }
        if self.state == "failed" {
            app.notice = Some(Notice::Error);
            app.status = "VPN activation failed. Network protection may remain enabled.".into();
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
            "connected" | "traffic" | "details" | "details-stale" | "connecting"
            | "disconnecting" | "unknown" | "profile-details" => 1,
            s if s.starts_with("usage-") => 1,
            _ => 0,
        }
    }

    pub(super) fn disconnect_enabled(&self) -> bool {
        self.active_count() == 1 && self.state != "disconnecting"
    }

    pub(super) fn connection_title(&self) -> &'static str {
        match self.state.as_str() {
            "nm-unavailable" => "NetworkManager unavailable",
            "connecting" => "Connecting…",
            "disconnecting" => "Disconnecting…",
            "unknown" => "Unknown connection state",
            "multiple" => "Multiple VPN connections",
            _ if self.active_count() == 1 => "Connected",
            _ => "Disconnected",
        }
    }

    pub(super) fn connection_hint(&self) -> &'static str {
        match self.state.as_str() {
            "nm-unavailable" => "Could not read NetworkManager state.",
            "backend-missing" => "VPN backend unavailable",
            "saved-long" => {
                "A synthetic profile with a deliberately long name for responsive layout review"
            }
            "multiple" => "Two active connections",
            _ if self.active_count() == 1 => "North · Amsterdam",
            _ => "",
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
            "disconnecting" => Some(ConnectionState::Disconnecting),
            "unknown" => Some(ConnectionState::Unknown),
            _ if self.active_count() > 0 => Some(ConnectionState::Connected),
            _ => None,
        };
        Some(vec![
            ProfileRow {
                id: "preview-a",
                name: if self.state == "saved-long" {
                    "NorthAmsterdamPremiumConnectionWithAnIntentionallyUnbrokenVeryLongProfileNameForLayoutReview"
                } else {
                    "North · Amsterdam"
                },
                persistent: true,
                state,
            },
            ProfileRow {
                id: "preview-b",
                name: "West · Frankfurt",
                persistent: false,
                state: (self.state == "multiple").then_some(ConnectionState::Connected),
            },
            ProfileRow {
                id: "preview-c",
                name: "Coast · Helsinki",
                persistent: true,
                state: None,
            },
        ])
    }

    pub(super) fn needs_capture(&self) -> bool {
        self.capture.is_some() && !self.requested
    }
    pub(super) fn size(&self) -> cosmic::iced::Size {
        self.size
    }
}

pub(super) fn update(app: &mut App, message: Message) -> Task<Message> {
    match message {
        Message::Navigate(page) => {
            app.page = page;
            app.details = None;
            app.core.set_show_context(false);
        }
        Message::CloseDetails => {
            app.details = None;
            app.core.set_show_context(false);
        }
        Message::ShowDetails(_) => {
            app.details = Some(Details::Connection);
            app.core.set_show_context(true);
        }
        Message::SearchProfiles(value) => {
            app.profile_search = value.chars().take(128).collect();
            app.profile_page = 0;
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
                return cosmic::iced::exit();
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
