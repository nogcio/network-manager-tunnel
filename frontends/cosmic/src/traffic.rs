//! Independent, read-only usage observation and a theme-owned sixty-second chart.
use super::{App, Message};
use crate::i18n::fl;
use cosmic::{
    Element,
    app::Task,
    iced::{Alignment, Length, Point, Rectangle, mouse},
    theme,
    widget::{self, canvas},
};
use nm_tunnel_client::{UsageError, UsageSnapshot};
use std::time::Instant;

#[derive(Default)]
pub(super) struct Traffic {
    pub snapshot: Option<UsageSnapshot>,
    received: Option<Instant>,
    error: Option<UsageError>,
    queried: bool,
}

impl Traffic {
    pub fn observe(&mut self, result: Result<Option<UsageSnapshot>, UsageError>) {
        self.queried = true;
        self.error = result.as_ref().err().copied();
        self.snapshot = result.ok().flatten();
        self.received = self.snapshot.as_ref().map(|_| Instant::now());
    }

    fn elapsed(&self) -> u64 {
        self.received.map_or(0, |time| {
            time.elapsed().as_millis().min(u64::MAX as u128) as u64
        })
    }

    pub fn live(&self) -> bool {
        self.snapshot.as_ref().is_some_and(|s| {
            s.available && s.live && s.age_ms.saturating_add(self.elapsed()) <= 3000
        })
    }

    pub fn freshness(&self) -> String {
        match &self.snapshot {
            Some(s) if !s.available => fl!("waiting-statistics"),
            Some(_) if self.live() => fl!("updated-just-now"),
            Some(s) => fl!(
                "sample-not-live",
                seconds = s.age_ms.saturating_add(self.elapsed()) / 1000
            ),
            None if !self.queried => fl!("checking-statistics"),
            None => self
                .error
                .map_or_else(|| fl!("backend-not-running"), crate::i18n::usage_error),
        }
    }
}

/// Binary units are explicit and independent of locale; never show non-finite values.
pub(super) fn bytes(value: u64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    let mut amount = value as f64;
    let mut unit = 0;
    while amount >= 1024.0 && unit + 1 < units.len() {
        amount /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value} B")
    } else {
        format!("{amount:.1} {}", units[unit])
    }
}

impl App {
    pub(super) fn poll_usage(&mut self) -> Task<Message> {
        let Some(ticket) = self.reads.begin_usage() else {
            return Task::none();
        };
        cosmic::task::future(async move {
            Message::UsageObserved(ticket, nm_tunnel_client::usage_snapshot().await)
        })
    }

    pub(super) fn traffic_view(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let live = self.traffic.live();
        let data = self.traffic.snapshot.as_ref().filter(|s| s.available);
        let metric = |label: String, rate: Option<u64>| {
            widget::column::with_capacity(2)
                .spacing(spacing.space_xxxs)
                .push(widget::text::caption(label))
                .push(widget::text::title4(
                    rate.map_or("—".into(), |v| format!("{}/s", bytes(v))),
                ))
        };
        let metrics = widget::flex_row(vec![
            metric(
                fl!("download-legend"),
                data.filter(|_| live).map(|s| s.download_bytes_per_second),
            )
            .into(),
            metric(
                fl!("upload-legend"),
                data.filter(|_| live).map(|s| s.upload_bytes_per_second),
            )
            .into(),
        ])
        .spacing(spacing.space_l)
        .min_item_width(180.0);
        let totals = data.map_or_else(
            || fl!("no-traffic"),
            |s| {
                fl!(
                    "last-attempt-traffic",
                    download = bytes(s.counters.download_bytes),
                    upload = bytes(s.counters.upload_bytes)
                )
            },
        );
        let mut graph = widget::column::with_capacity(3)
            .spacing(spacing.space_s)
            .push(metrics);
        if !live {
            graph = graph.push(widget::text::caption(self.traffic.freshness()));
        }
        let section = widget::settings::section()
            .header(
                widget::row::with_capacity(2)
                    .align_y(Alignment::Center)
                    .push(widget::text::heading(fl!("traffic")).width(Length::Fill))
                    .push(
                        widget::button::text(fl!("details")).on_press(Message::ShowDetails(None)),
                    ),
            )
            .add(
                graph.push(
                    widget::canvas(Chart {
                        traffic: &self.traffic,
                    })
                    .height(145.0)
                    .width(Length::Fill),
                ),
            )
            .add(widget::text::body(totals));
        section.into()
    }
}

struct Chart<'a> {
    traffic: &'a Traffic,
}

fn chart_segments(
    history: &[nm_tunnel_client::TrafficSample],
    now: u64,
) -> Vec<Vec<&nm_tunnel_client::TrafficSample>> {
    let mut groups: Vec<Vec<&nm_tunnel_client::TrafficSample>> = Vec::new();
    for sample in history
        .iter()
        .filter(|s| s.elapsed_ms <= now && now - s.elapsed_ms <= 60_000)
    {
        match groups.last_mut() {
            Some(group)
                if group.last().is_some_and(|previous| {
                    sample.elapsed_ms.saturating_sub(previous.elapsed_ms) <= 3000
                }) =>
            {
                group.push(sample)
            }
            _ => groups.push(vec![sample]),
        }
    }
    groups
}

impl canvas::Program<Message, cosmic::Theme, cosmic::Renderer> for Chart<'_> {
    type State = ();
    fn draw(
        &self,
        _: &(),
        renderer: &cosmic::Renderer,
        theme: &cosmic::Theme,
        bounds: Rectangle,
        _: mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        let cosmic = theme.cosmic();
        let divider = cosmic.bg_component_divider().into();
        let accent = cosmic.accent_color().into();
        let color = cosmic.on_bg_color().into();
        let width = (bounds.width - 85.0).max(1.0);
        let height = (bounds.height - 24.0).max(1.0);
        let now = self
            .traffic
            .snapshot
            .as_ref()
            .map_or(0, |s| s.elapsed_ms.saturating_add(self.traffic.elapsed()));
        let segments = self
            .traffic
            .snapshot
            .as_ref()
            .map(|s| chart_segments(&s.history, now))
            .unwrap_or_default();
        let peak = segments
            .iter()
            .flatten()
            .map(|s| s.download_bytes_per_second.max(s.upload_bytes_per_second))
            .max()
            .unwrap_or(0)
            .max(1024);
        let scale = 2_f64.powf((peak as f64).log2().ceil());
        for fraction in [0.0, 0.5, 1.0] {
            let y = height * fraction;
            frame.stroke(
                &canvas::Path::line(Point::new(0.0, y), Point::new(width, y)),
                canvas::Stroke::default().with_color(divider),
            );
            let mut text = canvas::Text::from(format!(
                "{}/s",
                bytes((scale * f64::from(1.0 - fraction)) as u64)
            ));
            text.position = Point::new(width + 8.0, (y - 6.0).max(0.0));
            text.color = color;
            text.size = 11.0.into();
            frame.fill_text(text);
        }
        for (label, x) in [
            (fl!("sixty-seconds-ago"), 0.0),
            (fl!("thirty-seconds"), width / 2.0),
            (fl!("now"), (width - 45.0).max(0.0)),
        ] {
            let mut text = canvas::Text::from(label);
            text.position = Point::new(x, height + 8.0);
            text.color = color;
            text.size = 11.0.into();
            frame.fill_text(text);
        }
        for upload in [false, true] {
            for samples in &segments {
                let path = canvas::Path::new(|builder| {
                    for (index, sample) in samples.iter().enumerate() {
                        let value = if upload {
                            sample.upload_bytes_per_second
                        } else {
                            sample.download_bytes_per_second
                        };
                        let point = Point::new(
                            width * (1.0 - now.saturating_sub(sample.elapsed_ms) as f32 / 60_000.0),
                            height * (1.0 - (value as f64 / scale) as f32),
                        );
                        if index > 0 {
                            builder.line_to(point);
                        } else {
                            builder.move_to(point);
                        }
                    }
                });
                let mut stroke = canvas::Stroke::default().with_color(accent).with_width(2.0);
                if upload {
                    stroke.line_dash = canvas::LineDash {
                        segments: &[4.0, 4.0],
                        offset: 0,
                    };
                }
                frame.stroke(&path, stroke);
            }
        }
        vec![frame.into_geometry()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn traffic_units_are_explicit_and_bounded() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(1024), "1.0 KiB");
        assert_eq!(bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(bytes(u64::MAX), "16.0 EiB");
    }

    #[test]
    fn graph_never_connects_missing_samples_or_moves_stale_samples_to_now() {
        use nm_tunnel_client::{TrafficCounters, TrafficSample};
        let history: Vec<_> = [0, 1000, 5000, 6000]
            .into_iter()
            .map(|elapsed_ms| TrafficSample {
                elapsed_ms,
                counters: TrafficCounters::default(),
                upload_bytes_per_second: 1,
                download_bytes_per_second: 2,
            })
            .collect();
        let groups = chart_segments(&history, 14_500);
        assert_eq!(groups.iter().map(Vec::len).collect::<Vec<_>>(), [2, 2]);
        assert_eq!(groups[1][1].elapsed_ms, 6000);
        assert_eq!(14_500 - groups[1][1].elapsed_ms, 8500);
        assert!(chart_segments(&history, 66_001).is_empty());
    }

    #[test]
    fn local_age_prevents_a_frozen_ui_snapshot_from_claiming_live_rates() {
        let mut traffic = Traffic::default();
        assert_eq!(traffic.freshness(), "Checking backend statistics…");
        let data = UsageSnapshot {
            version: 1,
            generation: 1,
            state: "running".into(),
            setup_stage: "ready".into(),
            worker_stage: 7,
            elapsed_ms: 1000,
            available: true,
            live: true,
            age_ms: 0,
            counters: nm_tunnel_client::TrafficCounters {
                download_bytes: 42,
                ..Default::default()
            },
            upload_bytes_per_second: 0,
            download_bytes_per_second: 42,
            history: vec![],
        };
        traffic.observe(Ok(Some(data)));
        assert!(traffic.live());
        traffic.received = Instant::now().checked_sub(std::time::Duration::from_secs(4));
        assert!(!traffic.live());
        assert!(traffic.freshness().contains("not live"));
        assert_eq!(
            traffic.snapshot.as_ref().map(|s| s.counters.download_bytes),
            Some(42)
        );
        traffic.observe(Ok(None));
        assert!(traffic.snapshot.is_none());
        assert_eq!(traffic.freshness(), "Backend is not running");
    }
}
