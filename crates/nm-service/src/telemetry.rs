//! Read-only, bounded, in-memory observations. Never a lifecycle or guard owner.
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::{net::UnixDatagram, time::Instant};
use zbus::zvariant::Type;

#[cfg(test)]
pub(crate) const INTERFACE: &str = "org.freedesktop.NetworkManager.tunnel.Telemetry";
const WINDOW_MS: u64 = 60_000;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, Type, PartialEq)]
pub(crate) struct Counters {
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub upload_packets: u64,
    pub download_packets: u64,
    pub tcp_active: u64,
    pub udp_active: u64,
    pub tcp_opened: u64,
    pub udp_opened: u64,
    pub tcp_failed: u64,
    pub udp_failed: u64,
    pub dropped_packets: u64,
}

#[derive(Default)]
pub(crate) struct Meter {
    upload_bytes: AtomicU64,
    download_bytes: AtomicU64,
    upload_packets: AtomicU64,
    download_packets: AtomicU64,
    tcp_active: AtomicU64,
    udp_active: AtomicU64,
    tcp_opened: AtomicU64,
    udp_opened: AtomicU64,
    tcp_failed: AtomicU64,
    udp_failed: AtomicU64,
    dropped_packets: AtomicU64,
}

impl Meter {
    pub fn packet(&self, upload: bool, bytes: usize) {
        let (total, packets) = if upload {
            (&self.upload_bytes, &self.upload_packets)
        } else {
            (&self.download_bytes, &self.download_packets)
        };
        total.fetch_add(bytes as u64, Ordering::Relaxed);
        packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dropped(&self) {
        self.dropped_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn flow(self: &Arc<Self>, tcp: bool) -> Flow {
        let (active, opened) = if tcp {
            (&self.tcp_active, &self.tcp_opened)
        } else {
            (&self.udp_active, &self.udp_opened)
        };
        active.fetch_add(1, Ordering::Relaxed);
        opened.fetch_add(1, Ordering::Relaxed);
        Flow {
            meter: Arc::clone(self),
            tcp,
        }
    }

    fn snapshot(&self) -> Counters {
        Counters {
            upload_bytes: self.upload_bytes.load(Ordering::Relaxed),
            download_bytes: self.download_bytes.load(Ordering::Relaxed),
            upload_packets: self.upload_packets.load(Ordering::Relaxed),
            download_packets: self.download_packets.load(Ordering::Relaxed),
            tcp_active: self.tcp_active.load(Ordering::Relaxed),
            udp_active: self.udp_active.load(Ordering::Relaxed),
            tcp_opened: self.tcp_opened.load(Ordering::Relaxed),
            udp_opened: self.udp_opened.load(Ordering::Relaxed),
            tcp_failed: self.tcp_failed.load(Ordering::Relaxed),
            udp_failed: self.udp_failed.load(Ordering::Relaxed),
            dropped_packets: self.dropped_packets.load(Ordering::Relaxed),
        }
    }
}

pub(crate) struct Flow {
    meter: Arc<Meter>,
    tcp: bool,
}
impl Flow {
    pub fn failed(&self) {
        let counter = if self.tcp {
            &self.meter.tcp_failed
        } else {
            &self.meter.udp_failed
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}
impl Drop for Flow {
    fn drop(&mut self) {
        let counter = if self.tcp {
            &self.meter.tcp_active
        } else {
            &self.meter.udp_active
        };
        counter.fetch_sub(1, Ordering::Relaxed);
    }
}

impl nm_tunnel_dataplane::runtime::Observer for Meter {
    type Flow = Flow;
    fn packet(&self, upload: bool, bytes: usize) {
        self.packet(upload, bytes);
    }
    fn dropped(&self) {
        self.dropped();
    }
    fn flow(self: &Arc<Self>, tcp: bool) -> Flow {
        self.flow(tcp)
    }
}

impl nm_tunnel_dataplane::runtime::Flow for Flow {
    fn failed(&self) {
        self.failed();
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Report {
    stage: u8,
    counters: Counters,
}

/// Best effort datagrams on a distinct inherited FD: never wait on the FD broker
/// or backpressure packet processing. Lost samples are reflected in sample age.
pub(crate) async fn publish(socket: Arc<UnixDatagram>, meter: Arc<Meter>) {
    let mut timer = tokio::time::interval(std::time::Duration::from_secs(1));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        timer.tick().await;
        let report = Report {
            stage: crate::worker::STAGE.load(Ordering::Relaxed),
            counters: meter.snapshot(),
        };
        if let Ok(bytes) = serde_json::to_vec(&report) {
            let _ = socket.try_send(&bytes);
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Type)]
pub(crate) struct Sample {
    pub elapsed_ms: u64,
    pub counters: Counters,
    pub upload_bytes_per_second: u64,
    pub download_bytes_per_second: u64,
}

#[derive(Debug, Deserialize, Serialize, Type)]
pub(crate) struct Snapshot {
    pub version: u32,
    pub generation: u64,
    pub state: String,
    pub setup_stage: String,
    pub worker_stage: u8,
    pub elapsed_ms: u64,
    pub available: bool,
    pub live: bool,
    pub age_ms: u64,
    pub counters: Counters,
    pub upload_bytes_per_second: u64,
    pub download_bytes_per_second: u64,
    pub history: Vec<Sample>,
}

struct Store {
    generation: u64,
    started: Instant,
    state: &'static str,
    stage: &'static str,
    worker_stage: u8,
    receiving: bool,
    last: Option<Instant>,
    history: VecDeque<Sample>,
}

#[derive(Clone)]
pub(crate) struct Telemetry(Arc<Mutex<Store>>);

impl Default for Telemetry {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(Store {
            generation: 0,
            started: Instant::now(),
            state: "idle",
            stage: "idle",
            worker_stage: 0,
            receiving: false,
            last: None,
            history: VecDeque::new(),
        })))
    }
}

fn millis(duration: std::time::Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

impl Telemetry {
    fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn begin(&self) {
        let mut store = self.store();
        store.generation = store.generation.saturating_add(1);
        store.started = Instant::now();
        store.state = "connecting";
        store.stage = "uplink";
        store.worker_stage = 0;
        store.receiving = true;
        store.last = None;
        store.history.clear();
    }

    pub fn stage(&self, stage: &'static str) {
        self.store().stage = stage;
    }

    pub fn worker_stage(&self, stage: u8) {
        self.store().worker_stage = stage;
    }

    pub fn state(&self, state: &'static str) {
        let mut store = self.store();
        store.state = state;
        if matches!(state, "failed" | "stopped" | "stopping") {
            store.receiving = false;
        }
    }

    fn observe(&self, report: Report) {
        let mut store = self.store();
        if !store.receiving {
            return;
        }
        let elapsed_ms = millis(store.started.elapsed());
        let previous = store.history.back();
        let rate = |bytes: u64, old: u64, delta: u64| {
            bytes.saturating_sub(old).saturating_mul(1000) / delta.max(1)
        };
        let (upload, download) = previous.map_or((0, 0), |old| {
            let delta = elapsed_ms.saturating_sub(old.elapsed_ms);
            (
                rate(
                    report.counters.upload_bytes,
                    old.counters.upload_bytes,
                    delta,
                ),
                rate(
                    report.counters.download_bytes,
                    old.counters.download_bytes,
                    delta,
                ),
            )
        });
        store.worker_stage = report.stage;
        store.last = Some(Instant::now());
        store.history.push_back(Sample {
            elapsed_ms,
            counters: report.counters,
            upload_bytes_per_second: upload,
            download_bytes_per_second: download,
        });
        while store.history.len() > 61
            || store
                .history
                .front()
                .is_some_and(|s| elapsed_ms.saturating_sub(s.elapsed_ms) > WINDOW_MS)
        {
            store.history.pop_front();
        }
    }

    pub async fn receive(&self, socket: UnixDatagram) -> io::Result<()> {
        let mut buffer = [0; 2048];
        loop {
            let length = socket.recv(&mut buffer).await?;
            if let Ok(report) = serde_json::from_slice::<crate::health::Report>(&buffer[..length]) {
                if report.health && report.stage <= 14 {
                    eprintln!(
                        "VPN health: failures={}, stage={}, elapsed_ms={}, reason={:?}, fatal={}; session protection retained.",
                        report.failures,
                        report.stage,
                        report.elapsed_ms,
                        report.failure,
                        report.fatal,
                    );
                }
                continue;
            }
            // Invalid/oversized telemetry is discarded, not a VPN failure.
            if let Ok(report) = serde_json::from_slice(&buffer[..length]) {
                self.observe(report);
            }
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        let store = self.store();
        let elapsed_ms = millis(store.started.elapsed());
        let age_ms = store.last.map_or(0, |last| millis(last.elapsed()));
        let live = store.receiving && store.last.is_some() && age_ms <= 3000;
        let latest = store.history.back();
        Snapshot {
            version: 1,
            generation: store.generation,
            state: store.state.into(),
            setup_stage: store.stage.into(),
            worker_stage: store.worker_stage,
            elapsed_ms,
            available: store.last.is_some(),
            live,
            age_ms,
            counters: latest.map_or_else(Counters::default, |s| s.counters),
            upload_bytes_per_second: if live {
                latest.map_or(0, |s| s.upload_bytes_per_second)
            } else {
                0
            },
            download_bytes_per_second: if live {
                latest.map_or(0, |s| s.download_bytes_per_second)
            } else {
                0
            },
            history: store
                .history
                .iter()
                .filter(|s| elapsed_ms.saturating_sub(s.elapsed_ms) <= WINDOW_MS)
                .cloned()
                .collect(),
        }
    }
}

#[zbus::interface(name = "org.freedesktop.NetworkManager.tunnel.Telemetry")]
impl Telemetry {
    fn get_snapshot(&self) -> Snapshot {
        self.snapshot()
    }
}

#[cfg(test)]
#[path = "telemetry_tests.rs"]
mod tests;
