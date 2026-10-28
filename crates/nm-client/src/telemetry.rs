//! Read-only telemetry v1. Observation never D-Bus-activates the service.
use nm_tunnel_profile::SERVICE_TYPE;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use zbus::{proxy::MethodFlags, zvariant::Type};

const PATH: &str = "/org/freedesktop/NetworkManager/VPN/Plugin";
const INTERFACE: &str = "org.freedesktop.NetworkManager.tunnel.Telemetry";

/// Last observed TUN/flow counters for one activation, not a provider billing meter.
/// Multi-field samples are approximate; active counts are historical when not live.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Type)]
pub struct TrafficCounters {
    /// IP packet bytes read from TUN, including headers and retransmissions.
    pub upload_bytes: u64,
    /// IP packet bytes successfully written to TUN.
    pub download_bytes: u64,
    /// Packets read from TUN.
    pub upload_packets: u64,
    /// Packets successfully written to TUN.
    pub download_packets: u64,
    /// Admitted TCP flow tasks, including setup.
    pub tcp_active: u64,
    /// Admitted UDP associations, including setup; excludes health probes.
    pub udp_active: u64,
    /// TCP tasks admitted in this activation, not confirmed handshakes.
    pub tcp_opened: u64,
    /// UDP tasks admitted in this activation.
    pub udp_opened: u64,
    /// TCP tasks ending in error/deadline, excluding explicit teardown cancellation.
    pub tcp_failed: u64,
    /// UDP tasks ending in error/deadline.
    pub udp_failed: u64,
    /// Observed unsupported packets, admission rejections and queue backpressure.
    pub dropped_packets: u64,
}

/// One historical observation, oldest first in [`UsageSnapshot::history`].
#[derive(Clone, Debug, Deserialize, Serialize, Type)]
pub struct TrafficSample {
    /// Monotonic milliseconds since activation admission.
    pub elapsed_ms: u64,
    /// Cumulative counts at this sample.
    pub counters: TrafficCounters,
    /// Upload rate averaged over the preceding sampling interval.
    pub upload_bytes_per_second: u64,
    /// Download rate averaged over the preceding sampling interval.
    pub download_bytes_per_second: u64,
}

/// Bounded telemetry v1 response. No profile identity, endpoint or secrets.
/// Replace snapshots wholesale; never merge histories across generations/owners.
/// `running` is worker readiness, not NM activation or firewall certification.
#[derive(Clone, Debug, Deserialize, Serialize, Type)]
pub struct UsageSnapshot {
    /// Wire contract version; only 1 is supported.
    pub version: u32,
    /// Attempt number within a service process; resets when the process restarts.
    pub generation: u64,
    /// Backend lifecycle state, independent of observed NM activation.
    pub state: String,
    /// Last supervisor setup step.
    pub setup_stage: String,
    /// Last worker stage code: 0 unknown, 1–4 setup, 7 dispatch, 10–14 socket/protocol/DNS.
    pub worker_stage: u8,
    /// Milliseconds since admission, or service startup before any attempt.
    pub elapsed_ms: u64,
    /// Whether at least one worker report was received for this attempt.
    pub available: bool,
    /// Collector is active and the last worker report is at most 3 seconds old.
    pub live: bool,
    /// Milliseconds since last worker report, or 0 when unavailable.
    pub age_ms: u64,
    /// Last cumulative counters; retained after stop until the next attempt.
    pub counters: TrafficCounters,
    /// Upload rate in bytes/s; 0 when not live or before two samples.
    pub upload_bytes_per_second: u64,
    /// Download rate in bytes/s.
    pub download_bytes_per_second: u64,
    /// At most 61 observations in the preceding 60 seconds.
    pub history: Vec<TrafficSample>,
}

/// Sanitized telemetry errors; raw D-Bus messages are never displayed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum UsageError {
    /// Bus/owner unavailable, access refused, deadline expired or response lost.
    #[error("Backend statistics are unavailable.")]
    Unavailable,
    /// Unsupported version or malformed/beyond-contract response.
    #[error("Backend statistics use an unsupported or invalid format.")]
    Invalid,
}

impl UsageSnapshot {
    fn validate(&self) -> Result<(), UsageError> {
        if self.version != 1
            || self.history.len() > 61
            || !matches!(
                self.state.as_str(),
                "idle" | "connecting" | "running" | "stopping" | "stopped" | "failed"
            )
            || !matches!(
                self.setup_stage.as_str(),
                "idle" | "uplink" | "guard" | "resolve" | "tun" | "worker" | "readiness" | "ready"
            )
            || !matches!(self.worker_stage, 0..=4 | 7 | 10..=14)
            || self
                .history
                .iter()
                .any(|s| s.elapsed_ms > self.elapsed_ms || self.elapsed_ms - s.elapsed_ms > 60_000)
            || self
                .history
                .windows(2)
                .any(|s| s[0].elapsed_ms > s[1].elapsed_ms)
        {
            return Err(UsageError::Invalid);
        }
        Ok(())
    }
}

/// Observe an already-running backend without starting it or making NM calls.
/// Returns `Ok(None)` if no service owns the name. Uses a 3-second total deadline,
/// disables auto-start/property caching, pins the unique owner and rechecks it
/// before publishing. Cancellation drops read-only work; it never stops the VPN.
pub async fn usage_snapshot() -> Result<Option<UsageSnapshot>, UsageError> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let bus = zbus::Connection::system()
            .await
            .map_err(|_| UsageError::Unavailable)?;
        read(&bus).await
    })
    .await
    .map_err(|_| UsageError::Unavailable)?
}

async fn read(bus: &zbus::Connection) -> Result<Option<UsageSnapshot>, UsageError> {
    let Some(owner) = crate::transport::ReadOnly::pin(bus, SERVICE_TYPE)
        .await
        .map_err(|_| UsageError::Unavailable)?
    else {
        return Ok(None);
    };
    let proxy = owner
        .proxy(PATH, INTERFACE)
        .await
        .map_err(|_| UsageError::Unavailable)?;
    let snapshot: UsageSnapshot = proxy
        .call_with_flags("GetSnapshot", MethodFlags::NoAutoStart.into(), &())
        .await
        .map_err(|error| match error {
            zbus::Error::Variant(_)
            | zbus::Error::InvalidReply
            | zbus::Error::InvalidField
            | zbus::Error::MissingField
            | zbus::Error::ExcessData
            | zbus::Error::IncorrectEndian => UsageError::Invalid,
            _ => UsageError::Unavailable,
        })?
        .ok_or(UsageError::Unavailable)?;
    snapshot.validate()?;
    owner
        .validate()
        .await
        .map_err(|_| UsageError::Unavailable)?;
    Ok(Some(snapshot))
}

#[cfg(test)]
#[path = "telemetry_tests.rs"]
mod tests;
