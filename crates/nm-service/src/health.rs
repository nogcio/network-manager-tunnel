//! Session-local recovery: retry network probes, never reuse an uncertain broker.
use serde::{Deserialize, Serialize};
use std::{future::Future, io, time::Duration};

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub(crate) enum Failure {
    Deadline = 1,
    Refused = 2,
    Connection = 3,
    Other = 4,
}

impl Failure {
    pub(crate) fn from_error(error: &io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::TimedOut => Self::Deadline,
            io::ErrorKind::PermissionDenied => Self::Refused,
            io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof => Self::Connection,
            _ => Self::Other,
        }
    }

    pub(crate) fn from_code(code: u8) -> io::Result<Self> {
        match code {
            1 => Ok(Self::Deadline),
            2 => Ok(Self::Refused),
            3 => Ok(Self::Connection),
            4 => Ok(Self::Other),
            _ => Err(io::Error::other("Invalid worker error class.")),
        }
    }
}

/// Private, best-effort diagnostics. No error strings, names or addresses cross
/// this boundary. Absence of a report is not evidence of health.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Report {
    pub health: bool,
    pub failures: u32,
    pub stage: u8,
    pub elapsed_ms: u64,
    pub failure: Option<Failure>,
    pub fatal: bool,
}

/// The caller retains TUN, guard and flow ownership during transient failures.
/// Each probe includes queueing in its deadline; probes never overlap. Dropping
/// this future cancels retries. Cancellation of an in-flight broker exchange
/// poisons it, and is fatal rather than eligible for another exchange.
pub(crate) async fn monitor<F: Future<Output = io::Result<()>>>(
    mut probe: impl FnMut() -> F,
    usable: impl Fn() -> bool,
    stage: impl Fn() -> u8,
    mut report: impl FnMut(Report),
) -> io::Result<()> {
    let mut failures = 0_u32;
    let mut delay = 20;
    loop {
        tokio::time::sleep(Duration::from_secs(delay)).await;
        if !usable() {
            return Err(io::Error::other("Broker cancelled."));
        }
        let started = tokio::time::Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(15), probe())
            .await
            .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "Health deadline.")));
        let fatal = !usable();
        if result.is_err() || failures != 0 || fatal {
            failures = if result.is_err() {
                failures.saturating_add(1)
            } else {
                0
            };
            report(Report {
                health: true,
                failures,
                stage: stage(),
                elapsed_ms: started.elapsed().as_millis() as u64,
                failure: result.as_ref().err().map(Failure::from_error),
                fatal,
            });
        }
        if fatal {
            return Err(io::Error::other("Broker cancelled during health probe."));
        }
        // A fresh upstream connection is tried on each probe. Keep protection,
        // and allow independent flows to recover without tearing down NM routes.
        delay = if result.is_ok() {
            20
        } else {
            (delay * 2).min(60)
        };
    }
}

#[cfg(test)]
#[path = "health_tests.rs"]
mod tests;
