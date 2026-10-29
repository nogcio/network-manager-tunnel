//! Privileged runtime ownership. NM API and unprivileged dispatch are separate adapters.
mod broker;
mod plan;
mod resources;
mod roaming;
mod session;
mod tun;
pub(crate) mod uplink_dns;

pub(crate) use roaming::{changed, resume};
pub(crate) use session::Session;

/// Only an activation failure with confirmed teardown permits guard cleanup.
#[derive(Debug)]
pub(crate) enum Failure {
    Activation(std::io::Error),
    Shutdown(std::io::Error),
}

/// Retry only preparation, before NM receives readiness/IP configuration. Retain
/// the same admitted input in memory; never select another profile or persist secrets.
pub(crate) async fn prepare(
    bus: zbus::Connection,
    config: crate::wire::WorkerConfig,
    telemetry: crate::telemetry::Telemetry,
    cancel: tokio::sync::oneshot::Receiver<()>,
) -> Result<Session, Failure> {
    let (resources, prepared) = prepare_owned(cancel, |resources| {
        let bus = bus.clone();
        let config = config.clone();
        let telemetry = telemetry.clone();
        async move { session::prepare(bus, config, telemetry, &mut *resources.lock().await).await }
    })
    .await?;
    Ok(Session {
        resources,
        prepared,
    })
}

type OwnedResources = std::sync::Arc<tokio::sync::Mutex<resources::Resources>>;

#[cfg(test)]
mod preparation_tests;

/// Cancellation and the total attempt deadline drop only borrowed setup work.
/// This owner survives to confirm teardown before publishing an activation error.
async fn prepare_owned<T, F, O>(
    mut cancel: tokio::sync::oneshot::Receiver<()>,
    mut operation: O,
) -> Result<(OwnedResources, T), Failure>
where
    O: FnMut(OwnedResources) -> F,
    F: std::future::Future<Output = std::io::Result<T>>,
{
    let resources = std::sync::Arc::new(tokio::sync::Mutex::new(resources::Resources::default()));
    let result = tokio::select! {
        _ = &mut cancel => Err(Failure::Activation(std::io::Error::new(std::io::ErrorKind::Interrupted, "Activation cancelled."))),
        result = retry_preparation(|| {
            let resources = std::sync::Arc::clone(&resources);
            let attempt = operation(std::sync::Arc::clone(&resources));
            async move {
                let result = attempt.await;
                if result.is_err() {
                    resources.lock().await.stop().await.map_err(Failure::Shutdown)?;
                }
                result.map_err(Failure::Activation)
            }
        }) => result,
    };
    match result {
        Ok(prepared) => Ok((resources, prepared)),
        Err(error @ Failure::Shutdown(_)) => Err(error),
        Err(error @ Failure::Activation(_)) => {
            resources
                .lock()
                .await
                .stop()
                .await
                .map_err(Failure::Shutdown)?;
            Err(error)
        }
    }
}

async fn retry_preparation<T, F, O>(mut operation: O) -> Result<T, Failure>
where
    O: FnMut() -> F,
    F: std::future::Future<Output = Result<T, Failure>>,
{
    use std::{io, time::Duration};
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let first = tokio::time::timeout_at(deadline, operation())
        .await
        .map_err(|_| {
            Failure::Activation(io::Error::new(
                io::ErrorKind::TimedOut,
                "Activation recovery deadline.",
            ))
        })?;
    if first.is_ok() || matches!(first, Err(Failure::Shutdown(_))) {
        return first;
    }
    if tokio::time::Instant::now() + Duration::from_secs(1) >= deadline {
        return first;
    }
    eprintln!(
        "VPN preparation failed; retrying the same admitted profile once before automatic cleanup."
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    tokio::time::timeout_at(deadline, operation())
        .await
        .map_err(|_| {
            Failure::Activation(io::Error::new(
                io::ErrorKind::TimedOut,
                "Activation recovery deadline.",
            ))
        })?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, io, time::Duration};

    #[tokio::test(start_paused = true)]
    async fn unconfirmed_shutdown_never_retries_preparation() {
        let attempts = Cell::new(0);
        let start = tokio::time::Instant::now();
        let result = retry_preparation(|| {
            attempts.set(attempts.get() + 1);
            std::future::ready(Err::<(), _>(Failure::Shutdown(io::Error::other(
                "Synthetic termination refusal",
            ))))
        })
        .await;
        assert!(matches!(result, Err(Failure::Shutdown(_))));
        assert_eq!(attempts.get(), 1);
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn preparation_retries_once_then_preserves_the_terminal_error() -> io::Result<()> {
        let attempts = Cell::new(0);
        let start = tokio::time::Instant::now();
        let result = retry_preparation(|| {
            attempts.set(attempts.get() + 1);
            std::future::ready(Err::<(), _>(Failure::Activation(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "Synthetic refusal.",
            ))))
        })
        .await;
        assert_eq!(attempts.get(), 2);
        assert_eq!(
            result.err().map(|error| match error {
                Failure::Activation(error) => error.kind(),
                Failure::Shutdown(_) => panic!("Unexpected shutdown failure"),
            }),
            Some(io::ErrorKind::ConnectionRefused)
        );
        assert_eq!(start.elapsed(), Duration::from_secs(1));
        let successful = Cell::new(0);
        assert_eq!(
            retry_preparation(|| {
                successful.set(successful.get() + 1);
                std::future::ready(if successful.get() == 1 {
                    Err(Failure::Activation(io::Error::other("Synthetic failure.")))
                } else {
                    Ok(7)
                })
            })
            .await
            .map_err(|error| io::Error::other(format!("{error:?}")))?,
            7
        );
        assert_eq!(successful.get(), 2);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn one_total_deadline_bounds_stalled_preparation_without_detached_retries() {
        let attempts = Cell::new(0);
        let start = tokio::time::Instant::now();
        let result = retry_preparation(|| {
            attempts.set(attempts.get() + 1);
            std::future::pending::<Result<(), Failure>>()
        })
        .await;
        assert_eq!(attempts.get(), 1);
        assert_eq!(start.elapsed(), Duration::from_secs(45));
        assert_eq!(
            result.err().map(|error| match error {
                Failure::Activation(error) => error.kind(),
                Failure::Shutdown(_) => panic!("Unexpected shutdown failure"),
            }),
            Some(io::ErrorKind::TimedOut)
        );
    }
}
