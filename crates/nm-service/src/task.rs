//! Task ownership shared by runtime components, independent of activation.
use tokio::task::JoinHandle;

/// Confirm a supervised child's exit. Any kill/wait/deadline error is an
/// unconfirmed shutdown, never permission to release network guards. Keep the
/// child owned by the caller across cancellation so it can be waited again.
pub(crate) async fn terminate(child: &mut tokio::process::Child) -> std::io::Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    confirm_exit(child.start_kill(), child.wait()).await
}

async fn confirm_exit<T>(
    kill: std::io::Result<()>,
    wait: impl std::future::Future<Output = std::io::Result<T>>,
) -> std::io::Result<()> {
    kill?;
    tokio::time::timeout(std::time::Duration::from_secs(3), wait)
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Process termination unconfirmed.",
            )
        })??;
    Ok(())
}

/// Abort on drop. Callers needing ordered teardown must also await cancellation.
pub(crate) struct AbortTask<T>(pub JoinHandle<T>);

impl<T> Drop for AbortTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io, time::Duration};

    #[tokio::test(start_paused = true)]
    async fn termination_refusal_wait_error_and_deadline_are_not_completed_shutdown() {
        let polled = std::cell::Cell::new(false);
        let wait = async {
            polled.set(true);
            Ok(())
        };
        let refusal = confirm_exit(
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Synthetic kill refusal",
            )),
            wait,
        )
        .await;
        assert_eq!(
            refusal.err().map(|e| e.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        assert!(!polled.get());
        let failed = confirm_exit(
            Ok(()),
            std::future::ready(Err::<(), _>(io::Error::other("Synthetic wait failure"))),
        )
        .await;
        assert!(failed.is_err());
        let start = tokio::time::Instant::now();
        let stalled = confirm_exit(Ok(()), std::future::pending::<io::Result<()>>()).await;
        assert_eq!(
            stalled.err().map(|e| e.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        assert_eq!(start.elapsed(), Duration::from_secs(3));
    }

    #[tokio::test]
    async fn dropping_owned_task_aborts_it_and_releases_its_resources() -> io::Result<()> {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (owned, mut receiver) = tokio::sync::mpsc::channel::<()>(1);
            let (ready, started) = tokio::sync::oneshot::channel();
            let task = AbortTask(tokio::spawn(async move {
                let _owned = owned;
                let _ = ready.send(());
                std::future::pending::<()>().await;
            }));
            started.await.map_err(io::Error::other)?;
            drop(task);
            assert_eq!(receiver.recv().await, None);
            Ok(())
        })
        .await
        .map_err(|_| io::Error::other("Task cancellation deadline."))?
    }
}
