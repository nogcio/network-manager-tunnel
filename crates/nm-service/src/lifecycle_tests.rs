use super::*;

#[tokio::test]
async fn cleanup_completion_is_awaited_and_task_failure_is_not_success() -> io::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let (release, wait) = oneshot::channel();
        let mut cleanup = Some(AbortTask(tokio::spawn(async move {
            wait.await.map_err(io::Error::other)?;
            Ok(())
        })));
        let pending = await_cleanup(&mut cleanup);
        tokio::pin!(pending);
        assert!(futures_util::poll!(&mut pending).is_pending());
        release
            .send(())
            .map_err(|_| io::Error::other("Lost cleanup owner."))?;
        pending.await?;
        let mut refused = Some(AbortTask(tokio::spawn(async {
            Err(io::Error::other("Synthetic cleanup refusal."))
        })));
        assert!(await_cleanup(&mut refused).await.is_err());
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Cleanup contract deadline."))?
}

#[test]
fn admission_checks_ownership_even_when_reported_state_is_stopped() {
    let state = AtomicU32::new(6);
    assert!(admit_start(&state, true, false).is_err());
    assert!(admit_start(&state, false, true).is_err());
    assert_eq!(state.load(Ordering::SeqCst), 6);
    assert!(admit_start(&state, false, false).is_ok());
    assert_eq!(state.load(Ordering::SeqCst), 3);
    assert!(admit_start(&state, false, false).is_err());
    assert_eq!(state.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn cancelling_preparation_awaits_owned_task_resource_release() -> io::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let (owned, mut receiver) = mpsc::channel::<()>(1);
        let (ready, started) = oneshot::channel();
        let (cancel, cancelled) = oneshot::channel();
        let mut pending = Some(Preparation {
            cancel,
            task: AbortTask(tokio::spawn(async move {
                let _owned = owned;
                let _ = ready.send(());
                let _ = cancelled.await;
                Err(supervisor::Failure::Activation(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Cancelled",
                )))
            })),
        });
        started.await.map_err(io::Error::other)?;
        cancel_preparation(&mut pending)
            .await
            .map_err(io::Error::other)?;
        assert!(pending.is_none());
        assert_eq!(receiver.recv().await, None);
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Preparation cancellation deadline."))?
}

#[tokio::test]
async fn unconfirmed_preparation_shutdown_is_not_accepted_as_safe_cancellation() {
    let (cancel, _cancelled) = oneshot::channel();
    let mut pending = Some(Preparation {
        cancel,
        task: AbortTask(tokio::spawn(async {
            Err(supervisor::Failure::Shutdown(io::Error::other(
                "Synthetic unconfirmed worker",
            )))
        })),
    });
    assert!(cancel_preparation(&mut pending).await.is_err());
}
