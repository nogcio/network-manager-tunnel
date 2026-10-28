use super::*;
use std::{io, time::Duration};
use tokio::sync::{mpsc, oneshot};

async fn install_nested_task(
    resources: OwnedResources,
    owned: mpsc::Sender<()>,
    ready: oneshot::Sender<()>,
) {
    let relays = std::sync::Arc::clone(&resources.lock().await.relays);
    resources.lock().await.broker = Some(crate::task::AbortTask(tokio::spawn(async move {
        let mut relays = relays.lock().await;
        relays.tcp.spawn(async move {
            let _owned = owned;
            let _ = ready.send(());
            std::future::pending::<io::Result<()>>().await
        });
        std::future::pending::<io::Result<()>>().await
    })));
}

#[tokio::test]
async fn preparation_cancellation_joins_nested_resources_before_reporting_completion()
-> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (cancel, cancelled) = oneshot::channel();
        let (ready, started) = oneshot::channel();
        let (observe, observed) = oneshot::channel();
        let (owned, mut released) = mpsc::channel(1);
        let mut fixture = Some((owned, ready, observe));
        let task = tokio::spawn(prepare_owned(cancelled, move |resources| {
            let fixture = fixture.take();
            async move {
                let (owned, ready, observe) = fixture.ok_or_else(|| io::Error::other("Unexpected retry"))?;
                {
                    let mut owner = resources.lock().await;
                    owner.child = Some(tokio::process::Command::new("/usr/bin/sleep")
                        .arg("60").kill_on_drop(true).spawn()?);
                    owner.guard_writer = Some(tokio::process::Command::new("/usr/bin/sleep")
                        .arg("60").kill_on_drop(true).spawn()?);
                }
                let _ = observe.send(std::sync::Arc::clone(&resources));
                install_nested_task(resources, owned, ready).await;
                std::future::pending::<io::Result<()>>().await
            }
        }));
        started.await.map_err(io::Error::other)?;
        let resources = observed.await.map_err(io::Error::other)?;
        cancel.send(()).map_err(|_| io::Error::other("Lost cancellation owner"))?;
        assert!(matches!(task.await.map_err(io::Error::other)?, Err(Failure::Activation(error)) if error.kind() == io::ErrorKind::Interrupted));
        assert_eq!(released.try_recv(), Err(mpsc::error::TryRecvError::Disconnected));
        let resources = resources.lock().await;
        assert!(resources.child.is_none());
        assert!(resources.guard_writer.is_none());
        Ok(())
    }).await.map_err(|_| io::Error::other("Preparation barrier deadline"))?
}

#[tokio::test(start_paused = true)]
async fn preparation_deadline_joins_resources_before_returning_timeout() -> io::Result<()> {
    let (_cancel, cancelled) = oneshot::channel();
    let (ready, started) = oneshot::channel();
    let (owned, mut released) = mpsc::channel(1);
    let mut fixture = Some((owned, ready));
    let start = tokio::time::Instant::now();
    let task = tokio::spawn(prepare_owned(cancelled, move |resources| {
        let fixture = fixture.take();
        async move {
            let (owned, ready) = fixture.ok_or_else(|| io::Error::other("Unexpected retry"))?;
            install_nested_task(resources, owned, ready).await;
            std::future::pending::<io::Result<()>>().await
        }
    }));
    started.await.map_err(io::Error::other)?;
    assert!(
        matches!(task.await.map_err(io::Error::other)?, Err(Failure::Activation(error)) if error.kind() == io::ErrorKind::TimedOut)
    );
    assert_eq!(start.elapsed(), Duration::from_secs(45));
    assert_eq!(
        released.try_recv(),
        Err(mpsc::error::TryRecvError::Disconnected)
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn retry_starts_only_after_previous_nested_resources_are_joined() -> io::Result<()> {
    let (_cancel, cancelled) = oneshot::channel();
    let (owned, mut released) = mpsc::channel(1);
    let mut owned = Some(owned);
    let mut attempt = 0;
    let result = prepare_owned(cancelled, |resources| {
        attempt += 1;
        let first = owned.take();
        // This assertion is synchronous: cleanup must precede even invoking retry.
        if first.is_none() {
            assert_eq!(
                released.try_recv(),
                Err(mpsc::error::TryRecvError::Disconnected)
            );
        }
        async move {
            if let Some(owned) = first {
                let (ready, started) = oneshot::channel();
                install_nested_task(resources, owned, ready).await;
                started.await.map_err(io::Error::other)?;
                return Err(io::Error::other("Synthetic readiness failure"));
            }
            assert!(resources.lock().await.relays.lock().await.tcp.is_empty());
            Ok(())
        }
    })
    .await;
    assert!(result.is_ok());
    assert_eq!(attempt, 2);
    Ok(())
}
