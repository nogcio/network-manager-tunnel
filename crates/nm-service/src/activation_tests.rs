use super::*;

#[tokio::test(start_paused = true)]
async fn socket_bursts_wait_for_the_next_window_without_failing() {
    let mut budget = SocketBudget::new();
    for _ in 0..64 {
        budget.acquire().await;
    }
    let start = tokio::time::Instant::now();
    let next = budget.acquire();
    tokio::pin!(next);
    assert!(futures_util::poll!(&mut next).is_pending());
    tokio::time::advance(Duration::from_secs(1)).await;
    next.await;
    assert_eq!(tokio::time::Instant::now() - start, Duration::from_secs(1));
}

#[tokio::test]
async fn dropping_owned_task_aborts_it_and_releases_its_resources() -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (owned, mut receiver) = tokio::sync::mpsc::channel::<()>(1);
        let (ready, started) = oneshot::channel();
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
