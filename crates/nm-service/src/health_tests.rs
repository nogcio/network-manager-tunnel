use super::*;
use std::cell::{Cell, RefCell};

#[tokio::test(start_paused = true)]
async fn queue_timeout_preserves_the_existing_exchange_and_allows_health_recovery() -> io::Result<()>
{
    use crate::wire::Broker;
    use std::sync::atomic::Ordering;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
    };
    let (client, mut server) = UnixStream::pair()?;
    let broker = Broker::new(client);
    let reports = RefCell::new(Vec::new());
    // This request owns the channel before health starts. Timing out while
    // waiting for its mutex must not cancel or consume its reply.
    let existing = broker.open();
    tokio::pin!(existing);
    tokio::select! {
        code = server.read_u8() => assert_eq!(code?, b'O'),
        _ = &mut existing => return Err(io::Error::other("Missing initial request.")),
    }
    let health = monitor(
        || async { broker.open().await.map(|_| ()) },
        || !broker.poisoned.load(Ordering::SeqCst),
        || 10,
        |report| reports.borrow_mut().push(report),
    );
    let mut health = Box::pin(health);
    assert!(futures_util::poll!(&mut health).is_pending());
    tokio::time::advance(Duration::from_secs(20)).await;
    assert!(futures_util::poll!(&mut health).is_pending());
    tokio::time::advance(Duration::from_secs(15)).await;
    assert!(futures_util::poll!(&mut health).is_pending());
    assert!(!broker.poisoned.load(Ordering::SeqCst));
    assert!(!reports.borrow()[0].fatal);
    server.write_all(b"N").await?;
    assert!(
        matches!(existing.await, Err(error) if error.kind() == io::ErrorKind::PermissionDenied)
    );
    let (payload, _peer) = UnixStream::pair()?;
    tokio::time::advance(Duration::from_secs(40)).await;
    tokio::select! {
        code = server.read_u8() => assert_eq!(code?, b'O'),
        _ = &mut health => return Err(io::Error::other("Missing health retry.")),
    }
    crate::wire::send_socket(&server, &payload).await?;
    // Readability is driven by the actual FD reply, not a scheduling sleep.
    // Poll alongside an independent bounded yield until the recovery report.
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            assert!(futures_util::poll!(&mut health).is_pending());
            if reports.borrow().len() == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(io::Error::other)?;
    assert_eq!(reports.borrow()[1].failures, 0);
    assert!(reports.borrow()[1].failure.is_none());
    assert!(!broker.poisoned.load(Ordering::SeqCst));
    drop(health);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn transient_failures_back_off_then_recovery_restores_normal_interval() {
    let attempts = Cell::new(0);
    let reports = RefCell::new(Vec::new());
    let health = monitor(
        || {
            attempts.set(attempts.get() + 1);
            std::future::ready(if attempts.get() <= 3 {
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "synthetic"))
            } else {
                Ok(())
            })
        },
        || true,
        || 12,
        |report| reports.borrow_mut().push(report),
    );
    tokio::pin!(health);
    assert!(futures_util::poll!(&mut health).is_pending());
    for (attempt, delay) in [20, 40, 60, 60, 20].into_iter().enumerate() {
        tokio::time::advance(Duration::from_secs(delay - 1)).await;
        assert!(futures_util::poll!(&mut health).is_pending());
        assert_eq!(attempts.get(), attempt);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(futures_util::poll!(&mut health).is_pending());
        assert_eq!(attempts.get(), attempt + 1);
    }
    let reports = reports.borrow();
    assert_eq!(reports.len(), 4);
    assert_eq!(reports[2].failures, 3);
    assert!(matches!(reports[0].failure, Some(Failure::Refused)));
    assert_eq!(reports[3].failures, 0);
    assert!(reports[3].failure.is_none());
    assert!(
        reports
            .iter()
            .all(|report| !report.fatal && report.stage == 12)
    );
}

#[tokio::test(start_paused = true)]
async fn withheld_probe_keeps_dispatch_live_retries_without_overlap_and_cancels() -> io::Result<()>
{
    let attempts = Cell::new(0);
    let reports = RefCell::new(Vec::new());
    let health = monitor(
        || {
            attempts.set(attempts.get() + 1);
            std::future::pending::<io::Result<()>>()
        },
        || true,
        || 12,
        |report| reports.borrow_mut().push(report),
    );
    let mut health = Box::pin(health);
    assert!(futures_util::poll!(&mut health).is_pending());
    tokio::time::advance(Duration::from_secs(20)).await;
    assert!(futures_util::poll!(&mut health).is_pending());
    let (dispatch, mut packets) = tokio::sync::mpsc::channel(1);
    dispatch.send(b"udp").await.map_err(io::Error::other)?;
    tokio::select! {
        _ = &mut health => return Err(io::Error::other("Health stopped dispatch.")),
        packet = packets.recv() => assert_eq!(packet, Some(b"udp")),
    }
    tokio::time::advance(Duration::from_secs(15)).await;
    assert!(futures_util::poll!(&mut health).is_pending());
    assert_eq!(attempts.get(), 1);
    assert!(matches!(
        reports.borrow()[0].failure,
        Some(Failure::Deadline)
    ));
    tokio::time::advance(Duration::from_secs(40)).await;
    assert!(futures_util::poll!(&mut health).is_pending());
    assert_eq!(attempts.get(), 2);
    drop(health);
    tokio::time::advance(Duration::from_secs(600)).await;
    assert_eq!(attempts.get(), 2);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn cancelled_exchange_is_fatal_and_never_reused() -> io::Result<()> {
    use crate::wire::Broker;
    use std::sync::atomic::Ordering;
    use tokio::{io::AsyncReadExt, net::UnixStream};
    let (client, mut server) = UnixStream::pair()?;
    let broker = Broker::new(client);
    let reports = RefCell::new(Vec::new());
    let health = monitor(
        || async { broker.open().await.map(|_| ()) },
        || !broker.poisoned.load(Ordering::SeqCst),
        || 10,
        |report| reports.borrow_mut().push(report),
    );
    tokio::pin!(health);
    assert!(futures_util::poll!(&mut health).is_pending());
    tokio::time::advance(Duration::from_secs(20)).await;
    tokio::select! {
        code = server.read_u8() => assert_eq!(code?, b'O'),
        _ = &mut health => return Err(io::Error::other("Missing broker request.")),
    }
    tokio::time::advance(Duration::from_secs(15)).await;
    assert!(health.await.is_err());
    assert!(broker.poisoned.load(Ordering::SeqCst));
    assert!(broker.open().await.is_err());
    assert_eq!(reports.borrow().len(), 1);
    assert!(reports.borrow()[0].fatal);
    Ok(())
}
