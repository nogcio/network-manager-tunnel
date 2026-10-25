use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(start_paused = true)]
async fn tcp_setup_deadline_closes_inbound_and_preserves_broker_poisoning() -> io::Result<()> {
    let (client, mut server) = UnixStream::pair()?;
    let broker = Broker::new(client);
    let (mut application, inbound) = tokio::io::duplex(64);
    let forwarding = forward_tcp(inbound, async {
        let _socket = broker.open().await?;
        Err::<tokio::io::DuplexStream, _>(io::Error::other("Unexpected broker reply."))
    });
    tokio::pin!(forwarding);
    tokio::select! {
        code = server.read_u8() => assert_eq!(code?, b'O'),
        _ = &mut forwarding => return Err(io::Error::other("Broker completed without a reply.")),
    }
    tokio::time::advance(Duration::from_secs(60)).await;
    assert_eq!(
        forwarding.await.err().map(|e| e.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert!(broker.poisoned.load(Ordering::SeqCst));
    assert!(broker.open().await.is_err());
    assert_eq!(application.read(&mut [0]).await?, 0);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn established_tcp_outlives_setup_deadline_and_cancellation_closes_both_streams()
-> io::Result<()> {
    let (mut application, inbound) = tokio::io::duplex(64);
    let (remote, mut peer) = tokio::io::duplex(64);
    let mut forwarding = Box::pin(forward_tcp(inbound, std::future::ready(Ok(remote))));
    assert!(futures_util::poll!(&mut forwarding).is_pending());
    // Controlled time: no wall-clock wait or total-lifetime test.
    tokio::time::advance(Duration::from_secs(61)).await;
    assert!(futures_util::poll!(&mut forwarding).is_pending());
    application.write_all(b"a").await?;
    assert!(futures_util::poll!(&mut forwarding).is_pending());
    assert_eq!(peer.read_u8().await?, b'a');
    peer.write_all(b"b").await?;
    assert!(futures_util::poll!(&mut forwarding).is_pending());
    assert_eq!(application.read_u8().await?, b'b');
    drop(forwarding);
    assert_eq!(application.read(&mut [0]).await?, 0);
    assert_eq!(peer.read(&mut [0]).await?, 0);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn stalled_udp_write_expires_and_releases_association_queue() -> io::Result<()> {
    let (mut writer, _nonreading_peer) = tokio::io::duplex(1);
    let (sender, receiver) = mpsc::channel::<Vec<u8>>(16);
    let association = async move {
        let _queue = receiver;
        udp_deadline(writer.write_all(b"blocked")).await
    };
    tokio::pin!(association);
    assert!(futures_util::poll!(&mut association).is_pending());
    tokio::time::advance(Duration::from_secs(60)).await;
    assert!(association.await.is_err());
    assert!(sender.is_closed());
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn udp_deadline_bounds_a_broker_wait_and_preserves_poisoning() -> io::Result<()> {
    let (client, mut server) = UnixStream::pair()?;
    let broker = Broker::new(client);
    let opening = udp_deadline(broker.open());
    tokio::pin!(opening);
    use tokio::io::AsyncReadExt;
    tokio::select! {
        code = server.read_u8() => assert_eq!(code?, b'O'),
        _ = &mut opening => return Err(io::Error::other("Broker completed without a reply.")),
    }
    tokio::time::advance(Duration::from_secs(60)).await;
    assert!(opening.await.is_err());
    assert!(broker.poisoned.load(Ordering::SeqCst));
    assert!(broker.open().await.is_err());
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn withheld_health_probe_does_not_block_dispatch_and_cannot_overlap() -> io::Result<()> {
    let attempts = std::cell::Cell::new(0);
    let health = monitor_health(|| {
        attempts.set(attempts.get() + 1);
        std::future::pending::<io::Result<()>>()
    });
    tokio::pin!(health);
    assert!(futures_util::poll!(&mut health).is_pending());
    tokio::time::advance(Duration::from_secs(20)).await;
    assert!(futures_util::poll!(&mut health).is_pending());
    assert_eq!(attempts.get(), 1);
    let (dispatch, mut packets) = mpsc::channel(1);
    dispatch.send(b"udp").await.map_err(io::Error::other)?;
    tokio::select! {
        _ = &mut health => return Err(io::Error::other("Probe completed before its deadline.")),
        packet = packets.recv() => assert_eq!(packet, Some(b"udp")),
    }
    tokio::time::advance(Duration::from_secs(15)).await;
    assert!(health.await.is_err());
    assert_eq!(attempts.get(), 1);
    Ok(())
}
