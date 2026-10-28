use super::*;
use crate::wire::Broker;
use std::sync::Arc;
use tokio::{io::AsyncReadExt, time::timeout};

#[tokio::test]
async fn endpoint_grant_exports_only_a_payload_channel_and_session_cancellation_closes_both_sides()
-> io::Result<()> {
    timeout(Duration::from_secs(3), async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let socket = TcpStream::connect(listener.local_addr()?).await?;
        let (mut peer, _) = listener.accept().await?;
        let (client, mut control) = UnixStream::pair()?;
        let broker = Arc::new(Broker::new(client));
        let task_broker = Arc::clone(&broker);
        let pending = tokio::spawn(async move { task_broker.open().await });
        assert_eq!(control.read_u8().await?, b'O');
        let mut tasks = JoinSet::new();
        assert!(available(&mut tasks));
        grant(&control, socket, &mut tasks).await?;
        let mut payload = pending.await.map_err(io::Error::other)??;
        assert!(payload.peer_addr()?.is_unnamed());
        payload.write_all(b"payload").await?;
        let mut bytes = [0; 7];
        peer.read_exact(&mut bytes).await?;
        assert_eq!(&bytes, b"payload");
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        assert_eq!(peer.read(&mut [0]).await?, 0);
        assert_eq!(payload.read(&mut [0]).await?, 0);
        assert!(!broker.poisoned.load(std::sync::atomic::Ordering::SeqCst));
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Contract deadline."))?
}

#[tokio::test(start_paused = true)]
async fn half_closed_relay_cannot_pin_a_root_slot_indefinitely() -> io::Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let socket = TcpStream::connect(listener.local_addr()?).await?;
    let (mut peer, _) = listener.accept().await?;
    let (parent, mut worker) = UnixStream::pair()?;
    let relay = tokio::spawn(run(socket, parent));
    worker.write_all(b"request").await?;
    worker.shutdown().await?;
    let mut received = Vec::new();
    timeout(Duration::from_secs(1), peer.read_to_end(&mut received)).await??;
    assert_eq!(received, b"request");
    tokio::time::advance(Duration::from_secs(60)).await;
    assert_eq!(
        relay
            .await
            .map_err(io::Error::other)?
            .err()
            .map(|e| e.to_string()),
        Some("Stream relay half-close deadline.".into())
    );
    assert_eq!(
        timeout(Duration::from_secs(1), worker.read(&mut [0])).await??,
        0
    );
    Ok(())
}
