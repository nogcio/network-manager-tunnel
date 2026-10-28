use nm_tunnel_engine::inspect_tcp_hostname;
use std::{future::Future, pin::Pin, task::Poll, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(start_paused = true)]
async fn short_tls_handshake_headers_do_not_panic_or_lose_replay_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    for size in 1..4 {
        let mut bytes = vec![22, 3, 3, 0, size];
        bytes.extend(vec![1; usize::from(size)]);
        let (mut client, mut inbound) = tokio::io::duplex(64);
        client.write_all(&bytes).await?;
        client.shutdown().await?;
        let observed = inspect_tcp_hostname(&mut inbound).await?;
        assert!(observed.hostname().is_none());
        assert_eq!(observed.prefix(), bytes);
    }
    Ok(())
}

async fn pending<F: Future>(mut future: Pin<&mut F>) -> bool {
    std::future::poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx).is_pending())).await
}

#[tokio::test(start_paused = true)]
async fn fragmented_inspection_preserves_prefix_and_leaves_remaining_bytes_for_the_relay()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut client, mut inbound) = tokio::io::duplex(8192);
    let first = b"GET /private-token HTTP/1.1\r\nHost: Mixed.Exa";
    let second = b"mple:443\r\n\r\nbody";
    client.write_all(first).await?;
    let mut inspection = Box::pin(inspect_tcp_hostname(&mut inbound));
    assert!(pending(inspection.as_mut()).await);
    client.write_all(second).await?;
    let observed = inspection.await?;
    assert_eq!(observed.hostname(), Some("mixed.example"));
    assert_eq!(
        observed.prefix(),
        [first.as_slice(), second.as_slice()].concat()
    );
    assert!(!format!("{observed:?}").contains("private-token"));
    client.write_all(b"later").await?;
    let mut remaining = [0; 5];
    inbound.read_exact(&mut remaining).await?;
    assert_eq!(&remaining, b"later");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn one_deadline_bounds_silent_or_incomplete_streams_and_cancellation_owns_the_stream()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut client, mut inbound) = tokio::io::duplex(8192);
    client.write_all(b"incomplete-private-prefix").await?;
    let mut inspection = Box::pin(inspect_tcp_hostname(&mut inbound));
    assert!(pending(inspection.as_mut()).await);
    tokio::time::advance(Duration::from_millis(300)).await;
    let observed = inspection.await?;
    assert_eq!(observed.hostname(), None);
    assert_eq!(observed.prefix(), b"incomplete-private-prefix");
    let mut inspection = Box::pin(inspect_tcp_hostname(&mut inbound));
    assert!(pending(inspection.as_mut()).await);
    drop(inspection);
    drop(inbound);
    assert_eq!(client.read(&mut [0]).await?, 0);
    Ok(())
}

#[tokio::test]
async fn byte_budget_does_not_consume_unbounded_client_data()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (mut client, mut inbound) = tokio::io::duplex(16384);
        client.write_all(&vec![b'x'; 9000]).await?;
        let observed = inspect_tcp_hostname(&mut inbound).await?;
        assert_eq!(observed.hostname(), None);
        assert_eq!(observed.prefix().len(), 8192);
        let mut rest = vec![0; 808];
        inbound.read_exact(&mut rest).await?;
        assert!(rest.iter().all(|b| *b == b'x'));
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await??;
    Ok(())
}
