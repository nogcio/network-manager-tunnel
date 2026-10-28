use super::*;
use crate::stream_relay::run as tcp;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

async fn wait_closed(worker: &UnixDatagram) -> io::Result<()> {
    // Parallel process-spawning tests may transiently retain CLOEXEC descriptors
    // between fork and exec. Observe actual channel closure with a deadline,
    // rather than treating an immediately reusable global port as ownership proof.
    timeout(Duration::from_secs(2), async {
        loop {
            if worker.send(b"closure probe").await.is_err() {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| io::Error::other("LAN channel did not close."))
}

#[tokio::test]
async fn datagrams_keep_one_root_owned_destination_and_cancellation_closes_the_bridge()
-> io::Result<()> {
    timeout(Duration::from_secs(3), async {
        let peer = UdpSocket::bind("127.0.0.1:0").await?;
        let upstream = UdpSocket::bind("127.0.0.1:0").await?;
        upstream.connect(peer.local_addr()?).await?;
        let local_address = upstream.local_addr()?;
        let (parent, worker) = UnixDatagram::pair()?;
        let relay = tokio::spawn(run(upstream, parent));
        for payload in [b"local datagram".as_slice(), b"".as_slice()] {
            worker.send(payload).await?;
            let mut buffer = [0; 64];
            let (size, source) = peer.recv_from(&mut buffer).await?;
            assert_eq!(source, local_address);
            assert_eq!(&buffer[..size], payload);
            peer.send_to(b"reply", source).await?;
            let size = worker.recv(&mut buffer).await?;
            assert_eq!(&buffer[..size], b"reply");
        }
        relay.abort();
        assert!(relay.await.is_err_and(|e| e.is_cancelled()));
        wait_closed(&worker).await?;
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Contract deadline."))?
}

#[tokio::test]
async fn oversized_datagram_rejects_before_upstream_io_and_closes_owned_resources() -> io::Result<()>
{
    timeout(Duration::from_secs(3), async {
        let peer = UdpSocket::bind("127.0.0.1:0").await?;
        let upstream = UdpSocket::bind("127.0.0.1:0").await?;
        upstream.connect(peer.local_addr()?).await?;
        let (parent, worker) = UnixDatagram::pair()?;
        let relay = tokio::spawn(run(upstream, parent));
        worker.send(&vec![0; 65508]).await?;
        assert_eq!(
            relay
                .await
                .map_err(io::Error::other)?
                .err()
                .map(|e| e.to_string()),
            Some("Oversized LAN datagram.".into())
        );
        assert!(matches!(peer.try_recv(&mut [0]),Err(e) if e.kind()==io::ErrorKind::WouldBlock));
        wait_closed(&worker).await?;
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Contract deadline."))?
}

#[tokio::test(start_paused = true)]
async fn datagram_idle_deadline_closes_the_owned_bridge() -> io::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let upstream = UdpSocket::bind("127.0.0.1:0").await?;
    upstream.connect(peer.local_addr()?).await?;
    let (parent, worker) = UnixDatagram::pair()?;
    let mut relay = Box::pin(run(upstream, parent));
    let pending = std::future::poll_fn(|cx| {
        std::task::Poll::Ready(std::future::Future::poll(relay.as_mut(), cx).is_pending())
    })
    .await;
    assert!(pending);
    tokio::time::advance(Duration::from_secs(60)).await;
    assert_eq!(
        relay.await.err().map(|e| e.to_string()),
        Some("LAN datagram idle deadline.".into())
    );
    tokio::time::resume();
    wait_closed(&worker).await?;
    Ok(())
}

#[tokio::test]
async fn tcp_bridge_preserves_bytes_and_cancellation_closes_ip_and_unix_streams() -> io::Result<()>
{
    timeout(Duration::from_secs(3), async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let upstream = TcpStream::connect(listener.local_addr()?).await?;
        let (mut peer, _) = listener.accept().await?;
        let (parent, mut worker) = UnixStream::pair()?;
        let relay = tokio::spawn(tcp(upstream, parent));
        worker.write_all(b"request").await?;
        let mut request = [0; 7];
        peer.read_exact(&mut request).await?;
        assert_eq!(&request, b"request");
        peer.write_all(b"reply").await?;
        let mut response = [0; 5];
        worker.read_exact(&mut response).await?;
        assert_eq!(&response, b"reply");
        relay.abort();
        assert!(relay.await.is_err_and(|e| e.is_cancelled()));
        assert_eq!(peer.read(&mut [0]).await?, 0);
        assert_eq!(worker.read(&mut [0]).await?, 0);
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Contract deadline."))?
}
