use super::*;

#[tokio::test(start_paused = true)]
async fn fatal_reports_accept_only_bounded_stage_and_error_codes_with_a_deadline() -> io::Result<()>
{
    let (mut worker, mut parent) = UnixStream::pair()?;
    worker
        .write_all(&[12, crate::health::Failure::Deadline as u8])
        .await?;
    let (stage, reason) = receive_worker_failure(&mut parent).await?;
    assert_eq!(stage, 12);
    assert!(matches!(reason, crate::health::Failure::Deadline));
    for bytes in [[0, 1], [15, 1], [12, 0], [12, 255]] {
        worker.write_all(&bytes).await?;
        assert!(receive_worker_failure(&mut parent).await.is_err());
    }
    worker.write_all(&[12]).await?;
    let report = receive_worker_failure(&mut parent);
    tokio::pin!(report);
    assert!(futures_util::poll!(&mut report).is_pending());
    tokio::time::advance(std::time::Duration::from_secs(5)).await;
    assert!(matches!(report.await, Err(error) if error.kind() == io::ErrorKind::TimedOut));
    Ok(())
}
use tokio::net::TcpStream;

async fn lan_request(server: &mut UnixStream) -> io::Result<LanRequest> {
    assert_eq!(server.read_u8().await?, b'L');
    let size = server.read_u16().await? as usize;
    assert!(size <= MAX_LAN_REQUEST);
    let mut bytes = vec![0; size];
    server.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

#[tokio::test]
async fn invalid_lan_frames_are_bounded_and_cannot_supply_prefixes_or_private_diagnostics()
-> io::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        for size in [0, MAX_LAN_REQUEST + 1] {
            let (mut client, mut server) = UnixStream::pair()?;
            client.write_u16(size as u16).await?;
            assert_eq!(
                receive_lan_request(&mut server)
                    .await
                    .err()
                    .map(|e| e.to_string()),
                Some("Invalid LAN request length.".into())
            );
        }
        for text in [
            r#"{"destination":"192.168.1.1:80","transport":"tcp","prefix":"0.0.0.0/0"}"#,
            r#"{"destination":"private-token","transport":"tcp"}"#,
            r#"{"destination":"192.168.1.1:80","transport":"unknown"}"#,
        ] {
            let (mut client, mut server) = UnixStream::pair()?;
            client.write_u16(text.len() as u16).await?;
            client.write_all(text.as_bytes()).await?;
            assert_eq!(
                receive_lan_request(&mut server)
                    .await
                    .err()
                    .map(|e| e.to_string()),
                Some("Invalid LAN request.".into())
            );
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Contract deadline."))?
}

#[tokio::test(start_paused = true)]
async fn incomplete_lan_frame_has_a_deadline_without_granting_any_socket() -> io::Result<()> {
    let (mut client, mut server) = UnixStream::pair()?;
    client.write_u16(8).await?;
    let mut request = Box::pin(receive_lan_request(&mut server));
    let pending = std::future::poll_fn(|cx| {
        std::task::Poll::Ready(std::future::Future::poll(request.as_mut(), cx).is_pending())
    })
    .await;
    assert!(pending);
    tokio::time::advance(std::time::Duration::from_secs(5)).await;
    assert_eq!(
        request.await.err().map(|e| e.to_string()),
        Some("LAN request deadline.".into())
    );
    assert!(matches!(client.try_read(&mut [0]),Err(e) if e.kind()==io::ErrorKind::WouldBlock));
    Ok(())
}

#[tokio::test]
async fn lan_datagram_grants_only_a_unix_payload_channel_and_cancellation_poisons_uncertain_grants()
-> io::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let (client, mut server) = UnixStream::pair()?;
        let broker = Arc::new(Broker::new(client));
        let destination: SocketAddr = "192.168.1.1:123".parse().map_err(io::Error::other)?;
        let task_broker = Arc::clone(&broker);
        let pending = tokio::spawn(async move { task_broker.open_lan_udp(destination).await });
        let request = lan_request(&mut server).await?;
        assert_eq!(request.destination, destination);
        assert!(matches!(request.transport, LanTransport::Udp));
        let (parent, worker) = UnixDatagram::pair()?;
        send_socket(&server, &worker).await?;
        drop(worker);
        let received = pending.await.map_err(io::Error::other)??;
        received.send(b"payload only").await?;
        let mut bytes = [0; 32];
        let size = parent.recv(&mut bytes).await?;
        assert_eq!(&bytes[..size], b"payload only");
        assert!(!broker.poisoned.load(Ordering::SeqCst));
        drop(received);
        let task_broker = Arc::clone(&broker);
        let pending = tokio::spawn(async move { task_broker.open_lan_udp(destination).await });
        lan_request(&mut server).await?;
        pending.abort();
        assert!(pending.await.is_err_and(|e| e.is_cancelled()));
        assert!(broker.poisoned.load(Ordering::SeqCst));
        assert!(broker.open_lan_tcp(destination).await.is_err());
        assert!(matches!(server.try_read(&mut [0]),Err(e) if e.kind()==io::ErrorKind::WouldBlock));
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Contract deadline."))?
}

#[tokio::test]
async fn lan_ip_datagram_descriptor_is_rejected_closed_and_poisoned_not_handed_to_worker()
-> io::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let (client, mut server) = UnixStream::pair()?;
        let broker = Arc::new(Broker::new(client));
        let task_broker = Arc::clone(&broker);
        let pending = tokio::spawn(async move {
            task_broker
                .open_lan_udp("192.168.1.1:123".parse().map_err(io::Error::other)?)
                .await
        });
        lan_request(&mut server).await?;
        send_socket(&server, &socket).await?;
        drop(socket);
        assert!(pending.await.map_err(io::Error::other)?.is_err());
        assert!(broker.poisoned.load(Ordering::SeqCst));
        assert!(broker.open().await.is_err());
        assert!(matches!(server.try_read(&mut [0]),Err(e) if e.kind()==io::ErrorKind::WouldBlock));
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Contract deadline."))?
}

#[tokio::test]
async fn lan_tcp_grant_uses_unix_stream_and_refusal_never_requests_a_proxy_socket() -> io::Result<()>
{
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        for refused in [false, true] {
            let (client, mut server) = UnixStream::pair()?;
            let broker = Arc::new(Broker::new(client));
            let task_broker = Arc::clone(&broker);
            let pending = tokio::spawn(async move {
                task_broker
                    .open_lan_tcp("192.168.1.1:80".parse().map_err(io::Error::other)?)
                    .await
            });
            let request = lan_request(&mut server).await?;
            assert!(matches!(request.transport, LanTransport::Tcp));
            if refused {
                server.write_all(b"N").await?;
                assert_eq!(
                    pending
                        .await
                        .map_err(io::Error::other)?
                        .err()
                        .map(|e| e.kind()),
                    Some(io::ErrorKind::PermissionDenied)
                );
            } else {
                let (worker, mut parent) = UnixStream::pair()?;
                send_socket(&server, &worker).await?;
                drop(worker);
                let mut received = pending.await.map_err(io::Error::other)??;
                received.write_all(b"owned").await?;
                let mut bytes = [0; 5];
                parent.read_exact(&mut bytes).await?;
                assert_eq!(&bytes, b"owned");
                drop(received);
                assert_eq!(parent.read(&mut [0]).await?, 0);
            }
            assert!(!broker.poisoned.load(Ordering::SeqCst));
            assert!(
                matches!(server.try_read(&mut [0]),Err(e) if e.kind()==io::ErrorKind::WouldBlock)
            );
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Contract deadline."))?
}

#[tokio::test]
async fn direct_request_cancellation_poisons_the_channel_but_local_size_rejection_does_not()
-> io::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let (client, mut server) = UnixStream::pair()?;
        let broker = Arc::new(Broker::new(client));
        let request = DirectRequest {
            domain: "x".repeat(MAX_DIRECT_REQUEST),
            destination: "1.1.1.1:443".parse().map_err(io::Error::other)?,
        };
        assert!(broker.open_direct(&request).await.is_err());
        assert!(!broker.poisoned.load(Ordering::SeqCst));
        assert!(
            matches!(server.try_read(&mut [0]), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
        );
        let open = Arc::clone(&broker);
        let pending = tokio::spawn(async move {
            open.open_direct(&DirectRequest {
                domain: "direct.example".into(),
                destination: request.destination,
            })
            .await
        });
        assert_eq!(server.read_u8().await?, b'D');
        let size = server.read_u16().await? as usize;
        let mut bytes = vec![0; size];
        server.read_exact(&mut bytes).await?;
        pending.abort();
        assert!(pending.await.is_err_and(|error| error.is_cancelled()));
        assert!(broker.poisoned.load(Ordering::SeqCst));
        assert!(broker.open().await.is_err());
        assert!(
            matches!(server.try_read(&mut [0]), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
        );
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Contract deadline."))?
}

#[tokio::test]
async fn lan_tcp_rejects_an_ip_socket_even_when_its_stream_type_is_correct() -> io::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let socket = TcpStream::connect(listener.local_addr()?).await?;
        let (mut peer, _) = listener.accept().await?;
        let (client, mut server) = UnixStream::pair()?;
        let broker = Arc::new(Broker::new(client));
        let task_broker = Arc::clone(&broker);
        let pending = tokio::spawn(async move {
            task_broker
                .open_lan_tcp("192.168.1.1:80".parse().map_err(io::Error::other)?)
                .await
        });
        lan_request(&mut server).await?;
        send_socket(&server, &socket).await?;
        drop(socket);
        assert!(pending.await.map_err(io::Error::other)?.is_err());
        assert!(broker.poisoned.load(Ordering::SeqCst));
        assert_eq!(peer.read(&mut [0]).await?, 0);
        assert!(broker.open().await.is_err());
        assert!(matches!(server.try_read(&mut [0]),Err(e) if e.kind()==io::ErrorKind::WouldBlock));
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Contract deadline."))?
}

#[tokio::test]
async fn mismatched_direct_descriptor_is_closed_and_poisoned_instead_of_relayed() -> io::Result<()>
{
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let socket = TcpStream::connect(listener.local_addr()?).await?;
        let (mut peer, _) = listener.accept().await?;
        let (client, mut server) = UnixStream::pair()?;
        let broker = Arc::new(Broker::new(client));
        let open = Arc::clone(&broker);
        let pending = tokio::spawn(async move {
            open.open_direct(&DirectRequest {
                domain: "direct.example".into(),
                destination: "1.1.1.1:443".parse().map_err(io::Error::other)?,
            })
            .await
        });
        assert_eq!(server.read_u8().await?, b'D');
        let size = server.read_u16().await? as usize;
        let mut bytes = vec![0; size];
        server.read_exact(&mut bytes).await?;
        let queued_broker = Arc::clone(&broker);
        let queued = tokio::spawn(async move { queued_broker.open().await });
        send_socket(&server, &socket).await?;
        drop(socket);
        assert!(pending.await.map_err(io::Error::other)?.is_err());
        assert!(broker.poisoned.load(Ordering::SeqCst));
        assert!(queued.await.map_err(io::Error::other)?.is_err());
        assert!(
            matches!(server.try_read(&mut [0]), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
        );
        assert_eq!(peer.read(&mut [0]).await?, 0);
        assert!(broker.open().await.is_err());
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Contract deadline."))?
}

#[tokio::test]
async fn received_socket_owns_the_descriptor_and_closes_without_a_second_broker_request()
-> io::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let (socket,mut peer) = UnixStream::pair()?;
        let (client, mut server) = UnixStream::pair()?;
        let broker = Arc::new(Broker::new(client));
        let request = Arc::clone(&broker);
        let pending = tokio::spawn(async move { request.open().await });
        assert_eq!(server.read_u8().await?, b'O');
        send_socket(&server, &socket).await?;
        drop(socket);
        let mut received = pending.await.map_err(io::Error::other)??;
        assert!(received.peer_addr()?.is_unnamed());
        received.write_all(b"owned").await?;
        let mut payload = [0; 5];
        peer.read_exact(&mut payload).await?;
        assert_eq!(&payload, b"owned");
        drop(received);
        assert_eq!(peer.read(&mut payload).await?, 0);
        assert!(!broker.poisoned.load(Ordering::SeqCst));
        let mut byte = [0];
        assert!(matches!(server.try_read(&mut byte), Err(ref e) if e.kind() == io::ErrorKind::WouldBlock));
        Ok(())
    }).await.map_err(|_| io::Error::other("Contract deadline."))?
}

#[tokio::test]
async fn missing_descriptor_poison_prevents_reuse_of_an_ambiguous_channel() -> io::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let (client, mut server) = UnixStream::pair()?;
        let broker = Arc::new(Broker::new(client));
        let request = Arc::clone(&broker);
        let pending = tokio::spawn(async move { request.open().await });
        assert_eq!(server.read_u8().await?, b'O');
        server.write_all(b"F").await?;
        assert!(pending.await.map_err(io::Error::other)?.is_err());
        assert!(broker.poisoned.load(Ordering::SeqCst));
        assert!(broker.open().await.is_err());
        let mut byte = [0];
        assert!(matches!(server.try_read(&mut byte), Err(ref e) if e.kind() == io::ErrorKind::WouldBlock));
        Ok(())
    }).await.map_err(|_| io::Error::other("Contract deadline."))?
}

#[tokio::test]
async fn cancellation_poisons_the_broker_before_a_descriptor_can_be_reused() -> io::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let (client, mut server) = UnixStream::pair()?;
        let broker = Arc::new(Broker::new(client));
        let open = Arc::clone(&broker);
        let pending = tokio::spawn(async move { open.open().await });
        assert_eq!(server.read_u8().await?, b'O');
        pending.abort();
        assert!(pending.await.is_err_and(|e| e.is_cancelled()));
        assert!(broker.poisoned.load(Ordering::SeqCst));
        assert!(broker.open().await.is_err());
        let mut byte = [0];
        assert!(matches!(server.try_read(&mut byte), Err(ref e) if e.kind() == io::ErrorKind::WouldBlock));
        Ok(())
    }).await.map_err(|_| io::Error::other("Contract deadline."))?
}

#[tokio::test]
async fn oversized_config_is_rejected_before_allocating_its_body() -> io::Result<()> {
    let (mut sender, mut receiver) = UnixStream::pair()?;
    sender.write_u32(32769).await?;
    assert!(receive_config(&mut receiver).await.is_err());
    Ok(())
}
