use super::*;

#[tokio::test]
async fn received_socket_owns_the_descriptor_and_closes_without_a_second_broker_request()
-> io::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let endpoint = listener.local_addr()?;
        let socket = TcpStream::connect(endpoint).await?;
        let (mut peer, _) = listener.accept().await?;
        let (client, mut server) = UnixStream::pair()?;
        let broker = Arc::new(Broker::new(client));
        let request = Arc::clone(&broker);
        let pending = tokio::spawn(async move { request.open().await });
        assert_eq!(server.read_u8().await?, b'O');
        send_socket(&server, &socket).await?;
        drop(socket);
        let mut received = pending.await.map_err(io::Error::other)??;
        assert_eq!(received.peer_addr()?, endpoint);
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
