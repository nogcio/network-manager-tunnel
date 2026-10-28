use super::*;

#[tokio::test]
async fn unconfigured_authority_refuses_requests_without_losing_channel_or_readiness()
-> io::Result<()> {
    timeout(Duration::from_secs(3), async {
        let draft = nm_tunnel_profile::import_vless("vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example").map_err(io::Error::other)?;
        let profile = draft.validate().map_err(|_| io::Error::other("Invalid fixture."))?;
        let endpoint = "192.0.2.1:443".parse().map_err(io::Error::other)?;
        let authority = Authority {
            profile, endpoint, interface: "never-open-this".into(),
            dns: Ipv4Addr::new(192,0,2,53), lan: crate::lan::Plan::default(),
            fake_state: None, telemetry: Telemetry::default(),
        };
        let (client, server) = UnixStream::pair()?;
        let (ready, observed) = oneshot::channel();
        let relays = std::sync::Arc::new(tokio::sync::Mutex::new(super::super::resources::Relays::default()));
        let mut serving = crate::task::AbortTask(tokio::spawn(authority.serve(server, ready, relays)));
        let broker = wire::Broker::new(client);
        let destination = "203.0.113.1:443".parse().map_err(io::Error::other)?;
        assert!(broker.open_direct(&wire::DirectRequest { domain: "direct.example".into(), destination }).await.is_err());
        assert!(broker.open_policy_tcp(&wire::PolicyRequest { domain: Some("direct.example".into()), destination, transport: wire::LanTransport::Tcp }).await.is_err());
        assert!(broker.open_lan_tcp(destination).await.is_err());
        let (_, query) = crate::dns::dns_query()?;
        assert!(broker.query_dns(&query, false).await.is_err());
        assert!(broker.fake_dns(&query).await.is_err());
        assert!(!broker.poisoned.load(std::sync::atomic::Ordering::SeqCst));
        broker.ready().await?;
        observed.await.map_err(io::Error::other)?;
        // Readiness is one-shot, even after several complete refusals.
        broker.ready().await?;
        assert!((&mut serving.0).await.map_err(io::Error::other)?.is_err());
        Ok(())
    }).await.map_err(|_| io::Error::other("Broker authority deadline."))?
}

#[tokio::test]
async fn endpoint_dial_failure_refuses_only_one_request_and_next_grant_works() -> io::Result<()> {
    timeout(Duration::from_secs(3), async {
        let (client, mut server) = UnixStream::pair()?;
        let broker = wire::Broker::new(client);
        let mut relays = tokio::task::JoinSet::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let (existing, _peer) = tokio::join!(
            tokio::net::TcpStream::connect(listener.local_addr()?),
            listener.accept(),
        );
        let existing = existing?;
        let _peer = _peer?;
        relays.spawn(async move {
            let _socket = existing;
            std::future::pending::<io::Result<()>>().await
        });
        let parent = async {
            assert_eq!(server.read_u8().await?, b'O');
            grant_endpoint(
                &mut server,
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "synthetic",
                )),
                &mut relays,
            )
            .await?;
            assert_eq!(relays.len(), 1);
            assert_eq!(server.read_u8().await?, b'O');
            let (socket, accepted) = tokio::join!(
                tokio::net::TcpStream::connect(listener.local_addr()?),
                listener.accept(),
            );
            let (mut peer, _) = accepted?;
            grant_endpoint(&mut server, socket, &mut relays).await?;
            assert_eq!(relays.len(), 2);
            peer.write_all(b"recovered").await?;
            let mut ack = [0];
            peer.read_exact(&mut ack).await?;
            assert_eq!(ack, *b"!");
            Ok::<_, io::Error>(())
        };
        let worker = async {
            assert_eq!(
                broker.open().await.err().map(|e| e.kind()),
                Some(io::ErrorKind::PermissionDenied)
            );
            assert!(!broker.poisoned.load(std::sync::atomic::Ordering::SeqCst));
            let mut stream = broker.open().await?;
            let mut bytes = [0; 9];
            stream.read_exact(&mut bytes).await?;
            assert_eq!(&bytes, b"recovered");
            stream.write_all(b"!").await?;
            Ok::<_, io::Error>(())
        };
        tokio::try_join!(parent, worker)?;
        relays.abort_all();
        while relays.join_next().await.is_some() {}
        assert!(relays.is_empty());
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Endpoint recovery deadline."))?
}

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
