use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn combined_lan_tcp_uses_only_a_local_payload_channel_and_never_falls_back_on_refusal()
-> io::Result<()> {
    timeout(Duration::from_secs(3), async {
        for refused in [false, true] {
            let mut draft = routed_profile("block")?.to_draft();
            draft.lan_bypass = true;
            draft.dns_interception = true;
            let profile = draft
                .validate()
                .map_err(|_| io::Error::other("Invalid LAN fixture."))?;
            let lan =
                crate::lan::Plan::connected(&[(std::net::Ipv4Addr::new(192, 168, 1, 2), 24)])?
                    .with_interception(true)?;
            let (client, mut server) = UnixStream::pair()?;
            let broker = Arc::new(Broker::new(client));
            let flow_broker = Arc::clone(&broker);
            let (mut application, inbound) = tokio::io::duplex(8192);
            let payload = b"GET / HTTP/1.1\r\nHost: direct.example\r\n\r\nbody";
            application.write_all(payload).await?;
            application.shutdown().await?;
            let flow = tokio::spawn(async move {
                route_tcp(
                    inbound,
                    &profile,
                    &flow_broker,
                    "192.0.2.1:443".parse().map_err(io::Error::other)?,
                    "192.168.1.1:80".parse().map_err(io::Error::other)?,
                    &lan,
                )
                .await
            });
            assert_eq!(server.read_u8().await?, b'L');
            let size = server.read_u16().await? as usize;
            let mut bytes = vec![0; size];
            server.read_exact(&mut bytes).await?;
            let request: wire::LanRequest =
                serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            assert!(matches!(request.transport, wire::LanTransport::Tcp));
            assert_eq!(request.destination.to_string(), "192.168.1.1:80");
            if refused {
                server.write_all(b"N").await?;
                assert_eq!(
                    flow.await
                        .map_err(io::Error::other)?
                        .err()
                        .map(|e| e.kind()),
                    Some(io::ErrorKind::PermissionDenied)
                );
                assert_eq!(application.read(&mut [0]).await?, 0);
            } else {
                let (worker, mut parent) = UnixStream::pair()?;
                wire::send_socket(&server, &worker).await?;
                drop(worker);
                let mut received = Vec::new();
                parent.read_to_end(&mut received).await?;
                assert_eq!(received, payload);
                parent.write_all(b"local reply").await?;
                parent.shutdown().await?;
                let mut reply = Vec::new();
                application.read_to_end(&mut reply).await?;
                flow.await.map_err(io::Error::other)??;
                assert_eq!(reply, b"local reply");
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
async fn intercepted_tcp_dns_uses_selected_resolver_before_hostname_inspection_or_proxy_dispatch()
-> io::Result<()> {
    timeout(Duration::from_secs(3), async {
        let mut draft = routed_profile("block")?.to_draft();
        draft.dns_override = nm_tunnel_profile::DnsOverride::CurrentNetwork;
        draft.dns_interception = true;
        draft.lan_bypass = true;
        let lan = crate::lan::Plan::connected(&[(std::net::Ipv4Addr::new(192, 168, 1, 2), 24)])?
            .with_interception(true)?;
        let profile = draft
            .validate()
            .map_err(|_| io::Error::other("Invalid interception fixture."))?;
        let (client, mut server) = UnixStream::pair()?;
        let broker = Arc::new(Broker::new(client));
        let flow_broker = Arc::clone(&broker);
        let (mut application, inbound) = tokio::io::duplex(8192);
        let task = tokio::spawn(async move {
            route_tcp(
                inbound,
                &profile,
                &flow_broker,
                "192.0.2.1:443".parse().map_err(io::Error::other)?,
                "192.168.1.1:53".parse().map_err(io::Error::other)?,
                &lan,
            )
            .await
        });
        let (_, query) = dns::dns_query()?;
        application.write_u16(query.len() as u16).await?;
        application.write_all(&query).await?;
        assert_eq!(server.read_u8().await?, b'Q');
        assert_eq!(server.read_u8().await?, 1);
        let size = server.read_u16().await? as usize;
        let mut request = vec![0; size];
        server.read_exact(&mut request).await?;
        assert_eq!(request, query);
        let parsed = dns::parse_query(&request)?;
        let mut response = hickory_proto::op::Message::new(
            parsed.id,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        response.queries = parsed.queries;
        let response = response.to_vec().map_err(io::Error::other)?;
        server.write_all(b"A").await?;
        server.write_u16(response.len() as u16).await?;
        server.write_all(&response).await?;
        let size = application.read_u16().await? as usize;
        let mut received = vec![0; size];
        application.read_exact(&mut received).await?;
        assert_eq!(received, response);
        application.shutdown().await?;
        task.await.map_err(io::Error::other)??;
        assert!(!broker.poisoned.load(Ordering::SeqCst));
        assert!(matches!(server.try_read(&mut [0]),Err(e) if e.kind()==io::ErrorKind::WouldBlock));
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Contract deadline."))?
}

#[tokio::test]
async fn readiness_endpoint_refusal_never_queries_any_resolver_or_destination() -> io::Result<()> {
    timeout(Duration::from_secs(3), async {
        let mut profiles = vec![crate::test_support::source_profile()?];
        for dns in [
            nm_tunnel_profile::DnsOverride::Inherit,
            nm_tunnel_profile::DnsOverride::CurrentNetwork,
            nm_tunnel_profile::DnsOverride::ProxyIpv4("9.9.9.9".parse().map_err(io::Error::other)?),
        ] {
            let mut draft = routed_profile("block")?.to_draft();
            draft.dns_override = dns;
            // The manual override cannot coexist with a Direct rule.
            draft.tcp_domain_policy = None;
            profiles.push(
                draft
                    .validate()
                    .map_err(|_| io::Error::other("Invalid DNS fixture."))?,
            );
        }
        for profile in profiles {
            let (client, mut server) = UnixStream::pair()?;
            let broker = Arc::new(Broker::new(client));
            let probe_broker = Arc::clone(&broker);
            let pending = tokio::spawn(async move {
                probe(
                    &profile,
                    &probe_broker,
                    "192.0.2.1:443".parse().map_err(io::Error::other)?,
                )
                .await
            });
            assert_eq!(server.read_u8().await?, b'O');
            server.write_all(b"N").await?;
            assert!(pending.await.map_err(io::Error::other)?.is_err());
            assert!(!broker.poisoned.load(Ordering::SeqCst));
            assert!(
                matches!(server.try_read(&mut [0]), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
            );
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Contract deadline."))?
}

fn routed_profile(action: &str) -> io::Result<nm_tunnel_profile::Profile> {
    let mut draft = nm_tunnel_profile::import_vless(
        "vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example",
    ).map_err(io::Error::other)?;
    draft.tcp_domain_policy = Some(
        nm_tunnel_profile::TcpDomainPolicy::from_json(&format!(
            r#"{{"version":1,"rules":[{{"domain":["direct.example"],"action":"{action}"}}]}}"#,
        ))
        .map_err(io::Error::other)?,
    );
    draft
        .validate()
        .map_err(|_| io::Error::other("Invalid policy fixture."))
}

// Synthetic ClientHello, used to exercise routing admission and byte ownership,
// not as a TLS parser conformance suite or a real provider fixture.
fn client_hello() -> Vec<u8> {
    let mut bytes = vec![0x16, 3, 1, 0, 70, 1, 0, 0, 66, 3, 3];
    bytes.extend_from_slice(&[0; 32]);
    bytes.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0, 0, 23, 0, 0, 0, 19, 0, 17, 0, 0, 14]);
    bytes.extend_from_slice(b"direct.example");
    bytes
}

#[tokio::test]
async fn blocked_hostname_closes_inbound_without_any_broker_request() -> io::Result<()> {
    timeout(Duration::from_secs(3), async {
        for payload in [
            b"GET / HTTP/1.1\r\nHost: direct.example\r\n\r\n".to_vec(),
            client_hello(),
        ] {
            let (client, server) = UnixStream::pair()?;
            let broker = Broker::new(client);
            let profile = routed_profile("block")?;
            let (mut application, inbound) = tokio::io::duplex(8192);
            application.write_all(&payload).await?;
            route_tcp(
                inbound,
                &profile,
                &broker,
                "192.0.2.1:443".parse().map_err(io::Error::other)?,
                "1.1.1.1:443".parse().map_err(io::Error::other)?,
                &crate::lan::Plan::default(),
            )
            .await?;
            assert_eq!(application.read(&mut [0]).await?, 0);
            assert!(
                matches!(server.try_read(&mut [0]), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
            );
            assert!(!broker.poisoned.load(Ordering::SeqCst));
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Contract deadline."))?
}

#[tokio::test]
async fn direct_tcp_replays_inspected_prefix_once_and_refusal_never_falls_back_to_proxy()
-> io::Result<()> {
    timeout(Duration::from_secs(3), async {
        for refused in [false, true] {
            let destination = "1.1.1.1:443".parse().map_err(io::Error::other)?;
            let (socket,mut peer) = UnixStream::pair()?;
            let (client, mut server) = UnixStream::pair()?;
            let broker = Arc::new(Broker::new(client));
            let profile = routed_profile("direct")?;
            let (mut application, inbound) = tokio::io::duplex(8192);
            let request = b"GET /private HTTP/1.1\r\nHost: direct.example\r\n\r\nbody";
            application.write_all(request).await?;
            application.shutdown().await?;
            let worker_broker = Arc::clone(&broker);
            let flow = tokio::spawn(async move {
                route_tcp(inbound, &profile, &worker_broker, "192.0.2.1:443".parse().map_err(io::Error::other)?, destination, &crate::lan::Plan::default()).await
            });
            assert_eq!(server.read_u8().await?, b'D');
            let size = server.read_u16().await? as usize;
            let mut bytes = vec![0; size];
            server.read_exact(&mut bytes).await?;
            let sent: wire::DirectRequest = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            assert_eq!(sent.domain, "direct.example");
            assert_eq!(sent.destination, destination);
            if refused {
                server.write_all(b"N").await?;
                assert_eq!(flow.await.map_err(io::Error::other)?.err().map(|e| e.kind()), Some(io::ErrorKind::PermissionDenied));
                assert_eq!(application.read(&mut [0]).await?, 0);
                assert!(matches!(server.try_read(&mut [0]), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
                assert!(!broker.poisoned.load(Ordering::SeqCst));
            } else {
                wire::send_socket(&server, &socket).await?;
                drop(socket);
                let mut received = Vec::new();
                peer.read_to_end(&mut received).await?;
                assert_eq!(received, request);
                peer.write_all(b"response").await?;
                peer.shutdown().await?;
                let mut response = Vec::new();
                application.read_to_end(&mut response).await?;
                flow.await.map_err(io::Error::other)??;
                assert_eq!(response, b"response");
            }
        }
        Ok(())
    }).await.map_err(|_| io::Error::other("Contract deadline."))?
}

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
