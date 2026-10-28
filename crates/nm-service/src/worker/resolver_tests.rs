use super::*;
use crate::wire::Broker;
use crate::{
    dns::{MAX_DNS_BYTES, valid_uplink_server},
    supervisor::uplink_dns::exchange,
};
use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::{
    op::{Query, ResponseCode},
    rr::{Name, RecordType},
};
use std::net::Ipv4Addr;
use std::sync::{Arc, atomic::Ordering};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

fn fixture() -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut query = Message::new(7, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(
        Name::from_utf8("private.example.").map_err(io::Error::other)?,
        RecordType::A,
    ));
    let mut reply = Message::new(7, MessageType::Response, OpCode::Query);
    reply.queries = query.queries.clone();
    reply.metadata.response_code = ResponseCode::NXDomain;
    Ok((
        query.to_vec().map_err(io::Error::other)?,
        reply.to_vec().map_err(io::Error::other)?,
    ))
}

fn relay_profile(
    mode: nm_tunnel_profile::DnsOverride,
    intercept: bool,
) -> io::Result<nm_tunnel_profile::Profile> {
    let mut draft = nm_tunnel_profile::import_vless("vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example")
        .map_err(|_| io::Error::other("Invalid relay fixture."))?;
    draft.dns_override = mode;
    draft.dns_interception = intercept;
    draft
        .validate()
        .map_err(|_| io::Error::other("Invalid relay fixture."))
}

#[test]
fn interception_dispatch_is_explicit_ipv4_port53_only_and_preserves_legacy_behavior()
-> io::Result<()> {
    use nm_tunnel_profile::DnsOverride;
    for mode in [
        DnsOverride::Inherit,
        DnsOverride::CurrentNetwork,
        DnsOverride::ProxyIpv4(Ipv4Addr::new(8, 8, 8, 8)),
    ] {
        for enabled in [false, true] {
            let profile = relay_profile(mode, enabled)?;
            for (destination, expected) in [
                ("9.9.9.9:53", enabled),
                ("192.168.1.1:53", enabled),
                (
                    "198.18.0.2:53",
                    enabled || mode == DnsOverride::CurrentNetwork,
                ),
                ("9.9.9.9:443", false),
                ("9.9.9.9:853", false),
                ("[2001:db8::1]:53", false),
            ] {
                assert_eq!(
                    handles(&profile, destination.parse().map_err(io::Error::other)?),
                    expected
                );
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn invalid_intercepted_payload_never_requests_any_socket_or_fallback() -> io::Result<()> {
    use nm_tunnel_profile::DnsOverride;
    let (query, response) = fixture()?;
    for mode in [
        DnsOverride::Inherit,
        DnsOverride::CurrentNetwork,
        DnsOverride::ProxyIpv4(Ipv4Addr::new(8, 8, 8, 8)),
    ] {
        let profile = relay_profile(mode, true)?;
        let (client, server) = UnixStream::pair()?;
        let broker = Broker::new(client);
        for tcp in [false, true] {
            let mut duplicate = Message::from_vec(&query).map_err(io::Error::other)?;
            duplicate.queries.push(duplicate.queries[0].clone());
            for payload in [
                b"not-dns-private-token".to_vec(),
                response.clone(),
                duplicate.to_vec().map_err(io::Error::other)?,
                vec![0; MAX_DNS_BYTES + 1],
            ] {
                let error = relay_query(
                    &profile,
                    &broker,
                    "192.0.2.1:443".parse().map_err(io::Error::other)?,
                    &payload,
                    tcp,
                )
                .await
                .err()
                .ok_or_else(invalid)?;
                assert_eq!(error.to_string(), "Invalid or unsupported DNS exchange.");
                assert!(!broker.poisoned.load(Ordering::SeqCst));
                assert!(
                    matches!(server.try_read(&mut [0]), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
                );
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn selected_network_relay_preserves_udp_tcp_and_negative_answers_without_a_proxy_request()
-> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (query, response) = fixture()?;
        let (client, mut server) = UnixStream::pair()?;
        let broker = Arc::new(Broker::new(client));
        for tcp in [false, true] {
            let profile = relay_profile(nm_tunnel_profile::DnsOverride::CurrentNetwork, true)?;
            let task_broker = Arc::clone(&broker);
            let request = query.clone();
            let task = tokio::spawn(async move {
                relay_query(
                    &profile,
                    &task_broker,
                    "192.0.2.1:443".parse().map_err(io::Error::other)?,
                    &request,
                    tcp,
                )
                .await
            });
            receive_request(&mut server, tcp, &query).await?;
            reply(&mut server, &response).await?;
            assert_eq!(task.await.map_err(io::Error::other)??, response);
            assert!(!broker.poisoned.load(Ordering::SeqCst));
        }
        assert!(
            matches!(server.try_read(&mut [0]), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
        );
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Contract deadline."))?
}

#[tokio::test(start_paused = true)]
async fn tunneled_dns_deadline_bounds_broker_wait_and_never_switches_to_uplink_dns()
-> io::Result<()> {
    use nm_tunnel_profile::DnsOverride;
    for mode in [
        DnsOverride::Inherit,
        DnsOverride::ProxyIpv4(Ipv4Addr::new(8, 8, 8, 8)),
    ] {
        for tcp in [false, true] {
            let (query, _) = fixture()?;
            let profile = relay_profile(mode, true)?;
            let (client, mut server) = UnixStream::pair()?;
            let broker = Arc::new(Broker::new(client));
            let task_broker = Arc::clone(&broker);
            let task = tokio::spawn(async move {
                relay_query(
                    &profile,
                    &task_broker,
                    "192.0.2.1:443".parse().map_err(io::Error::other)?,
                    &query,
                    tcp,
                )
                .await
            });
            // Waiting for a connected proxy FD, never a Direct or uplink DNS grant.
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), server.read_u8()).await??,
                b'O'
            );
            tokio::time::advance(Duration::from_secs(10)).await;
            let result = tokio::time::timeout(Duration::from_secs(1), task)
                .await?
                .map_err(io::Error::other)?;
            assert_eq!(
                result.err().map(|e| e.to_string()),
                Some("DNS relay deadline.".into())
            );
            assert!(broker.poisoned.load(Ordering::SeqCst));
            assert!(
                matches!(server.try_read(&mut [0]), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn cancellation_after_proxy_socket_admission_closes_it_without_poison_or_direct_fallback()
-> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let endpoint: SocketAddr = "192.0.2.1:443".parse().map_err(io::Error::other)?;
        let (socket, mut peer) = UnixStream::pair()?;
        let mut draft = relay_profile(nm_tunnel_profile::DnsOverride::Inherit, true)?.to_draft();
        draft.port = endpoint.port().to_string();
        let profile = draft.validate().map_err(|_| invalid())?;
        let (query, _) = fixture()?;
        let (client, mut server) = UnixStream::pair()?;
        let broker = Arc::new(Broker::new(client));
        let task_broker = Arc::clone(&broker);
        let task = tokio::spawn(async move {
            relay_query(&profile, &task_broker, endpoint, &query, true).await
        });
        assert_eq!(server.read_u8().await?, b'O');
        crate::wire::send_socket(&server, &socket).await?;
        drop(socket);
        // Readiness, not a sleep: the verified TLS handshake has started using
        // the owned descriptor, while this synthetic peer deliberately stalls.
        peer.read_u8().await?;
        task.abort();
        assert!(task.await.is_err_and(|e| e.is_cancelled()));
        let mut buffered = Vec::new();
        peer.read_to_end(&mut buffered).await?;
        assert!(!broker.poisoned.load(Ordering::SeqCst));
        assert!(
            matches!(server.try_read(&mut [0]), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
        );
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Contract deadline."))?
}

#[tokio::test]
async fn explicit_proxy_refusal_does_not_retry_the_query_through_uplink_dns() -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        for tcp in [false, true] {
            let (query, _) = fixture()?;
            let profile = relay_profile(
                nm_tunnel_profile::DnsOverride::ProxyIpv4(Ipv4Addr::new(8, 8, 8, 8)),
                true,
            )?;
            let (client, mut server) = UnixStream::pair()?;
            let broker = Arc::new(Broker::new(client));
            let task_broker = Arc::clone(&broker);
            let task = tokio::spawn(async move {
                relay_query(
                    &profile,
                    &task_broker,
                    "192.0.2.1:443".parse().map_err(io::Error::other)?,
                    &query,
                    tcp,
                )
                .await
            });
            assert_eq!(server.read_u8().await?, b'O');
            server.write_all(b"N").await?;
            assert_eq!(
                task.await
                    .map_err(io::Error::other)?
                    .err()
                    .map(|e| e.kind()),
                Some(io::ErrorKind::PermissionDenied)
            );
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

async fn receive_request(server: &mut UnixStream, tcp: bool, query: &[u8]) -> io::Result<()> {
    assert_eq!(server.read_u8().await?, b'Q');
    assert_eq!(server.read_u8().await?, u8::from(tcp));
    let size = server.read_u16().await? as usize;
    let mut received = vec![0; size];
    server.read_exact(&mut received).await?;
    assert_eq!(received, query);
    Ok(())
}

async fn reply(server: &mut UnixStream, response: &[u8]) -> io::Result<()> {
    server.write_all(b"A").await?;
    server.write_u16(response.len() as u16).await?;
    server.write_all(response).await
}

#[tokio::test]
async fn invalid_dns_or_uplink_targets_fail_before_privileged_socket_creation() -> io::Result<()> {
    let (query, response) = fixture()?;
    assert!(parse_query(&response).is_err());
    for bytes in [
        vec![],
        vec![0; MAX_DNS_BYTES + 1],
        b"private-token".to_vec(),
    ] {
        assert_eq!(
            exchange(
                nm_tunnel_profile::DnsOverride::CurrentNetwork,
                &bytes,
                false,
                Ipv4Addr::new(1, 1, 1, 1),
                "must-never-be-opened"
            )
            .await
            .err()
            .map(|e| e.to_string()),
            Some("Invalid or unsupported DNS exchange.".into())
        );
    }
    for server in [
        Ipv4Addr::LOCALHOST,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::BROADCAST,
        Ipv4Addr::new(224, 0, 0, 1),
        dns::INTERNAL_DNS,
    ] {
        assert_eq!(
            exchange(
                nm_tunnel_profile::DnsOverride::CurrentNetwork,
                &query,
                false,
                server,
                "must-never-be-opened"
            )
            .await
            .err()
            .map(|e| e.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
    }
    assert!(valid_uplink_server(Ipv4Addr::new(192, 168, 1, 1)));
    for mode in [
        nm_tunnel_profile::DnsOverride::Inherit,
        nm_tunnel_profile::DnsOverride::ProxyIpv4(Ipv4Addr::new(8, 8, 8, 8)),
    ] {
        assert_eq!(
            exchange(
                mode,
                &query,
                false,
                Ipv4Addr::new(192, 168, 1, 1),
                "must-never-be-opened"
            )
            .await
            .err()
            .map(|e| e.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
    }
    let parsed = parse_query(&query)?;
    validate_response(&parsed, &response)?; // DNS negative answers are preserved, not fallback triggers.
    let mut wrong = Message::from_vec(&response).map_err(io::Error::other)?;
    wrong.metadata.id = 8;
    assert!(validate_response(&parsed, &wrong.to_vec().map_err(io::Error::other)?).is_err());
    Ok(())
}

#[tokio::test]
async fn dns_broker_validates_replies_and_never_retries_or_corrupts_the_fd_channel()
-> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (query, response) = fixture()?;
        let (client, mut server) = UnixStream::pair()?;
        let broker = Arc::new(Broker::new(client));
        // Local rejection does not write to or poison the channel.
        assert!(
            broker
                .query_dns(b"private-invalid-query", false)
                .await
                .is_err()
        );
        assert!(!broker.poisoned.load(Ordering::SeqCst));
        assert!(
            matches!(server.try_read(&mut [0]), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
        );
        for tcp in [false, true] {
            let task_broker = Arc::clone(&broker);
            let request = query.clone();
            let pending = tokio::spawn(async move { task_broker.query_dns(&request, tcp).await });
            receive_request(&mut server, tcp, &query).await?;
            reply(&mut server, &response).await?;
            assert_eq!(pending.await.map_err(io::Error::other)??, response);
            assert!(!broker.poisoned.load(Ordering::SeqCst));
        }
        let task_broker = Arc::clone(&broker);
        let request = query.clone();
        let pending = tokio::spawn(async move { task_broker.query_dns(&request, false).await });
        receive_request(&mut server, false, &query).await?;
        let mut wrong = Message::from_vec(&response).map_err(io::Error::other)?;
        wrong.metadata.id = 8;
        reply(&mut server, &wrong.to_vec().map_err(io::Error::other)?).await?;
        assert!(pending.await.map_err(io::Error::other)?.is_err());
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
async fn cancellation_during_dns_exchange_poisons_but_explicit_refusal_does_not() -> io::Result<()>
{
    tokio::time::timeout(Duration::from_secs(3), async {
        let (query, _) = fixture()?;
        let (client, mut server) = UnixStream::pair()?;
        let broker = Arc::new(Broker::new(client));
        for cancel in [false, true] {
            let task_broker = Arc::clone(&broker);
            let request = query.clone();
            let pending = tokio::spawn(async move { task_broker.query_dns(&request, false).await });
            receive_request(&mut server, false, &query).await?;
            if cancel {
                pending.abort();
                assert!(pending.await.is_err_and(|e| e.is_cancelled()));
                assert!(broker.poisoned.load(Ordering::SeqCst));
            } else {
                server.write_all(b"N").await?;
                assert_eq!(
                    pending
                        .await
                        .map_err(io::Error::other)?
                        .err()
                        .map(|e| e.kind()),
                    Some(io::ErrorKind::PermissionDenied)
                );
                assert!(!broker.poisoned.load(Ordering::SeqCst));
            }
        }
        assert!(broker.query_dns(&query, true).await.is_err());
        assert!(
            matches!(server.try_read(&mut [0]), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
        );
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Contract deadline."))?
}

#[tokio::test]
async fn tcp_dns_relay_preserves_frames_and_transport_without_opening_a_destination_socket()
-> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (query, response) = fixture()?;
        let (client, mut server) = UnixStream::pair()?;
        let broker = Broker::new(client);
        let (application, inbound) = tokio::io::duplex(8192);
        let profile = relay_profile(nm_tunnel_profile::DnsOverride::CurrentNetwork, false)?;
        let task = tokio::spawn(async move {
            serve_tcp(
                inbound,
                &broker,
                &profile,
                "192.0.2.1:443".parse().map_err(io::Error::other)?,
            )
            .await
        });
        let mut application = framed(application);
        for _ in 0..2 {
            application.send(query.as_slice()).await?;
            receive_request(&mut server, true, &query).await?;
            reply(&mut server, &response).await?;
            assert_eq!(
                application.next().await.ok_or_else(invalid)??.as_ref(),
                response
            );
        }
        drop(application);
        task.await.map_err(io::Error::other)??;
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Contract deadline."))?
}

#[tokio::test]
async fn oversized_client_frame_is_rejected_before_any_dns_broker_request() -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (client, server) = UnixStream::pair()?;
        let broker = Arc::new(Broker::new(client));
        let (mut application, inbound) = tokio::io::duplex(8192);
        let worker_broker = Arc::clone(&broker);
        let profile = relay_profile(nm_tunnel_profile::DnsOverride::CurrentNetwork, true)?;
        let worker = tokio::spawn(async move {
            serve_tcp(
                inbound,
                &worker_broker,
                &profile,
                "192.0.2.1:443".parse().map_err(io::Error::other)?,
            )
            .await
        });
        application.write_u16((MAX_DNS_BYTES + 1) as u16).await?;
        assert!(worker.await.map_err(io::Error::other)?.is_err());
        assert!(!broker.poisoned.load(Ordering::SeqCst));
        assert!(
            matches!(server.try_read(&mut [0]), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
        );
        assert_eq!(application.read(&mut [0]).await?, 0);
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Contract deadline."))?
}
