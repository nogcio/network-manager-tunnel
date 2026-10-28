use nm_tunnel_engine::{
    EndpointStream, Error, connect_tcp, connect_tcp_domain, connect_udp, connect_udp_domain,
};
use nm_tunnel_profile::{Draft, Profile, Security};
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

fn profile(endpoint: SocketAddr) -> Result<Profile, Box<dyn std::error::Error>> {
    Draft {
        name: "Synthetic ownership fixture".into(),
        server: endpoint.ip().to_string(),
        port: endpoint.port().to_string(),
        credential: "12345678-1234-4234-8234-123456789abc".to_owned().into(),
        security: Security::Tls,
        server_name: "peer.example".into(),
        vision: false,
        ..Default::default()
    }
    .validate()
    .map_err(|_| "invalid fixture".into())
}

#[tokio::test]
async fn domain_targets_reject_without_io_and_cancel_owned_transport_without_redial()
-> Result<(), Box<dyn std::error::Error>> {
    timeout(Duration::from_secs(5), async {
        let endpoint: SocketAddr = "192.0.2.1:443".parse()?;
        for udp in [false, true] {
        let mut draft = profile(endpoint)?.to_draft();
        if udp {
            draft.source_policy = Some(nm_tunnel_profile::SourcePolicy::from_json(
                r#"{"version":1,"dns":{"address":"1.1.1.1","port":853,"transport":"tls","via_proxy":true,"tls_name":"1.1.1.1"},"domain_policy":"{\"version\":1,\"rules\":[{\"domain_suffix\":[\"direct.example\"],\"action\":\"direct\"}]}","fakeip_range":"198.18.0.0/15","tun_address":"172.19.0.1","tun_prefix":30,"mtu":1400}"#,
            )?);
            draft.fake_ip = true;
            draft.dns_interception = true;
        }
        let profile = draft.validate().map_err(|_| "Invalid XUDP fixture")?;
        for (name, port, mismatch) in [
            ("https://private-token.example", 443, false),
            ("Upper.example", 443, false),
            ("127.0.0.1", 443, false),
            ("owned.example", 0, false),
            ("owned.example", 443, true),
        ] {
            let (input, mut peer) = tokio::net::UnixStream::pair()?;
            let input = EndpointStream::relayed(input, endpoint)?;
            let approved = if mismatch {
                "192.0.2.2:443".parse()?
            } else {
                endpoint
            };
            let result = if udp {
                connect_udp_domain(&profile, input, approved, name, port).await.map(|_| ())
            } else {
                connect_tcp_domain(&profile, input, approved, name, port).await.map(|_| ())
            };
            let error = result
                .err()
                .ok_or("Invalid domain flow accepted")?;
            assert!(matches!(error, Error::Endpoint | Error::Configuration));
            assert!(!error.to_string().contains("private-token"));
            let mut bytes = Vec::new();
            peer.read_to_end(&mut bytes).await?;
            assert!(bytes.is_empty());
        }
        let (input, mut peer) = tokio::net::UnixStream::pair()?;
        let input = EndpointStream::relayed(input, endpoint)?;
        let task = tokio::spawn(async move {
            if udp {
                connect_udp_domain(&profile, input, endpoint, "owned.example", 443).await.map(|_| ())
            } else {
                connect_tcp_domain(&profile, input, endpoint, "owned.example", 443).await.map(|_| ())
            }
        });
        assert_eq!(peer.read_u8().await?, 22);
        task.abort();
        assert!(task.await.is_err_and(|e| e.is_cancelled()));
        peer.read_to_end(&mut Vec::new()).await?;
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await?
}

#[tokio::test]
async fn relayed_endpoint_metadata_is_checked_before_handshake_and_cancellation_owns_the_channel()
-> Result<(), Box<dyn std::error::Error>> {
    timeout(Duration::from_secs(5), async {
        let endpoint: SocketAddr = "192.0.2.1:443".parse()?;
        for udp in [false, true] {
            for mismatch in [false, true] {
                let (channel, mut peer) = tokio::net::UnixStream::pair()?;
                let input = EndpointStream::relayed(channel, endpoint)?;
                let profile = profile(endpoint)?;
                let approved = if mismatch {
                    "192.0.2.2:443".parse()?
                } else {
                    endpoint
                };
                let task = tokio::spawn(async move {
                    if udp {
                        connect_udp(&profile, input, approved, endpoint)
                            .await
                            .map(|_| ())
                    } else {
                        connect_tcp(&profile, input, approved, endpoint)
                            .await
                            .map(|_| ())
                    }
                });
                if mismatch {
                    assert!(matches!(task.await?, Err(Error::Endpoint)));
                } else {
                    assert_eq!(peer.read_u8().await?, 22);
                    task.abort();
                    assert!(task.await.is_err_and(|e| e.is_cancelled()));
                }
                let mut bytes = Vec::new();
                peer.read_to_end(&mut bytes).await?;
                if mismatch {
                    assert!(bytes.is_empty());
                }
            }
        }
        let (channel, mut peer) = tokio::net::UnixStream::pair()?;
        assert!(EndpointStream::relayed(channel, "0.0.0.0:0".parse()?).is_err());
        assert_eq!(peer.read(&mut [0]).await?, 0);
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await?
}

#[tokio::test]
async fn mismatched_approved_peer_closes_the_owned_socket_without_handshake()
-> Result<(), Box<dyn std::error::Error>> {
    timeout(Duration::from_secs(5), async {
        for udp in [false, true] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let endpoint = listener.local_addr()?;
            let socket = TcpStream::connect(endpoint).await?;
            let (mut peer, _) = listener.accept().await?;
            let profile = profile(endpoint)?;
            let mut wrong = endpoint;
            wrong.set_ip(Ipv4Addr::new(127, 0, 0, 2).into());
            let result = if udp {
                connect_udp(&profile, socket, wrong, endpoint)
                    .await
                    .map(|_| ())
            } else {
                connect_tcp(&profile, socket, wrong, endpoint)
                    .await
                    .map(|_| ())
            };
            assert!(matches!(result, Err(Error::Endpoint)));
            let mut byte = [0];
            assert_eq!(peer.read(&mut byte).await?, 0);
            assert!(
                std::future::poll_fn(|cx| std::task::Poll::Ready(
                    listener.poll_accept(cx).is_pending()
                ))
                .await
            );
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await?
}

#[tokio::test]
async fn cancelling_protocol_setup_releases_the_socket_without_redial()
-> Result<(), Box<dyn std::error::Error>> {
    timeout(Duration::from_secs(5), async {
        for udp in [false, true] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let endpoint = listener.local_addr()?;
            let socket = TcpStream::connect(endpoint).await?;
            let (mut peer, _) = listener.accept().await?;
            let profile = profile(endpoint)?;
            let setup = tokio::spawn(async move {
                if udp {
                    connect_udp(&profile, socket, endpoint, endpoint)
                        .await
                        .map(|_| ())
                } else {
                    connect_tcp(&profile, socket, endpoint, endpoint)
                        .await
                        .map(|_| ())
                }
            });
            let mut first = [0];
            peer.read_exact(&mut first).await?;
            assert_eq!(first[0], 22, "TLS ClientHello readiness");
            setup.abort();
            assert!(setup.await.is_err_and(|error| error.is_cancelled()));
            let mut remaining = Vec::new();
            (&mut peer).take(8192).read_to_end(&mut remaining).await?;
            assert!(remaining.len() < 8192, "socket did not reach EOF");
            peer.shutdown().await?;
            assert!(
                std::future::poll_fn(|cx| std::task::Poll::Ready(
                    listener.poll_accept(cx).is_pending()
                ))
                .await
            );
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await?
}
