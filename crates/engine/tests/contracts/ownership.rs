use nm_tunnel_engine::{Error, connect_tcp, connect_udp};
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
