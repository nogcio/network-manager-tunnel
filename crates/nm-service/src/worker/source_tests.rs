use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn source_arbitrary_port_dns_replays_two_frames_once_without_destination_grants()
-> io::Result<()> {
    timeout(Duration::from_secs(3), async {
        let profile = crate::test_support::source_profile()?;
        let (client, mut server) = UnixStream::pair()?;
        let broker = Broker::new(client);
        let (inbound, mut application) = UnixStream::pair()?;
        let (_, bytes) = dns::dns_query()?;
        let mut query = dns::parse_query(&bytes)?;
        query.queries[0].set_query_type(hickory_proto::rr::RecordType::TXT);
        let query = query.to_vec().map_err(io::Error::other)?;
        for _ in 0..2 {
            application.write_u16(query.len() as u16).await?;
            application.write_all(&query).await?;
        }
        application.shutdown().await?;
        let flow = tokio::spawn(async move {
            route_tcp(
                inbound,
                &profile,
                &broker,
                "192.0.2.1:443".parse().map_err(io::Error::other)?,
                "10.2.3.4:5354".parse().map_err(io::Error::other)?,
                &crate::lan::Plan::default(),
            )
            .await
        });
        for _ in 0..2 {
            assert_eq!(server.read_u8().await?, b'Q');
            assert_eq!(server.read_u8().await?, 1);
            let size = server.read_u16().await? as usize;
            let mut received = vec![0; size];
            server.read_exact(&mut received).await?;
            assert_eq!(received, query);
            let parsed = dns::parse_query(&received)?;
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
        }
        flow.await.map_err(io::Error::other)??;
        assert_eq!(application.read(&mut [0]).await?, 0);
        assert_eq!(server.read(&mut [0]).await?, 0);
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Source DNS replay deadline."))?
}

#[tokio::test]
async fn source_bittorrent_and_domain_blocks_precede_reverse_dns_and_all_grants() -> io::Result<()>
{
    timeout(Duration::from_secs(3), async {
        for (payload, destination) in [
            (b"\x13BitTorrent protocol".as_slice(), "198.18.0.4:443"),
            (
                b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n".as_slice(),
                "10.1.2.3:80",
            ),
        ] {
            let profile = crate::test_support::source_profile()?;
            let (client, server) = UnixStream::pair()?;
            let broker = Broker::new(client);
            let (inbound, mut peer) = UnixStream::pair()?;
            peer.write_all(payload).await?;
            route_tcp(
                inbound,
                &profile,
                &broker,
                "192.0.2.1:443".parse().map_err(io::Error::other)?,
                destination.parse().map_err(io::Error::other)?,
                &crate::lan::Plan::default(),
            )
            .await?;
            assert!(
                matches!(server.try_read(&mut [0]), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
            );
            assert_eq!(peer.read(&mut [0]).await?, 0);
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Source route contract deadline."))?
}

#[tokio::test]
async fn source_domain_proxy_precedes_non_public_direct_and_refusal_never_switches_outbound()
-> io::Result<()> {
    timeout(Duration::from_secs(3), async {
        for proxy in [false, true] {
            let profile = crate::test_support::source_profile()?;
            let (client, mut server) = UnixStream::pair()?;
            let broker = Broker::new(client);
            let (inbound, mut peer) = UnixStream::pair()?;
            peer.write_all(if proxy {
                b"GET / HTTP/1.1\r\nHost: proxied.example\r\n\r\n"
            } else {
                b"GET / HTTP/1.1\r\nHost: unknown.example\r\n\r\n"
            })
            .await?;
            let task = tokio::spawn(async move {
                route_tcp(
                    inbound,
                    &profile,
                    &broker,
                    "192.0.2.1:443".parse().map_err(io::Error::other)?,
                    "10.2.3.4:80".parse().map_err(io::Error::other)?,
                    &crate::lan::Plan::default(),
                )
                .await
            });
            assert_eq!(server.read_u8().await?, if proxy { b'O' } else { b'P' });
            if !proxy {
                let size = server.read_u16().await? as usize;
                let mut bytes = vec![0; size];
                server.read_exact(&mut bytes).await?;
                let request: wire::PolicyRequest =
                    serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                assert_eq!(request.destination.to_string(), "10.2.3.4:80");
                assert_eq!(request.domain.as_deref(), Some("unknown.example"));
            }
            server.write_all(b"N").await?;
            assert!(task.await.map_err(io::Error::other)?.is_err());
            assert_eq!(server.read(&mut [0]).await?, 0);
            assert_eq!(peer.read(&mut [0]).await?, 0);
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Source route contract deadline."))?
}
