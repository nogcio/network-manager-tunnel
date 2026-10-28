use super::*;
use std::{
    net::Ipv4Addr,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};

fn profile(enabled: bool, action: &str) -> io::Result<nm_tunnel_profile::Profile> {
    let mut draft=nm_tunnel_profile::import_vless("vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example").map_err(io::Error::other)?;
    draft.dns_override = nm_tunnel_profile::DnsOverride::CurrentNetwork;
    draft.fake_ip = enabled;
    draft.dns_interception = enabled;
    draft.tcp_domain_policy = Some(
        nm_tunnel_profile::TcpDomainPolicy::from_json(&format!(
            r#"{{"version":1,"rules":[{{"domain":["owned.example"],"action":"{action}"}}]}}"#
        ))
        .map_err(io::Error::other)?,
    );
    draft
        .validate()
        .map_err(|_| io::Error::other("Invalid FakeIP fixture."))
}

#[tokio::test]
async fn synthetic_destinations_without_ownership_never_reach_any_outbound() -> io::Result<()> {
    timeout(Duration::from_secs(3), async {
        let (client, mut server) = UnixStream::pair()?;
        let broker = Arc::new(Broker::new(client));
        assert!(
            resolve(
                &profile(false, "proxy")?,
                &broker,
                "192.0.2.1:443".parse().map_err(io::Error::other)?,
                "198.18.0.4:443".parse().map_err(io::Error::other)?,
                &Plan::default()
            )
            .await
            .is_err()
        );
        assert!(matches!(server.try_read(&mut [0]),Err(e) if e.kind()==io::ErrorKind::WouldBlock));
        let task_broker = Arc::clone(&broker);
        let task = tokio::spawn(async move {
            resolve(
                &profile(true, "proxy")?,
                &task_broker,
                "192.0.2.1:443".parse().map_err(io::Error::other)?,
                "198.18.0.4:443".parse().map_err(io::Error::other)?,
                &Plan::default(),
            )
            .await
        });
        let mut request = [0; 8];
        server.read_exact(&mut request).await?;
        assert_eq!(request, [b'F', b'R', 0, 4, 198, 18, 0, 4]);
        server.write_all(b"N").await?;
        assert!(task.await.map_err(io::Error::other)?.is_err());
        assert!(!broker.poisoned.load(Ordering::SeqCst));
        assert!(matches!(server.try_read(&mut [0]),Err(e) if e.kind()==io::ErrorKind::WouldBlock));
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Contract deadline."))?
}

#[tokio::test]
async fn owned_identity_blocks_before_dns_or_resolves_only_its_bound_answer_chain() -> io::Result<()>
{
    use hickory_proto::{
        op::{Message, MessageType, OpCode},
        rr::{Name, RData, Record, rdata::A},
    };
    timeout(Duration::from_secs(3), async {
        for (blocked, private) in [(false, false), (true, false), (false, true)] {
            let (client, mut server) = UnixStream::pair()?;
            let broker = Arc::new(Broker::new(client));
            let task_broker = Arc::clone(&broker);
            let task = tokio::spawn(async move {
                let mut draft = profile(true, if blocked { "block" } else { "proxy" })?.to_draft();
                draft.private_lan_bypass = private;
                if private {
                    draft.tcp_domain_policy = None;
                }
                let prepared = draft
                    .validate()
                    .map_err(|_| io::Error::other("Invalid private FakeIP fixture."))?;
                let plan = if private {
                    Plan::private()?
                } else {
                    Plan::default()
                };
                resolve(
                    &prepared,
                    &task_broker,
                    "192.0.2.1:443".parse().map_err(io::Error::other)?,
                    "198.18.0.4:8443".parse().map_err(io::Error::other)?,
                    &plan,
                )
                .await
            });
            let mut request = [0; 8];
            server.read_exact(&mut request).await?;
            assert_eq!(&request[..2], b"FR");
            server.write_all(b"A").await?;
            server.write_u16(13).await?;
            server.write_all(b"owned.example").await?;
            if blocked {
                assert_eq!(
                    task.await
                        .map_err(io::Error::other)?
                        .err()
                        .map(|e| e.kind()),
                    Some(io::ErrorKind::PermissionDenied)
                );
            } else {
                assert_eq!(server.read_u8().await?, b'Q');
                assert_eq!(server.read_u8().await?, 0);
                let size = server.read_u16().await? as usize;
                let mut query = vec![0; size];
                server.read_exact(&mut query).await?;
                let parsed = dns::parse_query(&query)?;
                let mut response = Message::new(parsed.id, MessageType::Response, OpCode::Query);
                response.queries = parsed.queries.clone();
                response.add_answer(Record::from_rdata(
                    Name::from_utf8("unrelated.example.").map_err(io::Error::other)?,
                    60,
                    RData::A(A(Ipv4Addr::new(1, 1, 1, 2))),
                ));
                response.add_answer(Record::from_rdata(
                    parsed.queries[0].name().clone(),
                    60,
                    RData::A(A(if private {
                        Ipv4Addr::new(10, 2, 2, 1)
                    } else {
                        Ipv4Addr::new(1, 1, 1, 1)
                    })),
                ));
                let bytes = response.to_vec().map_err(io::Error::other)?;
                server.write_all(b"A").await?;
                server.write_u16(bytes.len() as u16).await?;
                server.write_all(&bytes).await?;
                let resolved = task.await.map_err(io::Error::other)??;
                assert_eq!(
                    resolved.address.to_string(),
                    if private {
                        "10.2.2.1:8443"
                    } else {
                        "1.1.1.1:8443"
                    }
                );
                assert_eq!(resolved.domain.as_deref(), Some("owned.example"));
            }
            assert!(
                matches!(server.try_read(&mut [0]),Err(e) if e.kind()==io::ErrorKind::WouldBlock)
            );
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Contract deadline."))?
}
