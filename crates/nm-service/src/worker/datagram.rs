//! Linux broker integration regressions for shared datagram dispatch.
#[cfg(test)]
use crate::{lan::Plan, wire::Broker};
pub(super) use nm_tunnel_dataplane::datagram::Route;
#[cfg(test)]
use std::io;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire;
    use std::{net::Ipv4Addr, sync::Arc, time::Duration};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{UnixDatagram, UnixStream},
        time::timeout,
    };

    #[tokio::test]
    async fn datagram_decisions_preserve_name_admission_and_refusal_without_outbound_fallback()
    -> io::Result<()> {
        timeout(Duration::from_secs(3), async {
            for (complete,name,destination,code) in [
                (false,"direct.example","203.0.113.1:443",Some(b'O')),
                (true,"proxied.example","10.2.3.4:443",Some(b'O')),
                (true,"unknown.example","10.2.3.4:443",Some(b'P')),
                (true,"direct.example","203.0.113.1:443",Some(b'P')),
                (true,"blocked.example","10.2.3.4:443",None),
            ] {
                let profile = if complete { crate::test_support::source_profile()? } else {
                    let mut draft = nm_tunnel_profile::import_vless("vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example").map_err(io::Error::other)?;
                    draft.tcp_domain_policy = Some(nm_tunnel_profile::TcpDomainPolicy::from_json(r#"{"version":1,"rules":[{"domain":["direct.example"],"action":"direct"}]}"#).map_err(io::Error::other)?);
                    draft.validate().map_err(|_|io::Error::other("Invalid datagram fixture."))?
                };
                let (client,mut server) = UnixStream::pair()?;
                let broker = Broker::new(client);
                let destination = destination.parse().map_err(io::Error::other)?;
                let endpoint = "192.0.2.1:443".parse().map_err(io::Error::other)?;
                if let Some(code) = code {
                    let task = tokio::spawn(async move {
                        Route::connect_named(&profile,&broker,endpoint,destination,&Plan::default(),Some(name)).await
                    });
                    assert_eq!(server.read_u8().await?,code);
                    if code == b'P' {
                        let size = server.read_u16().await? as usize;
                        let mut bytes = vec![0;size]; server.read_exact(&mut bytes).await?;
                        let request: wire::PolicyRequest = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                        assert_eq!(request.destination,destination);
                        assert_eq!(request.domain.as_deref(),Some(name));
                        assert!(matches!(request.transport,wire::LanTransport::Udp));
                    }
                    server.write_all(b"N").await?;
                    assert!(task.await.map_err(io::Error::other)?.is_err());
                    assert_eq!(server.read(&mut [0]).await?,0);
                } else {
                    assert!(Route::connect_named(&profile,&broker,endpoint,destination,&Plan::default(),Some(name)).await.is_err());
                    assert!(matches!(server.try_read(&mut [0]),Err(error) if error.kind()==io::ErrorKind::WouldBlock));
                }
            }
            Ok(())
        }).await.map_err(|_|io::Error::other("Datagram decision deadline."))?
    }

    #[tokio::test]
    async fn invalid_local_datagrams_do_not_fall_through_to_proxy_or_request_a_socket()
    -> io::Result<()> {
        timeout(Duration::from_secs(3),async {
        let lan = Plan::connected(&[(Ipv4Addr::new(192,168,1,2),24)])?.with_interception(true)?;
        let mut draft = nm_tunnel_profile::import_vless("vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example").map_err(io::Error::other)?;
        draft.lan_bypass = true;
        draft.dns_interception = true;
        let profile = draft.validate().map_err(|_|io::Error::other("Invalid LAN fixture."))?;
        let (client,server) = UnixStream::pair()?;
        let broker = Broker::new(client);
        for target in ["192.168.1.0:80","192.168.1.255:123","192.168.1.1:53"] {
            assert_eq!(Route::connect(&profile,&broker,"192.0.2.1:443".parse().map_err(io::Error::other)?,target.parse().map_err(io::Error::other)?,&lan).await.err().map(|e|e.kind()),Some(io::ErrorKind::PermissionDenied));
            assert!(matches!(server.try_read(&mut [0]),Err(e) if e.kind()==io::ErrorKind::WouldBlock));
        }
        Ok(())
        }).await.map_err(|_|io::Error::other("Contract deadline."))?
    }

    #[tokio::test]
    async fn local_datagram_route_carries_payload_only_and_refusal_never_falls_back()
    -> io::Result<()> {
        timeout(Duration::from_secs(3),async {
            for refused in [false,true] {
                let lan = Plan::connected(&[(Ipv4Addr::new(192,168,1,2),24)])?.with_interception(true)?;
                let mut draft = nm_tunnel_profile::import_vless("vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example").map_err(io::Error::other)?;
                draft.lan_bypass = true;
                draft.dns_interception = true;
                let profile = draft.validate().map_err(|_|io::Error::other("Invalid LAN fixture."))?;
                let (client,mut server) = UnixStream::pair()?;
                let broker = Arc::new(Broker::new(client));
                let task_broker = Arc::clone(&broker);
                let task = tokio::spawn(async move {
                    Route::connect(&profile,&task_broker,"192.0.2.1:443".parse().map_err(io::Error::other)?,"192.168.1.1:123".parse().map_err(io::Error::other)?,&lan).await
                });
                assert_eq!(server.read_u8().await?,b'L');
                let size = server.read_u16().await? as usize;
                let mut bytes = vec![0;size];
                server.read_exact(&mut bytes).await?;
                let request: wire::LanRequest = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                assert!(matches!(request.transport,wire::LanTransport::Udp));
                if refused {
                    server.write_all(b"N").await?;
                    assert_eq!(task.await.map_err(io::Error::other)?.err().map(|e|e.kind()),Some(io::ErrorKind::PermissionDenied));
                } else {
                    let (parent,worker) = UnixDatagram::pair()?;
                    wire::send_socket(&server,&worker).await?;
                    drop(worker);
                    let route = task.await.map_err(io::Error::other)??;
                    assert!(route.send(&vec![0;65508]).await.is_err());
                    assert!(matches!(parent.try_recv(&mut [0]),Err(e) if e.kind()==io::ErrorKind::WouldBlock));
                    route.send(b"payload").await?;
                    let mut payload = [0;7];
                    assert_eq!(parent.recv(&mut payload).await?,7);
                    assert_eq!(&payload,b"payload");
                    parent.send(b"reply").await?;
                    assert_eq!(route.receive().await?,b"reply");
                }
                assert!(matches!(server.try_read(&mut [0]),Err(e) if e.kind()==io::ErrorKind::WouldBlock));
            }
            Ok(())
        }).await.map_err(|_|io::Error::other("Contract deadline."))?
    }
}
