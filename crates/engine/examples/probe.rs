//! Explicit synthetic engine probe, for an isolated loopback fixture only.
use nm_tunnel_profile::{Draft, Security};
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("MEOW_ISOLATED_PEER_TEST").as_deref() != Ok("1") {
        return Err("Run only in the documented isolated loopback fixture.".into());
    }
    let mut args = std::env::args().skip(1);
    let mode = args
        .next()
        .ok_or("Expected reality, vision, xudp or vision-xudp.")?;
    if !matches!(
        mode.as_str(),
        "reality"
            | "vision"
            | "xudp"
            | "vision-xudp"
            | "xudp-invalid-auth"
            | "domain"
            | "vision-domain"
    ) || args.next().is_some()
    {
        return Err("Only synthetic reality/vision TCP/domain and XUDP modes are accepted.".into());
    }
    let xudp = mode.contains("xudp");
    let invalid_auth = mode == "xudp-invalid-auth";
    let port = if mode.starts_with("vision") {
        24449
    } else {
        24444
    };
    let source_policy = if xudp {
        Some(nm_tunnel_profile::SourcePolicy::from_json(
            r#"{"version":1,"dns":{"address":"1.1.1.1","port":853,"transport":"tls","via_proxy":true,"tls_name":"1.1.1.1"},"domain_policy":"{\"version\":1,\"rules\":[{\"domain_suffix\":[\"direct.example\"],\"action\":\"direct\"}]}","fakeip_range":"198.18.0.0/15","tun_address":"172.19.0.1","tun_prefix":30,"mtu":1400}"#,
        )?)
    } else {
        None
    };
    let profile = Draft {
        name: "Synthetic engine fixture".into(),
        server: Ipv4Addr::LOCALHOST.to_string(),
        port: port.to_string(),
        credential: if invalid_auth {
            "12345678-1234-4234-8234-123456789abd"
        } else {
            "12345678-1234-4234-8234-123456789abc"
        }
        .to_owned()
        .into(),
        security: Security::Reality,
        server_name: "peer.example".into(),
        public_key: std::env::var("MEOW_TEST_PUBLIC_KEY")
            .unwrap_or_else(|_| "8y8p8aO5lpROX8wIDsOzzLt13iQ-2DXZmTuqXjy0om0".into()),
        short_id: "abababababababab".into(),
        vision: mode.starts_with("vision"),
        source_policy,
        fake_ip: xudp,
        dns_interception: xudp,
        ..Default::default()
    }
    .validate()
    .map_err(|_| "Invalid synthetic profile.")?;
    let endpoint = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let destination = SocketAddr::from((Ipv4Addr::LOCALHOST, 24445));
    println!("Checking synthetic {mode} through the pinned engine libraries.");
    if xudp {
        tokio::time::timeout(Duration::from_secs(20), async {
            let mut socket = tokio::net::TcpStream::connect(endpoint).await?;
            let (mut host, worker) = tokio::net::UnixStream::pair()?;
            let bridge =
                tokio::spawn(
                    async move { tokio::io::copy_bidirectional(&mut socket, &mut host).await },
                );
            let input = nm_tunnel_engine::EndpointStream::relayed(worker, endpoint)?;
            let tunnel =
                nm_tunnel_engine::connect_udp(&profile, input, endpoint, destination).await?;
            println!("XUDP transport/session setup complete.");
            if invalid_auth {
                tunnel.send(b"must-not-reach-echo").await?;
                if tokio::time::timeout(Duration::from_secs(8), tunnel.receive())
                    .await?
                    .is_ok()
                {
                    return Err("Invalid XUDP authentication delivered a datagram.".into());
                }
                drop(tunnel);
                closed_bridge(bridge).await?;
                return Ok(());
            }
            for size in [1, 1400, 8192] {
                let payload: Vec<_> = (0..size).map(|n| (n % 251) as u8).collect();
                tunnel.send(&payload).await?;
                println!("XUDP payload queued: {size} bytes; awaiting peer echo.");
                if tunnel.receive().await? != payload {
                    return Err("XUDP payload mismatch.".into());
                }
            }
            if !matches!(
                tunnel.send(&vec![0; 8193]).await,
                Err(nm_tunnel_engine::Error::Configuration)
            ) {
                return Err("Oversized XUDP payload was not rejected before writing.".into());
            }
            tunnel.send(b"after-rejection").await?;
            if tunnel.receive().await? != b"after-rejection" {
                return Err("XUDP rejection corrupted the association.".into());
            }
            drop(tunnel);
            closed_bridge(bridge).await?;
            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .map_err(|_| "XUDP probe deadline exceeded.")??;
        println!("PASS: synthetic {mode}; checked XUDP result and Unix/IP relay cleanup.");
        return Ok(());
    }
    tokio::time::timeout(Duration::from_secs(12), async {
        let socket = tokio::net::TcpStream::connect(endpoint).await?;
        let mut stream = if mode.contains("domain") {
            nm_tunnel_engine::connect_tcp_domain(
                &profile,
                socket,
                endpoint,
                "echo.fixture.invalid",
                destination.port(),
            )
            .await?
        } else {
            nm_tunnel_engine::connect_tcp(&profile, socket, endpoint, destination).await?
        };
        let payload: Vec<u8> = (0..65549).map(|index| (index % 251) as u8).collect();
        stream.write_all(&payload).await?;
        stream.flush().await?;
        let mut response = vec![0; payload.len()];
        stream.read_exact(&mut response).await?;
        if response != payload {
            return Err("Payload mismatch.".into());
        }
        stream.shutdown().await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await
    .map_err(|_| "FAIL: engine probe deadline exceeded.")??;
    println!("PASS: synthetic {mode}, 65,549-byte payload round-trip.");
    Ok(())
}

async fn closed_bridge(
    task: tokio::task::JoinHandle<std::io::Result<(u64, u64)>>,
) -> Result<(), Box<dyn std::error::Error>> {
    match tokio::time::timeout(Duration::from_secs(2), task).await?? {
        Ok(_) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}
