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
    let mode = args.next().ok_or("Expected reality or vision.")?;
    if !matches!(mode.as_str(), "reality" | "vision") || args.next().is_some() {
        return Err("Only synthetic reality and vision modes are accepted.".into());
    }
    let port = if mode == "vision" { 24449 } else { 24444 };
    let profile = Draft {
        name: "Synthetic engine fixture".into(),
        server: Ipv4Addr::LOCALHOST.to_string(),
        port: port.to_string(),
        credential: "12345678-1234-4234-8234-123456789abc".to_owned().into(),
        security: Security::Reality,
        server_name: "peer.example".into(),
        public_key: "8y8p8aO5lpROX8wIDsOzzLt13iQ-2DXZmTuqXjy0om0".into(),
        short_id: "abababababababab".into(),
        vision: mode == "vision",
        ..Default::default()
    }
    .validate()
    .map_err(|_| "Invalid synthetic profile.")?;
    let endpoint = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let destination = SocketAddr::from((Ipv4Addr::LOCALHOST, 24445));
    println!("Checking synthetic {mode} through the pinned engine libraries.");
    tokio::time::timeout(Duration::from_secs(12), async {
        let socket = tokio::net::TcpStream::connect(endpoint).await?;
        let mut stream =
            nm_tunnel_engine::connect_tcp(&profile, socket, endpoint, destination).await?;
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
