//! Synthetic shared-route probe, only in the pinned loopback peer namespace.
use nm_tunnel_dataplane::{Datagram, Host, PayloadStream, datagram::Route, routing::Decision};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Mutex,
    time::Duration,
};

struct NoLan;
impl nm_tunnel_dataplane::LanScope for NoLan {
    fn is_local(&self, _: SocketAddr) -> bool {
        false
    }
    fn authorizes(&self, _: SocketAddr) -> bool {
        false
    }
}

struct Fixture {
    socket: Mutex<Option<nm_tunnel_engine::EndpointStream>>,
}

#[async_trait::async_trait]
impl Host for Fixture {
    async fn open_endpoint(&self, _: SocketAddr) -> io::Result<nm_tunnel_engine::EndpointStream> {
        self.socket
            .lock()
            .map_err(|_| io::Error::other("Fixture lock failed."))?
            .take()
            .ok_or_else(|| io::Error::other("Unexpected second endpoint request."))
    }
    async fn open_tcp(&self, _: SocketAddr, _: Decision<'_>) -> io::Result<Box<dyn PayloadStream>> {
        Err(io::Error::other("Unexpected Direct TCP."))
    }
    async fn open_udp(&self, _: SocketAddr, _: Decision<'_>) -> io::Result<Box<dyn Datagram>> {
        Err(io::Error::other("Unexpected Direct UDP."))
    }
    async fn query_dns(&self, _: &[u8], _: bool) -> io::Result<Vec<u8>> {
        Err(io::Error::other("Unexpected destination DNS."))
    }
    async fn fake_dns(&self, _: &[u8]) -> io::Result<Vec<u8>> {
        Err(io::Error::other("Unexpected DNS interception."))
    }
    async fn fake_reverse(&self, ip: Ipv4Addr) -> io::Result<String> {
        if ip != Ipv4Addr::new(198, 18, 0, 4) {
            return Err(io::Error::other("Unowned fixture identity."));
        }
        Ok("echo.fixture.invalid".into())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("MEOW_ISOLATED_PEER_TEST").as_deref() != Ok("1") {
        return Err("Isolated peer namespace required.".into());
    }
    let vision = match std::env::args().nth(1).as_deref() {
        Some("xudp-domain") => false,
        Some("vision-xudp-domain") => true,
        _ => return Err("Synthetic domain XUDP mode required.".into()),
    };
    tokio::time::timeout(Duration::from_secs(20), async {
        let port = if vision { 24449 } else { 24444 };
        let profile = nm_tunnel_profile::Draft {
            name: "Synthetic shared-route fixture".into(),
            server: "127.0.0.1".into(), port: port.to_string(),
            credential: "12345678-1234-4234-8234-123456789abc".to_owned().into(),
            security: nm_tunnel_profile::Security::Reality,
            server_name: "peer.example".into(),
            public_key: std::env::var("MEOW_TEST_PUBLIC_KEY")?,
            short_id: "abababababababab".into(), vision,
            fake_ip: true, dns_interception: true,
            source_policy: Some(nm_tunnel_profile::SourcePolicy::from_json(
                r#"{"version":1,"dns":{"address":"1.1.1.1","port":853,"transport":"tls","via_proxy":true,"tls_name":"1.1.1.1"},"domain_policy":"{\"version\":1,\"rules\":[{\"domain_suffix\":[\"direct.example\"],\"action\":\"direct\"}]}","fakeip_range":"198.18.0.0/15","tun_address":"172.19.0.1","tun_prefix":30,"mtu":1400}"#,
            )?),
            ..Default::default()
        }.validate().map_err(|_| "Invalid synthetic profile.")?;
        let endpoint = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let socket = tokio::net::TcpStream::connect(endpoint).await?;
        let host = Fixture { socket: Mutex::new(Some(socket.try_into()?)) };
        let route = Route::connect_named(&profile, &host, endpoint,
            SocketAddr::from(([198, 18, 0, 4], 24445)), &NoLan,
            Some("observed.fixture.invalid")).await?;
        for size in [1, 1400, 8192] {
            let payload: Vec<_> = (0..size).map(|n| (n % 251) as u8).collect();
            route.send(&payload).await?;
            if route.receive().await? != payload { return Err("XUDP echo mismatch.".into()); }
        }
        if route.send(&vec![0; 8193]).await.is_ok() || route.send(&[]).await.is_ok() {
            return Err("Invalid XUDP size accepted.".into());
        }
        route.send(b"after-rejection").await?;
        if route.receive().await? != b"after-rejection" { return Err("Association corrupted.".into()); }
        drop(route);
        Ok::<(), Box<dyn std::error::Error>>(())
    }).await.map_err(|_| "Shared-route probe deadline.")??;
    println!(
        "PASS shared domain XUDP route: original identity, no DNS/Direct/fallback, bounds and echo."
    );
    Ok(())
}
