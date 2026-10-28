use nm_tunnel_dataplane::{Datagram, Host, LanScope, PayloadStream, routing::Decision};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::atomic::{AtomicUsize, Ordering},
};

#[derive(Default)]
pub struct Refuse {
    pub calls: AtomicUsize,
    pub endpoint_calls: AtomicUsize,
}
impl Refuse {
    fn refusal<T>(&self) -> io::Result<T> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Synthetic refusal.",
        ))
    }
}
#[async_trait::async_trait]
impl Host for Refuse {
    async fn open_endpoint(&self, _: SocketAddr) -> io::Result<nm_tunnel_engine::EndpointStream> {
        self.endpoint_calls.fetch_add(1, Ordering::SeqCst);
        self.refusal()
    }
    async fn open_tcp(&self, _: SocketAddr, _: Decision<'_>) -> io::Result<Box<dyn PayloadStream>> {
        self.refusal()
    }
    async fn open_udp(&self, _: SocketAddr, _: Decision<'_>) -> io::Result<Box<dyn Datagram>> {
        self.refusal()
    }
    async fn query_dns(&self, _: &[u8], _: bool) -> io::Result<Vec<u8>> {
        self.refusal()
    }
    async fn fake_dns(&self, _: &[u8]) -> io::Result<Vec<u8>> {
        self.refusal()
    }
    async fn fake_reverse(&self, _: Ipv4Addr) -> io::Result<String> {
        self.refusal()
    }
}

pub struct NoLan;
impl LanScope for NoLan {
    fn is_local(&self, _: SocketAddr) -> bool {
        false
    }
    fn authorizes(&self, _: SocketAddr) -> bool {
        false
    }
}

pub fn profile() -> io::Result<nm_tunnel_profile::Profile> {
    let mut draft = nm_tunnel_profile::import_vless("vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example").map_err(io::Error::other)?;
    draft.tcp_domain_policy = Some(nm_tunnel_profile::TcpDomainPolicy::from_json(r#"{"version":1,"rules":[{"domain":["blocked.example"],"action":"block"},{"domain":["direct.example"],"action":"direct"}]}"#).map_err(io::Error::other)?);
    draft
        .validate()
        .map_err(|_| io::Error::other("Invalid synthetic profile."))
}

pub fn endpoint() -> SocketAddr {
    SocketAddr::from(([192, 0, 2, 1], 443))
}
pub fn destination() -> SocketAddr {
    SocketAddr::from(([203, 0, 113, 1], 443))
}
