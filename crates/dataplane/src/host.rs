//! Platform capabilities, not an implicit networking implementation.
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
};
use tokio::io::{AsyncRead, AsyncWrite};

/// An owned payload stream. Drop closes it; no reconnect or retarget operation.
pub trait PayloadStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> PayloadStream for T {}

/// Destination-confined datagram payloads. The platform retains IP socket authority.
/// Dropping an operation cancels it; implementations must not retry elsewhere.
#[async_trait::async_trait]
pub trait Datagram: Send + Sync {
    /// Send one whole payload or error; no partial-write success.
    async fn send(&self, bytes: &[u8]) -> io::Result<()>;
    /// Receive one payload, rejecting oversized/truncated datagrams.
    async fn receive(&self) -> io::Result<Vec<u8>>;
}

/// Activation-local LAN eligibility, never permission to create physical sockets.
pub trait LanScope: Send + Sync {
    /// Recognize local destinations even when an individual destination is forbidden.
    fn is_local(&self, destination: SocketAddr) -> bool;
    /// Reject DNS, broadcast and other destinations outside the checked LAN scope.
    fn authorizes(&self, destination: SocketAddr) -> bool;
}

/// Platform-owned, independently authorized networking and FakeIP operations.
///
/// Inputs are requests, not grants. The implementation independently checks its
/// activation profile/uplink. Refusal is final: callers never try another outbound.
/// Every endpoint connection must bypass TUN, including reconnects. DNS uses only
/// the selected policy. FakeIP replies require durable ownership. Errors must not
/// expose names, credentials or upstream diagnostics. Cancellation closes owned
/// resources; an ambiguous serialized exchange must poison its transport.
#[async_trait::async_trait]
pub trait Host: Send + Sync {
    /// Return a new approved connection to the fixed activation endpoint.
    async fn open_endpoint(
        &self,
        endpoint: SocketAddr,
    ) -> io::Result<nm_tunnel_engine::EndpointStream>;
    /// Open one intended non-proxy route after independent authorization.
    async fn open_tcp(
        &self,
        destination: SocketAddr,
        route: crate::routing::Decision<'_>,
    ) -> io::Result<Box<dyn PayloadStream>>;
    /// Open a destination-confined non-proxy datagram channel.
    async fn open_udp(
        &self,
        destination: SocketAddr,
        route: crate::routing::Decision<'_>,
    ) -> io::Result<Box<dyn Datagram>>;
    /// Exchange a bounded DNS message with the activation-selected resolver.
    async fn query_dns(&self, request: &[u8], tcp: bool) -> io::Result<Vec<u8>>;
    /// Answer using durable FakeIP identities, never a volatile fallback.
    async fn fake_dns(&self, request: &[u8]) -> io::Result<Vec<u8>>;
    /// Return the canonical owned name or reject an unknown synthetic address.
    async fn fake_reverse(&self, ip: Ipv4Addr) -> io::Result<String>;
}

#[async_trait::async_trait]
impl<T: Host + ?Sized> Host for std::sync::Arc<T> {
    async fn open_endpoint(
        &self,
        endpoint: SocketAddr,
    ) -> io::Result<nm_tunnel_engine::EndpointStream> {
        self.as_ref().open_endpoint(endpoint).await
    }
    async fn open_tcp(
        &self,
        destination: SocketAddr,
        route: crate::routing::Decision<'_>,
    ) -> io::Result<Box<dyn PayloadStream>> {
        self.as_ref().open_tcp(destination, route).await
    }
    async fn open_udp(
        &self,
        destination: SocketAddr,
        route: crate::routing::Decision<'_>,
    ) -> io::Result<Box<dyn Datagram>> {
        self.as_ref().open_udp(destination, route).await
    }
    async fn query_dns(&self, request: &[u8], tcp: bool) -> io::Result<Vec<u8>> {
        self.as_ref().query_dns(request, tcp).await
    }
    async fn fake_dns(&self, request: &[u8]) -> io::Result<Vec<u8>> {
        self.as_ref().fake_dns(request).await
    }
    async fn fake_reverse(&self, ip: Ipv4Addr) -> io::Result<String> {
        self.as_ref().fake_reverse(ip).await
    }
}

impl<T: LanScope + ?Sized> LanScope for std::sync::Arc<T> {
    fn is_local(&self, destination: SocketAddr) -> bool {
        self.as_ref().is_local(destination)
    }
    fn authorizes(&self, destination: SocketAddr) -> bool {
        self.as_ref().authorizes(destination)
    }
}
