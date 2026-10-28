//! Profile-to-protocol adaptation over a socket supplied by the host integration.
//! No NetworkManager, TUN, DNS lookup, socket creation or route ownership lives here.
mod adapter;
mod datagram;
mod endpoint;
mod hostname;
mod quic_hostname;
mod verify;
pub use datagram::{DatagramTunnel, connect_udp};
pub use endpoint::EndpointStream;
pub use hostname::{TcpHostname, inspect_tcp_hostname};
pub use quic_hostname::QuicHostname;
pub use verify::{verify_tls_peer, wrap_verified_tls};

use meow_common::{Metadata, ProxyAdapter, ProxyConn};
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Static, redacted failure categories. Upstream diagnostics never cross this API.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The validated model cannot be represented by the selected library.
    #[error("Protocol configuration is unsupported.")]
    Configuration,
    /// The supplied socket's peer does not match the explicitly approved endpoint.
    #[error("The supplied endpoint socket does not match the approved peer.")]
    Endpoint,
    /// TLS/REALITY or VLESS setup, or established UDP association I/O, failed.
    /// No direct fallback occurs; upstream diagnostics remain redacted.
    #[error("Proxy protocol setup or datagram I/O failed.")]
    Handshake,
    /// The complete initial protocol setup exceeded its deadline.
    #[error("Proxy protocol setup timed out.")]
    Timeout,
}

/// A single TCP flow. Drop closes its library-owned stream and upstream socket.
/// Runtime I/O errors are normalized; they never expose third-party diagnostic strings.
pub struct Tunnel(Box<dyn ProxyConn>);

/// Validate the selected library configuration without sockets or DNS.
/// Unsupported wire profiles fail before privileged activation resources exist.
pub fn validate_profile(profile: &nm_tunnel_profile::Profile) -> Result<(), Error> {
    adapter::build(profile).map(|_| ())
}

impl std::fmt::Debug for Tunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Tunnel([redacted])")
    }
}

/// Establish one VLESS TCP flow through a host-supplied, already-connected socket.
///
/// `endpoint` is the resolved peer explicitly approved by the integration. It must
/// match the input's peer metadata and the profile port. TCP inputs derive that
/// metadata from `peer_addr`; [`EndpointStream::relayed`] requires a trusted host
/// attestation for a fixed-peer Unix payload relay. Literal profile IPs must also
/// match; hostname resolution and endpoint bypass remain the caller's responsibility.
/// `destination` is carried inside VLESS, never dialed locally. TLS SNI, fingerprint,
/// WS path/Host and Vision come exclusively from the validated profile.
///
/// Ownership transfers on entry, including on error, timeout or cancellation. Dropping
/// this future drops the socket and transport setup. No automatic reconnect or fallback
/// occurs. A returned stream is NOT readiness/authentication acknowledgement for VLESS:
/// its response and Vision's deferred request may require actual application I/O.
///
/// # Errors
/// Returns a static category for endpoint mismatch, unsupported configuration, protocol
/// setup failure or the ten-second setup deadline. UDP and IP packet forwarding are not
/// implemented by this API. No state outside the supplied flow is changed.
pub async fn connect_tcp(
    profile: &nm_tunnel_profile::Profile,
    socket: impl TryInto<EndpointStream>,
    endpoint: SocketAddr,
    destination: SocketAddr,
) -> Result<Tunnel, Error> {
    let socket = socket.try_into().map_err(|_| Error::Endpoint)?;
    let node = profile.node();
    if socket.peer != endpoint
        || endpoint.port() != node.endpoint().port()
        || node
            .endpoint()
            .ipv4()
            .is_some_and(|ip| std::net::IpAddr::V4(ip) != endpoint.ip())
        || destination.port() == 0
        || destination.ip().is_unspecified()
    {
        return Err(Error::Endpoint);
    }
    let adapter = adapter::build(profile)?;
    let metadata = Metadata {
        dst_ip: Some(destination.ip()),
        dst_port: destination.port(),
        ..Default::default()
    };
    let raw = Box::new(meow_proxy::StreamConn(socket.inner));
    let stream = tokio::time::timeout(
        Duration::from_secs(10),
        adapter.connect_over(raw, &metadata),
    )
    .await
    .map_err(|_| Error::Timeout)?
    .map_err(|_| Error::Handshake)?;
    Ok(Tunnel(stream))
}

fn io_result<T>(result: io::Result<T>) -> io::Result<T> {
    result.map_err(|error| io::Error::new(error.kind(), "Proxy stream I/O failed."))
}

impl AsyncRead for Tunnel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf).map(io_result)
    }
}

impl AsyncWrite for Tunnel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf).map(io_result)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx).map(io_result)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx).map(io_result)
    }
}
