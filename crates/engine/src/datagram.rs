//! Bounded VLESS UDP associations over a single explicitly supplied endpoint socket.
use crate::{Error, adapter};
use meow_common::{Metadata, Network, ProxyAdapter, ProxyPacketConn};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::net::TcpStream;

struct SuppliedSocket(Mutex<Option<TcpStream>>);

#[async_trait::async_trait]
impl meow_proxy::dialer::TcpDialer for SuppliedSocket {
    async fn dial(
        &self,
        _: &str,
        _: u16,
        _: bool,
    ) -> std::io::Result<Box<dyn meow_transport::Stream>> {
        let stream = self
            .0
            .lock()
            .map_err(|_| std::io::Error::other("Socket state failed."))?
            .take()
            .ok_or_else(|| std::io::Error::other("Implicit redial refused."))?;
        Ok(Box::new(stream))
    }
}

/// One destination-bound VLESS UDP association. No local UDP socket is created.
/// Drop releases the library's framed stream. An incomplete write poisons the
/// library connection; its reader preserves partial frames across cancellation.
/// Send/receive may run concurrently.
pub struct DatagramTunnel {
    inner: Box<dyn ProxyPacketConn>,
    destination: SocketAddr,
}

impl std::fmt::Debug for DatagramTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DatagramTunnel([redacted])")
    }
}

impl DatagramTunnel {
    /// Send a payload of at most 65,507 bytes, without direct fallback.
    ///
    /// # Errors
    /// Returns [`Error::Configuration`] for oversized payloads, before writing,
    /// or [`Error::Handshake`] for association I/O failure or a short write.
    pub async fn send(&self, payload: &[u8]) -> Result<(), Error> {
        if payload.len() > 65507 {
            return Err(Error::Configuration);
        }
        let written = self
            .inner
            .write_packet(payload, &self.destination)
            .await
            .map_err(|_| Error::Handshake)?;
        if written != payload.len() {
            return Err(Error::Handshake);
        }
        Ok(())
    }

    /// Receive one bounded datagram. VLESS bound UDP has no wire source field;
    /// the pinned library reports `0.0.0.0:0`. Only that sentinel or the bound
    /// destination is accepted, never an unrelated concrete source.
    ///
    /// # Errors
    /// Returns [`Error::Handshake`] for association I/O failure or
    /// [`Error::Endpoint`] for an unrelated source or oversized datagram.
    pub async fn receive(&self) -> Result<Vec<u8>, Error> {
        let mut payload = vec![0; 65536];
        let (length, source) = self
            .inner
            .read_packet(&mut payload)
            .await
            .map_err(|_| Error::Handshake)?;
        let bound_sentinel = SocketAddr::from(([0, 0, 0, 0], 0));
        if (source != self.destination && source != bound_sentinel) || length > 65507 {
            return Err(Error::Endpoint);
        }
        payload.truncate(length);
        Ok(payload)
    }
}

/// Establish a destination-bound UDP-over-VLESS association on an already-connected
/// host-approved TCP socket. Ownership, ten-second setup deadline and endpoint checks
/// match `connect_tcp`. The only injected dial yields this socket exactly once; no
/// resolver/reconnect socket exists. Vision is TCP-only: the library deliberately uses
/// ordinary VLESS UDP framing on the same selected TLS/REALITY/WS transport.
/// Success alone does not prove authentication: exchange an actual datagram first.
pub async fn connect_udp(
    profile: &nm_tunnel_profile::Profile,
    socket: TcpStream,
    endpoint: SocketAddr,
    destination: SocketAddr,
) -> Result<DatagramTunnel, Error> {
    let fields = profile.fields();
    if socket.peer_addr().map_err(|_| Error::Endpoint)? != endpoint
        || endpoint.port()
            != fields
                .port
                .parse::<u16>()
                .map_err(|_| Error::Configuration)?
        || fields
            .server
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip != endpoint.ip())
        || destination.port() == 0
        || destination.ip().is_unspecified()
    {
        return Err(Error::Endpoint);
    }
    let dialer = Arc::new(SuppliedSocket(Mutex::new(Some(socket))));
    let adapter = adapter::build_with_dialer(profile, dialer)?;
    let metadata = Metadata {
        network: Network::Udp,
        dst_ip: Some(destination.ip()),
        dst_port: destination.port(),
        ..Default::default()
    };
    let inner = tokio::time::timeout(Duration::from_secs(10), adapter.dial_udp(&metadata))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| Error::Handshake)?;
    Ok(DatagramTunnel { inner, destination })
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Packet(SocketAddr);

    #[async_trait::async_trait]
    impl ProxyPacketConn for Packet {
        async fn read_packet(&self, buf: &mut [u8]) -> meow_common::Result<(usize, SocketAddr)> {
            buf[..3].copy_from_slice(b"dns");
            Ok((3, self.0))
        }
        async fn write_packet(&self, buf: &[u8], _: &SocketAddr) -> meow_common::Result<usize> {
            Ok(buf.len())
        }
        fn local_addr(&self) -> meow_common::Result<SocketAddr> {
            Ok(self.0)
        }
        fn close(&self) -> meow_common::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn bound_udp_accepts_absent_source_but_rejects_concrete_source_changes()
    -> Result<(), Error> {
        let destination = SocketAddr::from(([192, 0, 2, 1], 53));
        for source in [destination, SocketAddr::from(([0, 0, 0, 0], 0))] {
            let tunnel = DatagramTunnel {
                inner: Box::new(Packet(source)),
                destination,
            };
            assert_eq!(tunnel.receive().await?, b"dns");
        }
        let tunnel = DatagramTunnel {
            inner: Box::new(Packet(SocketAddr::from(([192, 0, 2, 2], 53)))),
            destination,
        };
        assert!(matches!(tunnel.receive().await, Err(Error::Endpoint)));
        assert_eq!(tunnel.destination, destination);
        Ok(())
    }
}
