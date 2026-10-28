//! Bounded VLESS UDP associations over a single explicitly supplied endpoint socket.
use crate::{EndpointStream, Error, adapter};
use meow_common::{Metadata, Network, PacketAddr, ProxyAdapter, ProxyPacketConn};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

struct SuppliedSocket(Mutex<Option<Box<dyn meow_transport::Stream>>>);

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
        Ok(stream)
    }
}

/// One destination-bound VLESS UDP association. No local UDP socket is created.
/// XUDP drop synchronously revokes its exclusive supplied transport before dropping
/// the library association: no queued End frame or peer progress is needed. The
/// revoked I/O wrapper wakes both directions so the driver can exit. Setup failure
/// and cancellation retain the same ownership. Legacy bound UDP is unchanged.
/// An incomplete write poisons the library connection; its reader preserves partial frames across cancellation.
/// Send/receive may run concurrently.
pub struct DatagramTunnel {
    // Declared first so revocation precedes library EndGuard/association cleanup.
    // This is an exclusive per-flow transport, never a shared connection pool.
    _transport: Option<crate::owned_transport::Owner>,
    inner: Box<dyn ProxyPacketConn>,
    destination: PacketAddr,
    xudp: bool,
}

impl std::fmt::Debug for DatagramTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DatagramTunnel([redacted])")
    }
}

impl DatagramTunnel {
    /// Send a payload without direct fallback: 1..=8,192 bytes for XUDP,
    /// at most 65,507 bytes for legacy bound UDP.
    ///
    /// # Errors
    /// Returns [`Error::Configuration`] for oversized payloads, before writing,
    /// or [`Error::Handshake`] for association I/O failure or a short write.
    pub async fn send(&self, payload: &[u8]) -> Result<(), Error> {
        if payload.len() > if self.xudp { 8192 } else { 65507 } || (self.xudp && payload.is_empty())
        {
            return Err(Error::Configuration);
        }
        let written = self
            .inner
            .write_packet_to(payload, &self.destination)
            .await
            .map_err(|_| Error::Handshake)?;
        if written != payload.len() {
            return Err(Error::Handshake);
        }
        Ok(())
    }

    /// Receive one bounded datagram. Domain XUDP requires the exact typed name/port;
    /// absent sources, IP substitutions and changed names/ports are rejected.
    /// IP XUDP accepts its exact IP or absent metadata. Only legacy bound UDP
    /// normalizes the library's `0.0.0.0:0` sentinel. No source authorizes host I/O.
    ///
    /// # Errors
    /// Returns [`Error::Handshake`] for association I/O failure or
    /// [`Error::Endpoint`] for an unrelated source or invalid datagram size.
    pub async fn receive(&self) -> Result<Vec<u8>, Error> {
        let mut payload = vec![0; 65536];
        let (length, source) = if self.xudp {
            self.inner.read_packet_from(&mut payload).await
        } else {
            self.inner
                .read_packet(&mut payload)
                .await
                .map(|(n, source)| {
                    let source = (source != SocketAddr::from(([0, 0, 0, 0], 0)))
                        .then_some(PacketAddr::Ip(source));
                    (n, source)
                })
        }
        .map_err(|_| Error::Handshake)?;
        let accepted = source.as_ref() == Some(&self.destination)
            || (source.is_none() && matches!(self.destination, PacketAddr::Ip(_)));
        if !accepted || (self.xudp && length == 0) || length > if self.xudp { 8192 } else { 65507 }
        {
            return Err(Error::Endpoint);
        }
        payload.truncate(length);
        Ok(payload)
    }
}

/// Establish a destination-bound UDP-over-VLESS association on an owned, approved
/// TCP input or fixed-peer Unix relay. Ownership, ten-second setup deadline and checks
/// match `connect_tcp`. The only injected dial yields this socket exactly once; no
/// resolver/reconnect socket exists. XUDP uses Mux.Cool; legacy profiles use ordinary
/// VLESS UDP framing on the selected TLS/REALITY/WS transport (Vision is TCP-only).
/// Success alone does not prove authentication: exchange an actual datagram first.
pub async fn connect_udp(
    profile: &nm_tunnel_profile::Profile,
    socket: impl TryInto<EndpointStream>,
    endpoint: SocketAddr,
    destination: SocketAddr,
) -> Result<DatagramTunnel, Error> {
    if destination.port() == 0 || destination.ip().is_unspecified() {
        return Err(Error::Endpoint);
    }
    connect_udp_target(profile, socket, endpoint, PacketAddr::Ip(destination)).await
}

/// Open domain XUDP without destination DNS. Only XUDP profiles and canonical
/// original names/nonzero ports are accepted. Ownership transfers on entry;
/// cancellation/drop closes the supplied transport, with no redial or fallback.
/// Setup has the same ten-second deadline as [`connect_udp`].
///
/// # Errors
/// Invalid mode/name/port returns [`Error::Configuration`] before transport I/O.
/// Peer mismatch, setup I/O and timeout use [`connect_udp`]'s error categories.
/// Responses must carry exactly this name/port, not a resolved IP or absent source.
pub async fn connect_udp_domain(
    profile: &nm_tunnel_profile::Profile,
    socket: impl TryInto<EndpointStream>,
    endpoint: SocketAddr,
    domain: &str,
    port: u16,
) -> Result<DatagramTunnel, Error> {
    if profile.node().udp_mode() != nm_tunnel_profile::UdpMode::Xudp
        || nm_tunnel_profile::canonical_domain(domain).as_deref() != Some(domain)
    {
        return Err(Error::Configuration);
    }
    let target = PacketAddr::domain(domain, port).map_err(|_| Error::Configuration)?;
    connect_udp_target(profile, socket, endpoint, target).await
}

async fn connect_udp_target(
    profile: &nm_tunnel_profile::Profile,
    socket: impl TryInto<EndpointStream>,
    endpoint: SocketAddr,
    destination: PacketAddr,
) -> Result<DatagramTunnel, Error> {
    let socket = socket.try_into().map_err(|_| Error::Endpoint)?;
    let node = profile.node();
    if socket.peer != endpoint
        || endpoint.port() != node.endpoint().port()
        || node
            .endpoint()
            .ipv4()
            .is_some_and(|ip| std::net::IpAddr::V4(ip) != endpoint.ip())
    {
        return Err(Error::Endpoint);
    }
    let xudp = node.udp_mode() == nm_tunnel_profile::UdpMode::Xudp;
    let (transport, stream) = if xudp {
        let (owner, stream) = crate::owned_transport::wrap(socket.inner);
        (Some(owner), stream)
    } else {
        (None, socket.inner)
    };
    let dialer = Arc::new(SuppliedSocket(Mutex::new(Some(stream))));
    let adapter = adapter::build_with_dialer(profile, dialer)?;
    connect_adapter(adapter, destination, xudp, transport).await
}

// Shared by production setup and the in-memory backpressure regression. The
// caller supplies security/transport layers; this owner adds no socket or dialer.
async fn connect_adapter(
    adapter: meow_proxy::VlessAdapter,
    destination: PacketAddr,
    xudp: bool,
    transport: Option<crate::owned_transport::Owner>,
) -> Result<DatagramTunnel, Error> {
    let adapter = if xudp {
        adapter.with_mux(meow_proxy::mux::MuxOptions {
            protocol: meow_proxy::mux::Protocol::MuxCool,
            max_connections: 1,
            min_streams: 1,
            max_streams: 1,
            padding: false,
            only_tcp: false,
        })
    } else {
        adapter
    };
    let setup = async {
        match &destination {
            PacketAddr::Domain { host, port } => adapter.dial_xudp_domain(host, *port).await,
            PacketAddr::Ip(address) => {
                adapter
                    .dial_udp(&Metadata {
                        network: Network::Udp,
                        dst_ip: Some(address.ip()),
                        dst_port: address.port(),
                        ..Default::default()
                    })
                    .await
            }
        }
    };
    let inner = tokio::time::timeout(Duration::from_secs(10), setup)
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| Error::Handshake)?;
    Ok(DatagramTunnel {
        _transport: transport,
        inner,
        destination,
        xudp,
    })
}

#[cfg(test)]
#[path = "datagram_backpressure_tests.rs"]
mod backpressure_tests;

#[cfg(test)]
mod tests {
    use super::*;
    struct Packet(SocketAddr);

    struct TypedPacket(Option<PacketAddr>, usize);
    #[async_trait::async_trait]
    impl ProxyPacketConn for TypedPacket {
        async fn read_packet(&self, _: &mut [u8]) -> meow_common::Result<(usize, SocketAddr)> {
            panic!("XUDP must not project typed sources through legacy reads")
        }
        async fn read_packet_from(
            &self,
            buf: &mut [u8],
        ) -> meow_common::Result<(usize, Option<PacketAddr>)> {
            buf[..self.1].fill(b'd');
            Ok((self.1, self.0.clone()))
        }
        async fn write_packet(&self, _: &[u8], _: &SocketAddr) -> meow_common::Result<usize> {
            panic!("Domain XUDP must not use placeholder IP writes")
        }
        async fn write_packet_to(
            &self,
            buf: &[u8],
            target: &PacketAddr,
        ) -> meow_common::Result<usize> {
            assert_eq!(target, &PacketAddr::domain("original.example", 53)?);
            Ok(buf.len())
        }
        fn local_addr(&self) -> meow_common::Result<SocketAddr> {
            Ok(([0, 0, 0, 0], 0).into())
        }
        fn close(&self) -> meow_common::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn domain_xudp_never_projects_changed_or_absent_sources_and_rejection_keeps_binding()
    -> Result<(), Error> {
        let destination =
            PacketAddr::domain("original.example", 53).map_err(|_| Error::Configuration)?;
        for source in [
            Some(destination.clone()),
            None,
            Some(PacketAddr::Ip(([192, 0, 2, 1], 53).into())),
            Some(PacketAddr::Ip(([0, 0, 0, 0], 0).into())),
            Some(PacketAddr::domain("other.example", 53).map_err(|_| Error::Configuration)?),
            Some(PacketAddr::domain("original.example", 54).map_err(|_| Error::Configuration)?),
        ] {
            let accepted = source.as_ref() == Some(&destination);
            let tunnel = DatagramTunnel {
                _transport: None,
                inner: Box::new(TypedPacket(source, 3)),
                destination: destination.clone(),
                xudp: true,
            };
            assert_eq!(tunnel.receive().await.is_ok(), accepted);
            for payload in [Vec::new(), vec![0; 8193]] {
                assert!(matches!(
                    tunnel.send(&payload).await,
                    Err(Error::Configuration)
                ));
            }
            tunnel.send(b"valid-after-rejection").await?;
            assert_eq!(tunnel.destination, destination);
        }
        Ok(())
    }

    #[tokio::test]
    async fn ip_xudp_never_treats_domains_or_concrete_zero_as_absent_and_bounds_responses()
    -> Result<(), Error> {
        let destination = PacketAddr::Ip(([192, 0, 2, 1], 53).into());
        for source in [
            None,
            Some(destination.clone()),
            Some(PacketAddr::Ip(([0, 0, 0, 0], 0).into())),
            Some(PacketAddr::Ip(([192, 0, 2, 2], 53).into())),
            Some(PacketAddr::Ip(([192, 0, 2, 1], 54).into())),
            Some(PacketAddr::domain("other.example", 53).map_err(|_| Error::Configuration)?),
        ] {
            for length in [0, 1, 8192, 8193] {
                let accepted = (source.is_none() || source.as_ref() == Some(&destination))
                    && (1..=8192).contains(&length);
                let tunnel = DatagramTunnel {
                    _transport: None,
                    inner: Box::new(TypedPacket(source.clone(), length)),
                    destination: destination.clone(),
                    xudp: true,
                };
                assert_eq!(tunnel.receive().await.is_ok(), accepted);
                assert_eq!(tunnel.destination, destination);
            }
        }
        Ok(())
    }

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
                _transport: None,
                xudp: false,
                inner: Box::new(Packet(source)),
                destination: PacketAddr::Ip(destination),
            };
            assert_eq!(tunnel.receive().await?, b"dns");
        }
        let tunnel = DatagramTunnel {
            _transport: None,
            xudp: false,
            inner: Box::new(Packet(SocketAddr::from(([192, 0, 2, 2], 53)))),
            destination: PacketAddr::Ip(destination),
        };
        assert!(matches!(tunnel.receive().await, Err(Error::Endpoint)));
        assert_eq!(tunnel.destination, PacketAddr::Ip(destination));
        Ok(())
    }
}
