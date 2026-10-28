//! Fixed source DNS authority and independent, activation-local response cache.
//! Root owns every upstream socket; requests cannot supply a resolver/detour.
use crate::{
    dns,
    network::{
        bootstrap,
        sockets::{self, Outbound},
    },
};
use futures_util::{SinkExt, StreamExt};
use nm_tunnel_dataplane::source_dns::{self, failed};
use nm_tunnel_profile::{DnsOverride, DnsTransport, Profile, SourceDns};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
};

pub(crate) struct Resolver {
    shared: source_dns::Resolver<Network>,
    interface: String,
}

struct Network {
    endpoint: SocketAddr,
    interface: String,
    uplink_dns: Ipv4Addr,
}

impl Resolver {
    pub fn new(
        profile: Profile,
        endpoint: SocketAddr,
        interface: String,
        uplink_dns: Ipv4Addr,
    ) -> Self {
        Self {
            shared: source_dns::Resolver::new(
                profile,
                Network {
                    endpoint,
                    interface: interface.clone(),
                    uplink_dns,
                },
            ),
            interface,
        }
    }
    pub async fn query(&mut self, bytes: &[u8], tcp: bool) -> io::Result<Vec<u8>> {
        self.shared.query(bytes, tcp).await
    }

    pub async fn direct(&mut self, request: &crate::wire::PolicyRequest) -> io::Result<Outbound> {
        self.shared
            .authorize_direct(request.domain.as_deref(), request.destination)
            .await?;
        let ip = request.destination.ip();
        let interface = if ip.is_loopback() || ip.is_unspecified() {
            "lo"
        } else {
            &self.interface
        };
        match request.transport {
            crate::wire::LanTransport::Tcp => sockets::tcp(request.destination, interface)
                .await
                .map(Outbound::Tcp),
            crate::wire::LanTransport::Udp => sockets::udp(request.destination, interface)
                .await
                .map(Outbound::Udp),
        }
    }
}

#[async_trait::async_trait]
impl source_dns::Exchange for Network {
    async fn exchange(&self, profile: &Profile, request: &[u8], tcp: bool) -> io::Result<Vec<u8>> {
        if profile.network().dns_override() == DnsOverride::CurrentNetwork {
            return crate::supervisor::uplink_dns::exchange(
                DnsOverride::CurrentNetwork,
                request,
                tcp,
                self.uplink_dns,
                &self.interface,
            )
            .await;
        }
        let upstream = match profile.network().dns_override() {
            DnsOverride::Inherit => profile.network().source().ok_or_else(failed)?.dns().clone(),
            DnsOverride::ProxyIpv4(address) => SourceDns {
                host: None,
                address,
                port: 53,
                transport: if tcp {
                    DnsTransport::Tcp
                } else {
                    DnsTransport::Udp
                },
                via_proxy: true,
                tls_name: String::new(),
            },
            DnsOverride::CurrentNetwork => return Err(failed()),
        };
        let destination = if let Some(host) = &upstream.host {
            bootstrap::resolve(host, upstream.port, &self.interface, self.uplink_dns).await?
        } else {
            SocketAddr::from((upstream.address, upstream.port))
        };
        let std::net::IpAddr::V4(address) = destination.ip() else {
            return Err(failed());
        };
        if DnsOverride::ProxyIpv4(address).validate().is_err() {
            return Err(failed());
        }
        if upstream.transport == DnsTransport::Udp {
            if upstream.via_proxy {
                let socket = sockets::tcp(self.endpoint, &self.interface).await?;
                let tunnel =
                    nm_tunnel_engine::connect_udp(profile, socket, self.endpoint, destination)
                        .await
                        .map_err(|_| failed())?;
                tunnel.send(request).await.map_err(|_| failed())?;
                return tunnel.receive().await.map_err(|_| failed());
            }
            let socket = sockets::udp(destination, &self.interface).await?;
            if socket.send(request).await? != request.len() {
                return Err(failed());
            }
            let mut bytes = vec![0; dns::MAX_DNS_BYTES + 1];
            let size = socket.recv(&mut bytes).await?;
            bytes.truncate(size);
            return Ok(bytes);
        }
        let stream: Box<dyn Payload> = if upstream.via_proxy {
            let socket = sockets::tcp(self.endpoint, &self.interface).await?;
            Box::new(
                nm_tunnel_engine::connect_tcp(profile, socket, self.endpoint, destination)
                    .await
                    .map_err(|_| failed())?,
            )
        } else {
            Box::new(sockets::tcp(destination, &self.interface).await?)
        };
        let stream: Box<dyn Payload> = if upstream.transport == DnsTransport::Tls {
            Box::new(
                nm_tunnel_engine::wrap_verified_tls(stream, &upstream.tls_name)
                    .await
                    .map_err(|_| failed())?,
            )
        } else {
            stream
        };
        let mut stream = tokio_util::codec::LengthDelimitedCodec::builder()
            .length_field_length(2)
            .max_frame_length(dns::MAX_DNS_BYTES)
            .new_framed(stream);
        stream.send(request).await?;
        Ok(stream.next().await.ok_or_else(failed)??.to_vec())
    }
}

trait Payload: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync> Payload for T {}
