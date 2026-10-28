//! Platform capability adapter. IPC and independent root authorization stay Linux-owned.
use crate::wire::{Broker, DirectRequest, LanTransport, PolicyRequest};
use nm_tunnel_dataplane::{Datagram, Host, PayloadStream, routing::Decision};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
};

#[async_trait::async_trait]
impl Host for Broker {
    async fn open_endpoint(
        &self,
        endpoint: SocketAddr,
    ) -> io::Result<nm_tunnel_engine::EndpointStream> {
        self.open_endpoint(endpoint).await
    }
    async fn open_tcp(
        &self,
        destination: SocketAddr,
        route: Decision<'_>,
    ) -> io::Result<Box<dyn PayloadStream>> {
        let stream = match route {
            Decision::Lan => self.open_lan_tcp(destination).await?,
            Decision::LegacyDirect(domain) => {
                self.open_direct(&DirectRequest {
                    domain: domain.to_owned(),
                    destination,
                })
                .await?
            }
            Decision::PolicyDirect(domain) => {
                self.open_policy_tcp(&PolicyRequest {
                    destination,
                    domain: domain.map(str::to_owned),
                    transport: LanTransport::Tcp,
                })
                .await?
            }
            Decision::Proxy | Decision::Block => {
                return Err(io::Error::other("Invalid payload route."));
            }
        };
        Ok(Box::new(stream))
    }
    async fn open_udp(
        &self,
        destination: SocketAddr,
        route: Decision<'_>,
    ) -> io::Result<Box<dyn Datagram>> {
        let socket = match route {
            Decision::Lan => self.open_lan_udp(destination).await?,
            Decision::LegacyDirect(domain) => {
                self.open_direct_udp(&DirectRequest {
                    domain: domain.to_owned(),
                    destination,
                })
                .await?
            }
            Decision::PolicyDirect(domain) => {
                self.open_policy_udp(&PolicyRequest {
                    destination,
                    domain: domain.map(str::to_owned),
                    transport: LanTransport::Udp,
                })
                .await?
            }
            Decision::Proxy | Decision::Block => {
                return Err(io::Error::other("Invalid payload route."));
            }
        };
        Ok(Box::new(LocalDatagram(socket)))
    }
    async fn query_dns(&self, request: &[u8], tcp: bool) -> io::Result<Vec<u8>> {
        self.query_dns(request, tcp).await
    }
    async fn fake_dns(&self, request: &[u8]) -> io::Result<Vec<u8>> {
        self.fake_dns(request).await
    }
    async fn fake_reverse(&self, ip: Ipv4Addr) -> io::Result<String> {
        self.fake_reverse(ip).await
    }
}

struct LocalDatagram(tokio::net::UnixDatagram);

#[async_trait::async_trait]
impl Datagram for LocalDatagram {
    async fn send(&self, payload: &[u8]) -> io::Result<()> {
        if payload.len() > 65507 {
            return Err(io::Error::other("Oversized datagram."));
        }
        if self.0.send(payload).await? != payload.len() {
            return Err(io::Error::other("Short LAN datagram write."));
        }
        Ok(())
    }
    async fn receive(&self) -> io::Result<Vec<u8>> {
        let mut payload = vec![0; 65508];
        let size = self.0.recv(&mut payload).await?;
        if size > 65507 {
            return Err(io::Error::other("Oversized LAN datagram."));
        }
        payload.truncate(size);
        Ok(payload)
    }
}
