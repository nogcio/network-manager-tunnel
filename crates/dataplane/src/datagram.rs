//! Destination-bound datagram routes; no implicit socket creation.
use crate::{
    Datagram, Host, LanScope,
    routing::{self, Decision},
};
use std::{io, net::SocketAddr};

/// One destination-bound association. Drop closes its owned transport; no redial.
pub enum Route {
    /// Protocol library association over an approved endpoint connection.
    Proxy(nm_tunnel_engine::DatagramTunnel),
    /// Independently authorized, destination-confined platform payload channel.
    Lan(Box<dyn Datagram>),
}

impl Route {
    /// Admit one association without a sniffed hostname. Refusal is final.
    pub async fn connect(
        profile: &nm_tunnel_profile::Profile,
        host: &(impl Host + ?Sized),
        endpoint: SocketAddr,
        destination: SocketAddr,
        lan: &(impl LanScope + ?Sized),
    ) -> io::Result<Self> {
        Self::connect_named(profile, host, endpoint, destination, lan, None).await
    }

    /// Admit QUIC-observed names only for complete policy; they select rules ahead
    /// of the FakeIP name without changing its original destination identity.
    /// Host calls are cancellation-sensitive; no alternate route is attempted.
    pub async fn connect_named(
        profile: &nm_tunnel_profile::Profile,
        host: &(impl Host + ?Sized),
        endpoint: SocketAddr,
        destination: SocketAddr,
        lan: &(impl LanScope + ?Sized),
        hostname: Option<&str>,
    ) -> io::Result<Self> {
        let hostname = if profile.network().source().is_some() {
            hostname
        } else {
            None
        };
        let resolved = crate::destination::resolve_with_sniffed_name(
            profile,
            host,
            endpoint,
            destination,
            lan,
            hostname,
        )
        .await?;
        let destination = resolved.address;
        // Legacy UDP never acquires TCP-only hostname inspection semantics.
        let name = crate::destination::routing_name(profile, resolved.domain.as_deref(), hostname);
        match routing::decide(profile.network(), lan, destination, name)? {
            Decision::Block => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Datagram blocked by policy.",
            )),
            decision @ (Decision::Lan | Decision::LegacyDirect(_) | Decision::PolicyDirect(_)) => {
                host.open_udp(destination, decision).await.map(Self::Lan)
            }
            Decision::Proxy => {
                let socket = host.open_endpoint(endpoint).await?;
                nm_tunnel_engine::connect_udp(profile, socket, endpoint, destination)
                    .await
                    .map(Self::Proxy)
                    .map_err(|_| io::Error::other("UDP proxy setup failed."))
            }
        }
    }

    /// Send one whole payload with its original destination binding; reject oversize.
    pub async fn send(&self, payload: &[u8]) -> io::Result<()> {
        if payload.len() > 65507 {
            return Err(io::Error::other("Oversized datagram."));
        }
        match self {
            Self::Proxy(tunnel) => tunnel
                .send(payload)
                .await
                .map_err(|_| io::Error::other("UDP proxy write failed.")),
            Self::Lan(socket) => socket.send(payload).await,
        }
    }

    /// Receive one bounded payload; errors never cause fallback or redial.
    pub async fn receive(&self) -> io::Result<Vec<u8>> {
        match self {
            Self::Proxy(tunnel) => tunnel
                .receive()
                .await
                .map_err(|_| io::Error::other("UDP proxy read failed.")),
            Self::Lan(socket) => {
                let payload = socket.receive().await?;
                if payload.len() > 65507 {
                    return Err(io::Error::other("Oversized LAN datagram."));
                }
                Ok(payload)
            }
        }
    }
}
