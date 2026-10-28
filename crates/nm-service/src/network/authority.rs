//! Independent legacy Direct/LAN authority. IPC decoding never grants permission.
use super::sockets;
use crate::{
    dns::{direct_dns_answer, query},
    lan::Plan,
};
use nm_tunnel_profile::{DomainAction, TcpDomainPolicy, canonical_domain};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    net::{TcpStream, UdpSocket},
    time::timeout,
};

/// A checked LAN destination and binding, not an open socket or a worker capability.
/// Construction is private; the broad mode alone may follow existing physical routes.
pub(crate) struct LanGrant<'a> {
    destination: SocketAddr,
    binding: Option<&'a str>,
}

impl LanGrant<'_> {
    /// Own the new root socket through completion/error/cancellation. Never redial.
    pub async fn tcp(self) -> io::Result<TcpStream> {
        sockets::tcp_bound(self.destination, self.binding).await
    }
    pub async fn udp(self) -> io::Result<UdpSocket> {
        sockets::udp_bound(self.destination, self.binding).await
    }
}

/// Validate against the supervisor's own NM snapshot before privileged I/O. DNS,
/// protected and non-local destinations fail; no requester prefixes are accepted.
pub(crate) fn lan<'a>(
    plan: &Plan,
    destination: SocketAddr,
    interface: &'a str,
) -> io::Result<LanGrant<'a>> {
    if !plan.authorizes(destination) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "LAN destination refused.",
        ));
    }
    Ok(LanGrant {
        destination,
        binding: if plan.private_bypass() {
            None
        } else {
            Some(interface)
        },
    })
}

/// Eligibility before DNS/socket work. Legacy hostname rules never authorize LAN,
/// loopback, link-local, shared CGNAT, FakeIP or non-unicast destinations.
fn direct_authorized(policy: &TcpDomainPolicy, domain: &str, destination: SocketAddr) -> bool {
    let std::net::IpAddr::V4(ip) = destination.ip() else {
        return false;
    };
    let [a, b, _, _] = ip.octets();
    destination.port() != 0
        && canonical_domain(domain).as_deref() == Some(domain)
        && policy.action(Some(domain)) == DomainAction::Direct
        && !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && a != 0
        && a < 224
        && !(a == 100 && (64..=127).contains(&b))
        && !(a == 198 && matches!(b, 18 | 19))
}

pub(crate) async fn direct_tcp(
    policy: &TcpDomainPolicy,
    domain: &str,
    destination: SocketAddr,
    interface: &str,
    dns: Ipv4Addr,
) -> io::Result<TcpStream> {
    verify_direct(policy, domain, destination, interface, dns).await?;
    sockets::tcp(destination, interface).await
}

pub(crate) async fn direct_udp(
    fake_ip: bool,
    policy: &TcpDomainPolicy,
    domain: &str,
    destination: SocketAddr,
    interface: &str,
    dns: Ipv4Addr,
) -> io::Result<UdpSocket> {
    if !fake_ip {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "No UDP identity policy.",
        ));
    }
    verify_direct(policy, domain, destination, interface, dns).await?;
    sockets::udp(destination, interface).await
}

/// Bind the independently resolved A/CNAME chain to the requested name and IP.
/// Refusal never switches the flow to another resolver, interface or outbound.
async fn verify_direct(
    policy: &TcpDomainPolicy,
    domain: &str,
    destination: SocketAddr,
    interface: &str,
    dns: Ipv4Addr,
) -> io::Result<()> {
    let denied = || {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Direct destination refused.",
        )
    };
    if !direct_authorized(policy, domain, destination) {
        return Err(denied());
    }
    let socket = sockets::udp(SocketAddr::from((dns, 53)), interface).await?;
    let (id, bytes) = query(domain)?;
    socket.send(&bytes).await?;
    let mut response = [0; 4096];
    let length = timeout(Duration::from_secs(5), socket.recv(&mut response))
        .await
        .map_err(|_| denied())??;
    if !direct_dns_answer(id, domain, destination.ip(), &response[..length])? {
        return Err(denied());
    }
    Ok(())
}

#[cfg(test)]
#[path = "authority_tests.rs"]
mod tests;
