//! Endpoint bootstrap through the selected uplink resolver, never the OS resolver.
use super::sockets;
use crate::dns::{direct_dns_answer, dns_answer, query};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::time::timeout;

pub(crate) async fn resolve(
    host: &str,
    port: u16,
    interface: &str,
    dns: Ipv4Addr,
) -> io::Result<SocketAddr> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if !ip.is_ipv4() {
            return Err(io::Error::other("IPv6 endpoints are not supported yet."));
        }
        return Ok(SocketAddr::new(ip, port));
    }
    let socket = sockets::udp(SocketAddr::from((dns, 53)), interface).await?;
    let (id, bytes) = query(host)?;
    socket.send(&bytes).await?;
    let mut response = [0; 4096];
    let length = timeout(Duration::from_secs(5), socket.recv(&mut response))
        .await
        .map_err(|_| io::Error::other("Bootstrap DNS timeout."))??;
    let ip = dns_answer(id, &response[..length])?
        .into_iter()
        .find(|ip| {
            !ip.is_unspecified()
                && !ip.is_multicast()
                && direct_dns_answer(id, host, std::net::IpAddr::V4(*ip), &response[..length])
                    .unwrap_or(false)
        })
        .ok_or_else(|| io::Error::other("Invalid endpoint address."))?;
    Ok(SocketAddr::from((ip, port)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn literal_endpoints_do_not_use_an_interface_or_dns_and_ipv6_rejects() -> io::Result<()> {
        assert_eq!(
            resolve("192.0.2.1", 443, "never-open-this", Ipv4Addr::LOCALHOST).await?,
            "192.0.2.1:443"
                .parse::<SocketAddr>()
                .map_err(io::Error::other)?
        );
        for host in ["::1", "::ffff:192.0.2.1"] {
            assert!(
                resolve(host, 443, "never-open-this", Ipv4Addr::LOCALHOST)
                    .await
                    .is_err()
            );
        }
        Ok(())
    }
}
