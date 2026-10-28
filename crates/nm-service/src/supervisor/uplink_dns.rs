//! Fixed uplink DNS transport. Requesters cannot supply a server or interface.
use crate::{
    dns::{self, MAX_DNS_BYTES},
    network::sockets,
};
use futures_util::{SinkExt, StreamExt};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

pub(crate) async fn exchange(
    mode: nm_tunnel_profile::DnsOverride,
    request: &[u8],
    tcp: bool,
    server: Ipv4Addr,
    interface: &str,
) -> io::Result<Vec<u8>> {
    if mode != nm_tunnel_profile::DnsOverride::CurrentNetwork {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DNS forwarding is not authorized by this profile.",
        ));
    }
    let query = dns::parse_query(request)?;
    if !dns::valid_uplink_server(server) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Invalid uplink DNS server.",
        ));
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        let endpoint = SocketAddr::from((server, 53));
        let response = if tcp {
            let socket = sockets::tcp(endpoint, interface).await?;
            let mut stream = dns::framed(socket);
            stream.send(request).await?;
            stream.next().await.ok_or_else(dns::invalid)??.to_vec()
        } else {
            let socket = sockets::udp(endpoint, interface).await?;
            if socket.send(request).await? != request.len() {
                return Err(dns::invalid());
            }
            let mut bytes = vec![0; MAX_DNS_BYTES + 1];
            let size = socket.recv(&mut bytes).await?;
            bytes.truncate(size);
            bytes
        };
        dns::validate_response(&query, &response)?;
        Ok(response)
    })
    .await
    .map_err(|_| io::Error::other("Uplink DNS deadline."))?
}
