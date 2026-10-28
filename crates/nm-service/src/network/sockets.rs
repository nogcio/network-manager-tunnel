//! Marked IPv4 socket mechanics, without policy matching, IPC, DNS parsing or nftables.
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    net::{TcpStream, UdpSocket},
    time::timeout,
};

/// Root-owned IP transport. Only payload relays, never these sockets, reach workers.
pub(crate) enum Outbound {
    Tcp(TcpStream),
    Udp(UdpSocket),
}

pub(crate) async fn udp(endpoint: SocketAddr, interface: &str) -> io::Result<UdpSocket> {
    udp_bound(endpoint, Some(interface)).await
}

// Unbound marked egress is restricted to the network authority module's explicit
// all-RFC1918 grant. Ordinary endpoint and DNS consumers must select an uplink.
pub(super) async fn udp_bound(
    endpoint: SocketAddr,
    interface: Option<&str>,
) -> io::Result<UdpSocket> {
    if !endpoint.is_ipv4() {
        return Err(io::Error::other(
            "IPv6 upstream sockets are not supported yet.",
        ));
    }
    let socket = base(interface, true)?;
    socket.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())?;
    let socket = UdpSocket::from_std(socket.into())?;
    socket.connect(endpoint).await?;
    Ok(socket)
}

fn base(interface: Option<&str>, udp: bool) -> io::Result<Socket> {
    let socket = Socket::new(
        Domain::IPV4,
        if udp { Type::DGRAM } else { Type::STREAM },
        Some(if udp { Protocol::UDP } else { Protocol::TCP }),
    )?;
    socket.bind_device(interface.map(str::as_bytes))?;
    socket.set_mark(super::MARK)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

pub(crate) async fn tcp(endpoint: SocketAddr, interface: &str) -> io::Result<TcpStream> {
    tcp_bound(endpoint, Some(interface)).await
}

pub(super) async fn tcp_bound(
    endpoint: SocketAddr,
    interface: Option<&str>,
) -> io::Result<TcpStream> {
    if !endpoint.is_ipv4() {
        return Err(io::Error::other("IPv6 endpoints are not supported yet."));
    }
    let socket = base(interface, false)?;
    match socket.connect(&endpoint.into()) {
        Ok(()) => {}
        Err(error)
            if error.kind() == io::ErrorKind::WouldBlock || error.raw_os_error() == Some(115) => {}
        Err(error) => return Err(error),
    }
    let stream = TcpStream::from_std(socket.into())?;
    timeout(Duration::from_secs(5), stream.writable())
        .await
        .map_err(|_| io::Error::other("Endpoint connect timeout."))??;
    if let Some(error) = stream.take_error()? {
        return Err(error);
    }
    Ok(stream)
}
