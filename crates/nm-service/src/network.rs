//! Privileged, bounded socket setup. No independent route or DNS configuration.
use hickory_proto::{
    op::{Message, Query},
    rr::{Name, RData, RecordType},
};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    net::{TcpStream, UdpSocket},
    process::Command,
    time::timeout,
};

pub(crate) const MARK: u32 = 0x4e4d5401;
pub(crate) const VPN_DNS: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

pub(crate) fn dns_query() -> io::Result<(u16, Vec<u8>)> {
    query("example.com")
}
fn query(host: &str) -> io::Result<(u16, Vec<u8>)> {
    let id = u16::from_ne_bytes(
        uuid::Uuid::new_v4().as_bytes()[..2]
            .try_into()
            .map_err(|_| io::Error::other("DNS ID failed."))?,
    );
    let mut message = Message::new(
        id,
        hickory_proto::op::MessageType::Query,
        hickory_proto::op::OpCode::Query,
    );
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(
        Name::from_utf8(host).map_err(|_| io::Error::other("Invalid endpoint name."))?,
        RecordType::A,
    ));
    Ok((
        id,
        message
            .to_vec()
            .map_err(|_| io::Error::other("DNS query failed."))?,
    ))
}

pub(crate) fn dns_answer(id: u16, bytes: &[u8]) -> io::Result<Vec<Ipv4Addr>> {
    let response =
        Message::from_vec(bytes).map_err(|_| io::Error::other("Invalid DNS response."))?;
    if response.id != id
        || response.truncation
        || response.response_code != hickory_proto::op::ResponseCode::NoError
        || response.message_type != hickory_proto::op::MessageType::Response
    {
        return Err(io::Error::other("DNS response refused."));
    }
    let ips: Vec<_> = response
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .collect();
    if ips.is_empty() {
        return Err(io::Error::other("No IPv4 endpoint."));
    }
    Ok(ips)
}

fn base(interface: &str, udp: bool) -> io::Result<Socket> {
    let socket = Socket::new(
        Domain::IPV4,
        if udp { Type::DGRAM } else { Type::STREAM },
        Some(if udp { Protocol::UDP } else { Protocol::TCP }),
    )?;
    socket.bind_device(Some(interface.as_bytes()))?;
    socket.set_mark(MARK)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

pub(crate) async fn tcp(endpoint: SocketAddr, interface: &str) -> io::Result<TcpStream> {
    if !endpoint.is_ipv4() {
        return Err(io::Error::other("IPv6 endpoints are not supported yet."));
    }
    let socket = base(interface, false)?;
    match socket.connect(&endpoint.into()) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.raw_os_error() == Some(115) => {}
        Err(e) => return Err(e),
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
    let socket = base(interface, true)?;
    socket.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())?;
    let socket = UdpSocket::from_std(socket.into())?;
    socket.connect((dns, 53)).await?;
    let (id, bytes) = query(host)?;
    socket.send(&bytes).await?;
    let mut response = [0; 4096];
    let length = timeout(Duration::from_secs(5), socket.recv(&mut response))
        .await
        .map_err(|_| io::Error::other("Bootstrap DNS timeout."))??;
    let ip = dns_answer(id, &response[..length])?
        .into_iter()
        .find(|ip| !ip.is_unspecified() && !ip.is_multicast())
        .ok_or_else(|| io::Error::other("Invalid endpoint address."))?;
    Ok(SocketAddr::from((ip, port)))
}

pub(crate) async fn guard_present() -> io::Result<bool> {
    let mut command = Command::new("/usr/sbin/nft");
    command
        .args(["list", "table", "inet", "nm_tunnel"])
        .kill_on_drop(true);
    let existing = timeout(Duration::from_secs(3), command.output())
        .await
        .map_err(|_| io::Error::other("Guard inspection timeout."))??;
    Ok(existing.status.success())
}

pub(crate) async fn guard(enable: bool) -> io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let existing = guard_present().await?;
    if !enable {
        if existing {
            let mut command = Command::new("/usr/sbin/nft");
            command
                .args(["delete", "table", "inet", "nm_tunnel"])
                .kill_on_drop(true);
            let status = timeout(Duration::from_secs(3), command.status())
                .await
                .map_err(|_| io::Error::other("Guard removal timeout."))??;
            if !status.success() {
                return Err(io::Error::other("Guard removal failed."));
            }
        }
        return Ok(());
    }
    let mut rules = String::new();
    if existing {
        rules.push_str("delete table inet nm_tunnel\n");
    }
    rules.push_str(&format!("table inet nm_tunnel {{\n chain output {{\n  type filter hook output priority 0; policy accept;\n  oifname lo accept\n  meta nfproto ipv6 counter drop\n  meta mark {MARK} accept\n  oifname nmtun0 accept\n  counter drop\n }}\n}}\n"));
    let mut child = Command::new("/usr/sbin/nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("Guard input unavailable."))?
        .write_all(rules.as_bytes())
        .await?;
    let status = timeout(Duration::from_secs(3), child.wait())
        .await
        .map_err(|_| io::Error::other("Guard update timeout."))??;
    if !status.success() {
        return Err(io::Error::other("Guard update failed."));
    }
    Ok(())
}
