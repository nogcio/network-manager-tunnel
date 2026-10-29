//! Private parent/child channel. Credentials never use arguments, files or logs.
use crate::schema::Strings;
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};
use serde::{Deserialize, Serialize};
use std::{
    io,
    io::{IoSlice, IoSliceMut},
    mem::MaybeUninit,
    net::SocketAddr,
    os::fd::{AsFd, OwnedFd},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, Interest},
    net::{UnixDatagram, UnixStream},
    sync::Mutex,
};

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct WorkerConfig {
    pub name: String,
    pub data: Strings,
    pub secrets: Strings,
    pub endpoint: SocketAddr,
    /// Activation-local NM snapshot, not persisted profile data or authority for
    /// the supervisor. Only present for combined LAN + DNS interception.
    pub lan: Vec<(std::net::Ipv4Addr, u8)>,
    /// NM's explicit per-connection persistent lifetime, not worker authority.
    #[serde(default)]
    pub persistent: bool,
}

/// A request is not authority: the supervisor rechecks its own validated policy
/// and resolves this name independently before granting a marked direct socket.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectRequest {
    pub domain: String,
    pub destination: SocketAddr,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyRequest {
    pub destination: SocketAddr,
    pub domain: Option<String>,
    pub transport: LanTransport,
}

pub(crate) const MAX_DIRECT_REQUEST: usize = 512;

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LanTransport {
    Tcp,
    Udp,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LanRequest {
    pub destination: SocketAddr,
    pub transport: LanTransport,
}

pub(crate) const MAX_LAN_REQUEST: usize = 128;

/// Fatal worker reports contain only a runtime stage and a fixed error class,
/// never upstream diagnostics. A truncated frame must not pin the supervisor.
pub(crate) async fn receive_worker_failure(
    stream: &mut UnixStream,
) -> io::Result<(u8, crate::health::Failure)> {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let stage = stream.read_u8().await?;
        let reason = crate::health::Failure::from_code(stream.read_u8().await?)?;
        if stage == 0 || stage > 14 {
            return Err(io::Error::other("Invalid worker runtime stage."));
        }
        Ok((stage, reason))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Worker error frame deadline."))?
}

/// Parent-side frame read: bound allocation before reading a body and never
/// expose serde diagnostics or worker-provided addresses in errors.
pub(crate) async fn receive_lan_request(stream: &mut UnixStream) -> io::Result<LanRequest> {
    receive_json(stream, MAX_LAN_REQUEST).await
}

/// Decode a bounded JSON request under one frame deadline. Payload diagnostics stay private.
pub(crate) async fn receive_json<T: serde::de::DeserializeOwned>(
    stream: &mut UnixStream,
    maximum: usize,
) -> io::Result<T> {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let size = stream.read_u16().await? as usize;
        if size == 0 || size > maximum {
            return Err(io::Error::other("Invalid LAN request length."));
        }
        let mut bytes = vec![0; size];
        stream.read_exact(&mut bytes).await?;
        serde_json::from_slice(&bytes).map_err(|_| io::Error::other("Invalid LAN request."))
    })
    .await
    .map_err(|_| io::Error::other("LAN request deadline."))?
}

#[cfg(test)]
#[path = "wire_tests.rs"]
mod tests;

pub(crate) async fn send_config(stream: &mut UnixStream, config: &WorkerConfig) -> io::Result<()> {
    let bytes =
        serde_json::to_vec(config).map_err(|_| io::Error::other("Worker configuration failed."))?;
    if bytes.len() > 32768 {
        return Err(io::Error::other("Worker configuration too large."));
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await
}

pub(crate) async fn receive_config(stream: &mut UnixStream) -> io::Result<WorkerConfig> {
    let size = stream.read_u32().await? as usize;
    if size > 32768 {
        return Err(io::Error::other("Worker configuration too large."));
    }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).map_err(|_| io::Error::other("Invalid worker configuration."))
}

pub(crate) async fn send_socket(
    stream: &UnixStream,
    socket: &(impl AsFd + Sync),
) -> io::Result<()> {
    loop {
        stream.writable().await?;
        let result = stream.try_io(Interest::WRITABLE, || {
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
            let mut ancillary = SendAncillaryBuffer::new(&mut space);
            let fds = [socket.as_fd()];
            if !ancillary.push(SendAncillaryMessage::ScmRights(&fds)) {
                return Err(io::Error::other("FD buffer failed."));
            }
            let count = rustix::net::sendmsg(
                stream,
                &[IoSlice::new(b"F")],
                &mut ancillary,
                SendFlags::NOSIGNAL,
            )?;
            if count != 1 {
                return Err(io::Error::other("FD transfer failed."));
            }
            Ok(())
        });
        match result {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            other => return other,
        }
    }
}

/// First private bootstrap frame: exactly one TUN fd, before configuration.
/// EOF, wrong/truncated ancillary data and non-TUN descriptors reject and close
/// received ownership. Cancellation discards the worker/channel; never retry.
pub(crate) async fn receive_tun(stream: &UnixStream) -> io::Result<OwnedFd> {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            stream.readable().await?;
            let result = stream.try_io(Interest::READABLE, || {
                let mut byte = [0];
                let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
                let mut ancillary = RecvAncillaryBuffer::new(&mut space);
                let message = rustix::net::recvmsg(
                    stream,
                    &mut [IoSliceMut::new(&mut byte)],
                    &mut ancillary,
                    RecvFlags::CMSG_CLOEXEC,
                )?;
                let mut fds = Vec::new();
                for item in ancillary.drain() {
                    if let RecvAncillaryMessage::ScmRights(rights) = item {
                        fds.extend(rights);
                    }
                }
                if message.bytes != 1
                    || byte != *b"F"
                    || fds.len() != 1
                    || message.flags.intersects(
                        rustix::net::ReturnFlags::TRUNC | rustix::net::ReturnFlags::CTRUNC,
                    )
                {
                    return Err(io::Error::other("Invalid worker TUN grant."));
                }
                let fd = fds
                    .pop()
                    .ok_or_else(|| io::Error::other("Missing worker TUN grant."))?;
                let stat = rustix::fs::fstat(&fd)?;
                if rustix::fs::FileType::from_raw_mode(stat.st_mode)
                    != rustix::fs::FileType::CharacterDevice
                    || rustix::fs::major(stat.st_rdev) != 10
                    || rustix::fs::minor(stat.st_rdev) != 200
                {
                    return Err(io::Error::other("Invalid worker TUN descriptor."));
                }
                Ok(fd)
            });
            match result {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                other => return other,
            }
        }
    })
    .await
    .map_err(|_| io::Error::other("Worker TUN grant deadline."))?
}

pub(crate) struct Broker {
    stream: Mutex<UnixStream>,
    pub poisoned: Arc<AtomicBool>,
}

struct Incomplete {
    poison: Arc<AtomicBool>,
    complete: bool,
}
impl Drop for Incomplete {
    fn drop(&mut self) {
        if !self.complete {
            self.poison.store(true, Ordering::SeqCst);
        }
    }
}

impl Broker {
    pub fn new(stream: UnixStream) -> Self {
        Self {
            stream: Mutex::new(stream),
            poisoned: Arc::new(AtomicBool::new(false)),
        }
    }
    pub async fn ready(&self) -> io::Result<()> {
        self.stream.lock().await.write_all(b"R").await
    }
    pub async fn open(&self) -> io::Result<UnixStream> {
        self.exchange(b"O", unix_stream).await
    }
    pub async fn open_endpoint(
        &self,
        peer: SocketAddr,
    ) -> io::Result<nm_tunnel_engine::EndpointStream> {
        nm_tunnel_engine::EndpointStream::relayed(self.open().await?, peer)
            .map_err(|_| io::Error::other("Invalid endpoint relay metadata."))
    }
    pub async fn query_dns(&self, request: &[u8], tcp: bool) -> io::Result<Vec<u8>> {
        let query = crate::dns::parse_query(request)?;
        self.payload_rpc(
            &[b'Q', u8::from(tcp)],
            request,
            crate::dns::MAX_DNS_BYTES,
            |response| crate::dns::validate_response(&query, response),
        )
        .await
    }

    pub async fn fake_dns(&self, request: &[u8]) -> io::Result<Vec<u8>> {
        let query = crate::dns::parse_query(request)?;
        self.payload_rpc(b"FD", request, crate::dns::MAX_DNS_BYTES, |response| {
            crate::dns::validate_response(&query, response)
        })
        .await
    }

    pub async fn fake_reverse(&self, ip: std::net::Ipv4Addr) -> io::Result<String> {
        if !crate::fakeip::in_range(ip) {
            return Err(io::Error::other("Invalid FakeIP destination."));
        }
        let bytes = self
            .payload_rpc(b"FR", &ip.octets(), 253, |bytes| {
                let name = std::str::from_utf8(bytes)
                    .map_err(|_| io::Error::other("Invalid FakeIP identity reply."))?;
                if nm_tunnel_profile::canonical_domain(name).as_deref() != Some(name) {
                    return Err(io::Error::other("Invalid FakeIP identity reply."));
                }
                Ok(())
            })
            .await?;
        String::from_utf8(bytes).map_err(|_| io::Error::other("Invalid FakeIP identity reply."))
    }

    async fn payload_rpc(
        &self,
        header: &[u8],
        request: &[u8],
        maximum: usize,
        validate: impl Fn(&[u8]) -> io::Result<()>,
    ) -> io::Result<Vec<u8>> {
        let mut stream = self.stream.lock().await;
        if self.poisoned.load(Ordering::SeqCst) {
            return Err(io::Error::other("Broker channel cancelled."));
        }
        let mut guard = Incomplete {
            poison: Arc::clone(&self.poisoned),
            complete: false,
        };
        stream.write_all(header).await?;
        stream.write_u16(request.len() as u16).await?;
        stream.write_all(request).await?;
        match stream.read_u8().await? {
            b'N' => {
                guard.complete = true;
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "DNS forwarding refused.",
                ));
            }
            b'A' => {}
            _ => return Err(io::Error::other("Invalid DNS broker reply.")),
        }
        let size = stream.read_u16().await? as usize;
        if size == 0 || size > maximum {
            return Err(io::Error::other("Invalid DNS broker reply length."));
        }
        let mut response = vec![0; size];
        stream.read_exact(&mut response).await?;
        validate(&response)?;
        guard.complete = true;
        Ok(response)
    }
    pub async fn open_direct(&self, request: &DirectRequest) -> io::Result<UnixStream> {
        self.exchange(&Self::direct_message(request, b'D')?, unix_stream)
            .await
    }

    fn policy_message(request: &PolicyRequest) -> io::Result<Vec<u8>> {
        let bytes = serde_json::to_vec(request)
            .map_err(|_| io::Error::other("Invalid source Direct request."))?;
        if bytes.len() > MAX_DIRECT_REQUEST {
            return Err(io::Error::other("Oversized source Direct request."));
        }
        let mut message = vec![b'P'];
        message.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        message.extend(bytes);
        Ok(message)
    }
    pub async fn open_policy_tcp(&self, request: &PolicyRequest) -> io::Result<UnixStream> {
        self.exchange(&Self::policy_message(request)?, unix_stream)
            .await
    }
    pub async fn open_policy_udp(&self, request: &PolicyRequest) -> io::Result<UnixDatagram> {
        self.exchange(&Self::policy_message(request)?, unix_datagram)
            .await
    }

    pub async fn open_direct_udp(&self, request: &DirectRequest) -> io::Result<UnixDatagram> {
        self.exchange(&Self::direct_message(request, b'U')?, unix_datagram)
            .await
    }

    fn direct_message(request: &DirectRequest, code: u8) -> io::Result<Vec<u8>> {
        let bytes =
            serde_json::to_vec(request).map_err(|_| io::Error::other("Invalid direct request."))?;
        if bytes.len() > MAX_DIRECT_REQUEST {
            return Err(io::Error::other("Oversized direct request."));
        }
        let mut message = Vec::with_capacity(bytes.len() + 3);
        message.push(code);
        message.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        message.extend_from_slice(&bytes);
        Ok(message)
    }

    fn lan_message(destination: SocketAddr, transport: LanTransport) -> io::Result<Vec<u8>> {
        let bytes = serde_json::to_vec(&LanRequest {
            destination,
            transport,
        })
        .map_err(|_| io::Error::other("Invalid LAN request."))?;
        if bytes.len() > MAX_LAN_REQUEST {
            return Err(io::Error::other("Oversized LAN request."));
        }
        let mut message = vec![b'L'];
        message.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        message.extend_from_slice(&bytes);
        Ok(message)
    }

    pub async fn open_lan_tcp(&self, destination: SocketAddr) -> io::Result<UnixStream> {
        let message = Self::lan_message(destination, LanTransport::Tcp)?;
        self.exchange(&message, unix_stream).await
    }

    /// Receives only a private Unix datagram channel, never a marked IP socket.
    /// A connected UDP IP descriptor is not destination-confined: sendto could
    /// retarget it. The supervisor retains that capability and relays payloads.
    pub async fn open_lan_udp(&self, destination: SocketAddr) -> io::Result<UnixDatagram> {
        let message = Self::lan_message(destination, LanTransport::Udp)?;
        self.exchange(&message, unix_datagram).await
    }

    async fn exchange<T>(
        &self,
        request: &[u8],
        decode: impl Fn(OwnedFd) -> io::Result<T>,
    ) -> io::Result<T> {
        let mut stream = self.stream.lock().await;
        if self.poisoned.load(Ordering::SeqCst) {
            return Err(io::Error::other("Broker channel cancelled."));
        }
        let mut guard = Incomplete {
            poison: Arc::clone(&self.poisoned),
            complete: false,
        };
        stream.write_all(request).await?;
        loop {
            stream.readable().await?;
            let result = stream.try_io(Interest::READABLE, || {
                let mut bytes = [0];
                let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
                let mut ancillary = RecvAncillaryBuffer::new(&mut space);
                let message = rustix::net::recvmsg(
                    &*stream,
                    &mut [IoSliceMut::new(&mut bytes)],
                    &mut ancillary,
                    RecvFlags::CMSG_CLOEXEC,
                )?;
                let mut fds = Vec::new();
                for item in ancillary.drain() {
                    if let RecvAncillaryMessage::ScmRights(rights) = item {
                        fds.extend(rights);
                    }
                }
                if message.bytes == 1
                    && bytes == *b"N"
                    && fds.is_empty()
                    && !message.flags.intersects(
                        rustix::net::ReturnFlags::TRUNC | rustix::net::ReturnFlags::CTRUNC,
                    )
                {
                    guard.complete = true;
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Direct socket request refused.",
                    ));
                }
                if message.bytes != 1
                    || bytes != *b"F"
                    || fds.len() != 1
                    || message.flags.intersects(
                        rustix::net::ReturnFlags::TRUNC | rustix::net::ReturnFlags::CTRUNC,
                    )
                {
                    return Err(io::Error::other("Invalid broker descriptor reply."));
                }
                let fd = fds
                    .pop()
                    .ok_or_else(|| io::Error::other("Missing endpoint socket."))?;
                // Type and peer validation remain inside the serialized exchange;
                // rejection poisons it before any queued request can proceed.
                decode(fd)
            });
            match result {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                other => {
                    if other.is_ok() {
                        guard.complete = true;
                    }
                    return other;
                }
            }
        }
    }
}

fn unix_stream(fd: OwnedFd) -> io::Result<UnixStream> {
    let reference = socket2::SockRef::from(&fd);
    if reference.r#type()? != socket2::Type::STREAM || reference.domain()? != socket2::Domain::UNIX
    {
        return Err(io::Error::other("Invalid stream relay descriptor."));
    }
    let socket: std::os::unix::net::UnixStream = fd.into();
    socket.set_nonblocking(true)?;
    socket.peer_addr()?;
    UnixStream::from_std(socket)
}

fn unix_datagram(fd: OwnedFd) -> io::Result<UnixDatagram> {
    let reference = socket2::SockRef::from(&fd);
    if reference.r#type()? != socket2::Type::DGRAM || reference.domain()? != socket2::Domain::UNIX {
        return Err(io::Error::other("Invalid datagram relay descriptor."));
    }
    let socket: std::os::unix::net::UnixDatagram = fd.into();
    socket.set_nonblocking(true)?;
    socket.peer_addr()?;
    UnixDatagram::from_std(socket)
}
