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
    os::fd::AsFd,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, Interest},
    net::{TcpStream, UnixStream},
    sync::Mutex,
};

#[derive(Serialize, Deserialize)]
pub(crate) struct WorkerConfig {
    pub name: String,
    pub data: Strings,
    pub secrets: Strings,
    pub endpoint: SocketAddr,
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

pub(crate) async fn send_socket(stream: &UnixStream, socket: &TcpStream) -> io::Result<()> {
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
    pub async fn open(&self) -> io::Result<TcpStream> {
        let mut stream = self.stream.lock().await;
        if self.poisoned.load(Ordering::SeqCst) {
            return Err(io::Error::other("Broker channel cancelled."));
        }
        let mut guard = Incomplete {
            poison: Arc::clone(&self.poisoned),
            complete: false,
        };
        stream.write_all(b"O").await?;
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
                let socket: std::net::TcpStream = fd.into();
                socket.set_nonblocking(true)?;
                TcpStream::from_std(socket)
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
