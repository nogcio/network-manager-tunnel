//! Root-owned LAN bridges. Only Unix payload channels cross into the worker.
use std::{io, time::Duration};
use tokio::{
    net::{UdpSocket, UnixDatagram},
    time::timeout,
};

pub(crate) const LIMIT: usize = 64;

pub(crate) async fn grant(
    control: &tokio::net::UnixStream,
    socket: UdpSocket,
    tasks: &mut tokio::task::JoinSet<io::Result<()>>,
) -> io::Result<()> {
    while tasks.try_join_next().is_some() {}
    if tasks.len() >= LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Datagram relay capacity reached.",
        ));
    }
    let (parent, worker) = std::os::unix::net::UnixDatagram::pair()?;
    parent.set_nonblocking(true)?;
    worker.set_nonblocking(true)?;
    let parent = UnixDatagram::from_std(parent)?;
    crate::wire::send_socket(control, &worker).await?;
    tasks.spawn(run(socket, parent));
    Ok(())
}

/// Own both sockets until cancellation, I/O error or sixty seconds of inactivity.
/// Upstream is already connected/marked/uplink-bound; no payload can retarget it.
/// Each write has a five-second deadline, each datagram a 65,507-byte bound.
pub(crate) async fn run(upstream: UdpSocket, local: UnixDatagram) -> io::Result<()> {
    let mut outgoing = vec![0; 65508];
    let mut incoming = vec![0; 65508];
    loop {
        enum Direction {
            Out(usize),
            In(usize),
        }
        let activity = timeout(Duration::from_secs(60), async {
            tokio::select! {
                size = local.recv(&mut outgoing) => size.map(Direction::Out),
                size = upstream.recv(&mut incoming) => size.map(Direction::In),
            }
        })
        .await
        .map_err(|_| io::Error::other("LAN datagram idle deadline."))??;
        let (size, written) = match activity {
            Direction::Out(size) => {
                if size > 65507 {
                    return Err(io::Error::other("Oversized LAN datagram."));
                }
                (
                    size,
                    timeout(Duration::from_secs(5), upstream.send(&outgoing[..size])).await,
                )
            }
            Direction::In(size) => {
                if size > 65507 {
                    return Err(io::Error::other("Oversized LAN datagram."));
                }
                (
                    size,
                    timeout(Duration::from_secs(5), local.send(&incoming[..size])).await,
                )
            }
        };
        if written.map_err(|_| io::Error::other("LAN datagram write deadline."))?? != size {
            return Err(io::Error::other("Short LAN datagram write."));
        }
    }
}

#[cfg(test)]
#[path = "lan_relay_tests.rs"]
mod tests;
