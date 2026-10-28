//! Destination-confined root TCP bridges for endpoint, hostname-Direct and LAN.
use crate::wire;
use std::io;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::{
    net::{TcpStream, UnixStream},
    task::JoinSet,
};

// 512 TCP flows, 64 UDP-over-TCP associations, 32 DNS tasks and one health probe.
pub(crate) const LIMIT: usize = 512 + 64 + 32 + 1;

pub(crate) fn available(tasks: &mut JoinSet<io::Result<()>>) -> bool {
    while tasks.try_join_next().is_some() {}
    tasks.len() < LIMIT
}

/// Caller validates the fixed IP peer before handing ownership here. Only the
/// Unix payload FD is transferred; the marked IP socket stays in this task set.
/// A failed send owns/closes both ends and the upstream. Parent cancellation
/// must abort and join the externally owned set before releasing session guards.
pub(crate) async fn grant(
    control: &UnixStream,
    socket: TcpStream,
    tasks: &mut JoinSet<io::Result<()>>,
) -> io::Result<()> {
    if !available(tasks) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Stream relay capacity reached.",
        ));
    }
    let (parent, worker) = std::os::unix::net::UnixStream::pair()?;
    parent.set_nonblocking(true)?;
    worker.set_nonblocking(true)?;
    let parent = UnixStream::from_std(parent)?;
    wire::send_socket(control, &worker).await?;
    tasks.spawn(run(socket, parent));
    Ok(())
}

/// Established bidirectional traffic has no lifetime deadline. Once either half
/// closes, allow sixty seconds for the other direction to drain, then close the
/// bridge. Otherwise dropped worker channels could pin root slots indefinitely.
pub(crate) async fn run(upstream: TcpStream, local: UnixStream) -> io::Result<()> {
    let (mut upstream_read, mut upstream_write) = upstream.into_split();
    let (mut local_read, mut local_write) = local.into_split();
    let outgoing = async {
        tokio::io::copy(&mut local_read, &mut upstream_write).await?;
        upstream_write.shutdown().await
    };
    let incoming = async {
        tokio::io::copy(&mut upstream_read, &mut local_write).await?;
        local_write.shutdown().await
    };
    tokio::pin!(outgoing, incoming);
    let drained = tokio::select! {
        result=&mut outgoing => { result?; tokio::time::timeout(Duration::from_secs(60),&mut incoming).await },
        result=&mut incoming => { result?; tokio::time::timeout(Duration::from_secs(60),&mut outgoing).await },
    };
    drained.map_err(|_| io::Error::other("Stream relay half-close deadline."))?
}

#[cfg(test)]
#[path = "stream_relay_tests.rs"]
mod tests;
