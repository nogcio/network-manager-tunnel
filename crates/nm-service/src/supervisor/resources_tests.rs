use super::*;
use std::time::Duration;
use tokio::time::timeout;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixDatagram, UnixStream},
    sync::oneshot,
};

#[tokio::test]
async fn shutdown_joins_nested_relays_before_releasing_cleanup_barrier() -> io::Result<()> {
    timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let upstream = TcpStream::connect(listener.local_addr()?).await?;
        let (mut peer, _) = listener.accept().await?;
        let (local, mut worker) = UnixStream::pair()?;
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let remote = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        udp.connect(remote.local_addr()?).await?;
        let (parent_datagram, worker_datagram) = UnixDatagram::pair()?;
        use std::os::fd::AsRawFd;
        let udp_descriptor =
            std::fs::read_link(format!("/proc/self/fd/{}", parent_datagram.as_raw_fd()))?;
        let mut resources = Resources::default();
        let relays = Arc::clone(&resources.relays);
        let (ready, started) = oneshot::channel();
        resources.broker = Some(AbortTask(tokio::spawn(async move {
            let mut relays = relays.lock().await;
            relays.tcp.spawn(crate::stream_relay::run(upstream, local));
            relays
                .udp
                .spawn(crate::lan_relay::run(udp, parent_datagram));
            let _ = ready.send(());
            std::future::pending().await
        })));
        started.await.map_err(io::Error::other)?;
        worker.write_all(b"x").await?;
        let mut byte = [0];
        peer.read_exact(&mut byte).await?;
        worker_datagram.send(b"u").await?;
        remote.recv(&mut byte).await?;
        resources.stop().await?;
        assert!(resources.relays.lock().await.tcp.is_empty());
        assert!(resources.relays.lock().await.udp.is_empty());
        assert_eq!(peer.read(&mut byte).await?, 0);
        assert_eq!(worker.read(&mut byte).await?, 0);
        // Concurrent fork/exec tests can transiently inherit CLOEXEC descriptors.
        // Check this owner's descriptor release, not those unrelated fork windows.
        for entry in std::fs::read_dir("/proc/self/fd")? {
            assert_ne!(
                std::fs::read_link(entry?.path()).ok().as_ref(),
                Some(&udp_descriptor)
            );
        }
        resources.stop().await?;
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Resource barrier deadline."))?
}

#[tokio::test]
async fn shutdown_confirms_owned_process_exit_and_is_idempotent() -> io::Result<()> {
    timeout(Duration::from_secs(5), async {
        let child = tokio::process::Command::new("/usr/bin/sleep")
            .arg("60")
            .kill_on_drop(true)
            .spawn()?;
        let mut resources = Resources {
            child: Some(child),
            ..Resources::default()
        };
        resources.stop().await?;
        assert!(resources.child.is_none());
        resources.stop().await
    })
    .await
    .map_err(|_| io::Error::other("Child barrier deadline."))?
}

#[tokio::test]
async fn unconfirmed_worker_retains_ownership_and_cannot_release_the_barrier() -> io::Result<()> {
    timeout(Duration::from_secs(5), async {
        let child = tokio::process::Command::new("/usr/bin/sleep")
            .arg("60")
            .kill_on_drop(true)
            .spawn()?;
        let writer = tokio::process::Command::new("/usr/bin/sleep")
            .arg("60")
            .kill_on_drop(true)
            .spawn()?;
        let mut resources = Resources {
            child: Some(child),
            guard_writer: Some(writer),
            ..Resources::default()
        };
        let result = resources
            .finish_stop(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Synthetic unconfirmed worker",
            )))
            .await;
        assert!(result.is_err());
        assert!(
            resources
                .child
                .as_mut()
                .is_some_and(|child| child.try_wait().is_ok_and(|status| status.is_none()))
        );
        assert!(
            resources
                .guard_writer
                .as_mut()
                .is_some_and(|child| child.try_wait().is_ok_and(|status| status.is_some()))
        );
        resources.stop().await?;
        assert!(resources.child.is_none());
        assert!(resources.guard_writer.is_none());
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Refused barrier deadline."))?
}
