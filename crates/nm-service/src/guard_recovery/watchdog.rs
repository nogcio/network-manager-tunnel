//! Process-pinned liveness lease. Never signal a recycled numeric PID.
use async_io::Async;
use std::{
    io,
    os::fd::{AsFd, OwnedFd},
    time::Duration,
};
use tokio::time::{Instant, timeout};

pub(super) const LEASE: Duration = Duration::from_secs(30);

pub(super) struct Lease {
    pub owner: String,
    process: Async<OwnedFd>,
    expires: Instant,
}

impl Lease {
    fn new(owner: String, process: OwnedFd) -> io::Result<Self> {
        Ok(Self {
            owner,
            process: Async::new(process)?,
            expires: Instant::now() + LEASE,
        })
    }

    /// ProcessFD comes from the message bus, never a backend-supplied PID/descriptor.
    /// Missing support refuses arming before guards. No PID-based fallback exists.
    pub async fn pin(bus: &zbus::Connection, owner: String) -> io::Result<Self> {
        timeout(Duration::from_secs(3), Self::pin_process(bus, owner))
            .await
            .map_err(|_| super::unavailable())?
    }

    async fn pin_process(bus: &zbus::Connection, owner: String) -> io::Result<Self> {
        let proxy = zbus::fdo::DBusProxy::new(bus)
            .await
            .map_err(|_| super::unavailable())?;
        let credentials = proxy
            .get_connection_credentials(
                owner
                    .as_str()
                    .try_into()
                    .map_err(|_| super::unavailable())?,
            )
            .await
            .map_err(|_| super::unavailable())?;
        let process = credentials
            .process_fd()
            .ok_or_else(|| {
                io::Error::other("D-Bus ProcessFD support is required for automatic recovery.")
            })?
            .as_fd()
            .try_clone_to_owned()?;
        if super::backend_owner(bus).await?.as_deref() != Some(owner.as_str()) {
            return Err(super::unavailable());
        }
        Self::new(owner, process)
    }

    pub fn expired(&self) -> bool {
        Instant::now() >= self.expires
    }

    /// A delayed heartbeat cannot revive a lease after its terminal deadline.
    pub fn renew(&mut self) -> io::Result<()> {
        if self.expired() {
            return Err(io::Error::other("Backend liveness lease expired."));
        }
        self.expires = Instant::now() + LEASE;
        Ok(())
    }

    /// Terminal failure ends session protection. Wait for process death before
    /// allowing cleanup; failed signaling/readiness never grants permission to clear.
    pub async fn terminate(&self) -> io::Result<()> {
        match rustix::process::pidfd_send_signal(
            self.process.get_ref(),
            rustix::process::Signal::KILL,
        ) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => {}
            Err(error) => return Err(error.into()),
        }
        timeout(Duration::from_secs(3), self.process.readable())
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Backend termination is not confirmed.",
                )
            })??;
        Ok(())
    }

    pub async fn stop_then(
        &self,
        cleanup: impl std::future::Future<Output = io::Result<()>>,
    ) -> io::Result<()> {
        self.terminate().await?;
        cleanup.await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn expired_leases_cannot_be_revived_by_a_late_heartbeat() -> io::Result<()> {
        let process = rustix::process::pidfd_open(
            rustix::process::getpid(),
            rustix::process::PidfdFlags::empty(),
        )?;
        let mut lease = Lease::new(":1.synthetic".into(), process)?;
        tokio::time::advance(LEASE - Duration::from_secs(1)).await;
        lease.renew()?;
        assert!(!lease.expired());
        tokio::time::advance(LEASE).await;
        assert!(lease.expired());
        assert!(lease.renew().is_err());
        assert!(lease.expired());
        Ok(())
    }

    #[tokio::test]
    async fn termination_is_pinned_to_an_owned_child_and_waits_for_its_exit() -> io::Result<()> {
        timeout(Duration::from_secs(10), async {
            let mut child = tokio::process::Command::new("cat")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()?;
            let pid = child
                .id()
                .and_then(|pid| i32::try_from(pid).ok())
                .and_then(rustix::process::Pid::from_raw)
                .ok_or_else(|| io::Error::other("Missing child PID."))?;
            let lease = Lease::new(
                ":1.synthetic".into(),
                rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())?,
            )?;
            lease
                .stop_then(async {
                    assert!(
                        child.try_wait()?.is_some(),
                        "cleanup must follow confirmed process exit"
                    );
                    Ok(())
                })
                .await?;
            assert!(!child.wait().await?.success());
            // Repeating termination on the same dead process is harmless and cannot
            // target a future process assigned the old numeric PID.
            lease.terminate().await?;
            Ok(())
        })
        .await
        .map_err(|_| io::Error::other("Child termination test deadline."))?
    }

    #[tokio::test]
    async fn an_invalid_process_descriptor_never_polls_cleanup() -> io::Result<()> {
        let (socket, _peer) = std::os::unix::net::UnixStream::pair()?;
        socket.set_nonblocking(true)?;
        let lease = Lease::new(":1.synthetic".into(), socket.into())?;
        let cleaned = std::cell::Cell::new(false);
        assert!(
            lease
                .stop_then(async {
                    cleaned.set(true);
                    Ok(())
                })
                .await
                .is_err()
        );
        assert!(!cleaned.get());
        Ok(())
    }
}
