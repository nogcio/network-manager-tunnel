//! Real pinned Mux.Cool setup/queue over controlled I/O, not a packet-connection mock.
use super::*;
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
struct Control {
    stalled: AtomicBool,
    blocked: tokio::sync::Notify,
    dropped: AtomicBool,
}

struct StalledTransport(Arc<Control>);

impl Drop for StalledTransport {
    fn drop(&mut self) {
        self.0.dropped.store(true, Ordering::SeqCst);
    }
}
impl AsyncRead for StalledTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}
impl AsyncWrite for StalledTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.0.stalled.load(Ordering::SeqCst) {
            self.0.blocked.notify_one();
            Poll::Pending
        } else {
            Poll::Ready(Ok(buf.len()))
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn cancelling_backpressured_ip_and_domain_xudp_drops_transport_without_peer_progress()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(5), async {
        for domain in [false, true] {
            let control = Arc::new(Control::default());
            let (owner, stream) =
                crate::owned_transport::wrap(Box::new(StalledTransport(Arc::clone(&control))));
            let dialer = Arc::new(SuppliedSocket(Mutex::new(Some(stream))));
            // Security handshakes are intentionally absent: the defect is in the
            // production mux lifecycle after setup, independent of TLS/REALITY.
            let adapter = meow_proxy::VlessAdapter::new(
                "synthetic-backpressure",
                "peer.example",
                443,
                [1; 16],
                None,
                true,
                meow_proxy::TransportChain::empty(),
                dialer,
            );
            let destination = if domain {
                PacketAddr::domain("echo.fixture.invalid", 53)?
            } else {
                PacketAddr::Ip(([192, 0, 2, 1], 53).into())
            };
            let tunnel = connect_adapter(adapter, destination, true, Some(owner)).await?;
            control.stalled.store(true, Ordering::SeqCst);
            tunnel.send(b"start-backpressure").await?;
            control.blocked.notified().await; // Actual write stall, not a timed sleep.
            let mut queued = 0;
            loop {
                let mut send = Box::pin(tunnel.send(b"queued-payload"));
                match std::future::poll_fn(|cx| Poll::Ready(send.as_mut().poll(cx))).await {
                    Poll::Ready(result) => {
                        result?;
                        queued += 1;
                        tokio::task::yield_now().await;
                    }
                    Poll::Pending => {
                        drop(send);
                        break;
                    } // Cancel the blocked send.
                }
            }
            assert!(queued > 0, "Must fill the real mux outbound queue");
            assert!(!control.dropped.load(Ordering::SeqCst));
            drop(tunnel);
            assert!(
                control.dropped.load(Ordering::SeqCst),
                "Transport drop must be synchronous, not dependent on queuing an End frame"
            );
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await?
}
