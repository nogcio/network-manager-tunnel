//! Revocation of an exclusively owned transport, independent of protocol queues.
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct State {
    stream: Option<Box<dyn meow_transport::Stream>>,
    reader: Option<Waker>,
    writer: Option<Waker>,
}

/// The flow's exclusive ownership capability. Drop closes the underlying channel
/// synchronously, even if a protocol-library task still holds its I/O wrapper.
pub(super) struct Owner(Arc<Mutex<State>>);

struct Revocable(Arc<Mutex<State>>);

pub(super) fn wrap(
    stream: Box<dyn meow_transport::Stream>,
) -> (Owner, Box<dyn meow_transport::Stream>) {
    let state = Arc::new(Mutex::new(State {
        stream: Some(stream),
        reader: None,
        writer: None,
    }));
    (Owner(Arc::clone(&state)), Box::new(Revocable(state)))
}

impl Drop for Owner {
    fn drop(&mut self) {
        let (stream, reader, writer) = {
            // Even a panic in dependency polling must not retain transport ownership.
            let mut state = self.0.lock().unwrap_or_else(|error| error.into_inner());
            (
                state.stream.take(),
                state.reader.take(),
                state.writer.take(),
            )
        };
        drop(stream);
        if let Some(reader) = reader {
            reader.wake();
        }
        if let Some(writer) = writer {
            writer.wake();
        }
    }
}

impl Revocable {
    fn poll<T>(
        &self,
        cx: &mut Context<'_>,
        read: bool,
        operation: impl FnOnce(
            &mut Box<dyn meow_transport::Stream>,
            &mut Context<'_>,
        ) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        let Ok(mut state) = self.0.lock() else {
            return Poll::Ready(Err(closed()));
        };
        let Some(stream) = &mut state.stream else {
            return Poll::Ready(Err(closed()));
        };
        // Poll and register under the same lock: revocation cannot miss a wakeup.
        // AsyncRead/Write polling is nonblocking; no lock crosses an await.
        let result = operation(stream, cx);
        let slot = if read {
            &mut state.reader
        } else {
            &mut state.writer
        };
        *slot = result.is_pending().then(|| cx.waker().clone());
        result
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "Owned transport closed.")
}

impl AsyncRead for Revocable {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll(cx, true, |stream, cx| Pin::new(stream).poll_read(cx, buf))
    }
}

impl AsyncWrite for Revocable {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll(cx, false, |stream, cx| Pin::new(stream).poll_write(cx, buf))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll(cx, false, |stream, cx| Pin::new(stream).poll_flush(cx))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll(cx, false, |stream, cx| Pin::new(stream).poll_shutdown(cx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::Future,
        sync::atomic::{AtomicUsize, Ordering},
        task::Wake,
        time::Duration,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn revocation_wakes_both_pending_directions_and_releases_shared_state() -> io::Result<()>
    {
        struct WakeCount(AtomicUsize);
        impl Wake for WakeCount {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            let (stream, mut peer) = tokio::io::duplex(1);
            let (owner, stream) = wrap(Box::new(stream));
            let weak = Arc::downgrade(&owner.0);
            let (mut reader, mut writer) = tokio::io::split(stream);
            let mut read = Box::pin(reader.read_u8());
            let payload = vec![1; 1024];
            let mut write = Box::pin(writer.write_all(&payload));
            let read_count = Arc::new(WakeCount(AtomicUsize::new(0)));
            let write_count = Arc::new(WakeCount(AtomicUsize::new(0)));
            let read_waker = Waker::from(Arc::clone(&read_count));
            let write_waker = Waker::from(Arc::clone(&write_count));
            assert!(
                read.as_mut()
                    .poll(&mut Context::from_waker(&read_waker))
                    .is_pending()
            );
            assert!(
                write
                    .as_mut()
                    .poll(&mut Context::from_waker(&write_waker))
                    .is_pending()
            );
            drop(owner);
            assert!(read_count.0.load(Ordering::SeqCst) > 0);
            assert!(write_count.0.load(Ordering::SeqCst) > 0);
            assert_eq!(
                read.await
                    .err()
                    .ok_or_else(|| io::Error::other("Read survived revocation."))?
                    .kind(),
                io::ErrorKind::BrokenPipe
            );
            assert_eq!(
                write
                    .await
                    .err()
                    .ok_or_else(|| io::Error::other("Write survived revocation."))?
                    .kind(),
                io::ErrorKind::BrokenPipe
            );
            peer.read_to_end(&mut Vec::new()).await?;
            drop(reader);
            drop(writer);
            assert!(
                weak.upgrade().is_none(),
                "No waker or I/O wrapper may retain shared state"
            );
            Ok(())
        })
        .await
        .map_err(|_| io::Error::other("Revocation contract deadline."))?
    }
}
