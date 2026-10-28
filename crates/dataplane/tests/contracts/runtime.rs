use super::support::*;
use nm_tunnel_dataplane::runtime::{self, Observer, PacketIo};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex, mpsc};

struct Packets(Mutex<mpsc::Receiver<Vec<u8>>>);
#[async_trait::async_trait]
impl PacketIo for Packets {
    async fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let packet = self.0.lock().await.recv().await.unwrap_or_default();
        buffer[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }
    async fn write(&self, _: &[u8]) -> io::Result<()> {
        Err(io::Error::other("Unexpected egress packet."))
    }
}
#[derive(Default)]
struct Meter {
    packets: AtomicUsize,
    drops: AtomicUsize,
}
struct Flow;
impl runtime::Flow for Flow {
    fn failed(&self) {}
}
impl Observer for Meter {
    type Flow = Flow;
    fn packet(&self, _: bool, _: usize) {
        self.packets.fetch_add(1, Ordering::SeqCst);
    }
    fn dropped(&self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
    fn flow(self: &Arc<Self>, _: bool) -> Flow {
        Flow
    }
}

#[tokio::test]
async fn packet_failure_and_readiness_refusal_join_pumps_without_host_requests() -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        // Sequential generations share this test's one lwIP runtime, never parallel cores.
        for refused in [true, false] {
            let (sender, receiver) = mpsc::channel(2);
            let packets = Arc::new(Packets(Mutex::new(receiver)));
            let host = Arc::new(Refuse::default());
            let meter = Arc::new(Meter::default());
            let profile = Arc::new(profile()?);
            let lan = Arc::new(NoLan);
            if !refused {
                let mut ipv6 = vec![0; 40];
                ipv6[0] = 0x60;
                sender.send(ipv6).await.map_err(io::Error::other)?;
                drop(sender);
            }
            let outcome = runtime::run(
                runtime::Context {
                    profile: Arc::clone(&profile),
                    host: Arc::clone(&host),
                    endpoint: endpoint(),
                    lan: Arc::clone(&lan),
                    packets: Arc::clone(&packets),
                    observer: Arc::clone(&meter),
                },
                async {
                    if refused {
                        Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "Synthetic readiness refusal.",
                        ))
                    } else {
                        Ok(())
                    }
                },
                std::future::pending(),
                |_| {},
            )
            .await;
            assert!(outcome.is_err());
            assert_eq!(host.calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                Arc::strong_count(&packets),
                1,
                "packet pump cannot survive return"
            );
            assert_eq!(Arc::strong_count(&meter), 1);
            assert_eq!(Arc::strong_count(&profile), 1);
            if !refused {
                assert_eq!(meter.packets.load(Ordering::SeqCst), 1);
                assert_eq!(meter.drops.load(Ordering::SeqCst), 1);
            }
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Runtime contract deadline."))?
}
