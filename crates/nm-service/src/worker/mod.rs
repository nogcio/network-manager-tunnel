//! Linux worker startup and packet-device adapter; shared dispatch is in dataplane.
use crate::{
    dns, schema,
    telemetry::{self, Meter},
    wire::{self, Broker},
};
use async_io::Async;
use nm_tunnel_dataplane::runtime::{self, PacketIo};
use std::{
    io,
    net::SocketAddr,
    os::fd::AsFd,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::{net::UnixStream, time::timeout};

pub(crate) static STAGE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);

#[cfg(test)]
#[path = "source_tests.rs"]
mod source_tests;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[cfg(test)]
mod datagram;
#[cfg(test)]
mod destination;
mod host;
#[cfg(test)]
mod resolver;
#[cfg(test)]
mod routing;
#[cfg(test)]
mod stream;
#[cfg(test)]
use nm_tunnel_dataplane::runtime::udp_deadline;
#[cfg(test)]
use stream::{forward_tcp, route_tcp};
#[cfg(test)]
use tokio::sync::mpsc;

struct Tun(Async<std::fs::File>);

#[async_trait::async_trait]
impl PacketIo for Tun {
    async fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0
            .read_with(|fd| rustix::io::read(fd, &mut *buffer).map_err(Into::into))
            .await
    }
    async fn write(&self, bytes: &[u8]) -> io::Result<()> {
        let size = self
            .0
            .write_with(|fd| rustix::io::write(fd, bytes).map_err(io::Error::from))
            .await?;
        if size != bytes.len() {
            return Err(io::Error::other("Short TUN packet write."));
        }
        Ok(())
    }
}

async fn probe(
    profile: &nm_tunnel_profile::Profile,
    broker: &Broker,
    endpoint: SocketAddr,
) -> io::Result<()> {
    STAGE.store(10, Ordering::SeqCst);
    let socket = broker.open_endpoint(endpoint).await?;
    STAGE.store(11, Ordering::SeqCst);
    nm_tunnel_engine::verify_peer_transport(profile, socket, endpoint)
        .await
        .map_err(|_| io::Error::other("Configured peer transport verification failed."))?;
    if profile.network().fake_ip() {
        let (id, query) = dns::dns_query()?;
        let response = broker.fake_dns(&query).await?;
        let ip = dns::dns_answer(id, &response)?
            .into_iter()
            .find(|ip| crate::fakeip::in_range(*ip))
            .ok_or_else(|| io::Error::other("FakeIP readiness refused."))?;
        if broker.fake_reverse(ip).await? != dns::PROBE_HOST {
            return Err(io::Error::other("FakeIP ownership mismatch."));
        }
    }
    Ok(())
}

pub(crate) async fn run() -> io::Result<()> {
    if rustix::process::geteuid().is_root() {
        return Err(io::Error::other("Worker must be unprivileged."));
    }
    let statistics: std::os::unix::net::UnixDatagram =
        std::io::stdout().as_fd().try_clone_to_owned()?.into();
    statistics.set_nonblocking(true)?;
    let statistics = Arc::new(tokio::net::UnixDatagram::from_std(statistics)?);
    let meter = Arc::new(Meter::default());
    let _publisher = crate::task::AbortTask(tokio::spawn(telemetry::publish(
        Arc::clone(&statistics),
        Arc::clone(&meter),
    )));
    let std_stream: std::os::unix::net::UnixStream =
        std::io::stderr().as_fd().try_clone_to_owned()?.into();
    std_stream.set_nonblocking(true)?;
    let mut stream = UnixStream::from_std(std_stream)?;
    let file: std::fs::File = wire::receive_tun(&stream).await?.into();
    let config = timeout(Duration::from_secs(5), wire::receive_config(&mut stream))
        .await
        .map_err(|_| io::Error::other("Worker configuration timeout."))??;
    STAGE.store(2, Ordering::SeqCst);
    let profile = Arc::new(
        schema::decode(config.name, &config.data, &config.secrets).map_err(io::Error::other)?,
    );
    let endpoint = config.endpoint;
    let lan = Arc::new(crate::lan::Plan::from_worker(&profile, &config.lan)?);
    drop(config.data);
    drop(config.secrets);
    let broker = Arc::new(Broker::new(stream));
    timeout(Duration::from_secs(15), probe(&profile, &broker, endpoint))
        .await
        .map_err(|_| io::Error::other("Proxy readiness timeout."))??;
    STAGE.store(3, Ordering::SeqCst);
    let tun = Arc::new(Tun(Async::new(file)?));
    let health = crate::health::monitor(
        || probe(&profile, &broker, endpoint),
        || !broker.poisoned.load(Ordering::SeqCst),
        || STAGE.load(Ordering::SeqCst),
        |report| {
            if let Ok(bytes) = serde_json::to_vec(&report) {
                let _ = statistics.try_send(&bytes);
            }
        },
    );
    runtime::run(
        runtime::Context {
            profile: Arc::clone(&profile),
            host: Arc::clone(&broker),
            endpoint,
            lan,
            packets: tun,
            observer: meter,
        },
        broker.ready(),
        health,
        |stage| STAGE.store(stage, Ordering::SeqCst),
    )
    .await
}
