//! Unprivileged TUN/netstack worker; its only upstream sockets come from the broker.
use crate::{
    network, schema,
    telemetry::{self, Meter},
    wire::{self, Broker},
};
use async_io::Async;
use futures_util::{SinkExt, StreamExt};
use std::{
    collections::HashMap,
    future::Future,
    io,
    net::SocketAddr,
    os::fd::AsFd,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::UnixStream,
    sync::{Semaphore, mpsc},
    task::JoinSet,
    time::timeout,
};

pub(crate) static STAGE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);

// Leave headroom below the pinned Linux lwIP pool of 1024 TCP PCBs for
// handshakes and closing states. This bounds tasks, not guaranteed throughput.
const TCP_FLOW_LIMIT: usize = 512;

#[cfg(test)]
#[path = "worker_tests.rs"]
mod tests;

/// Bound broker queueing and protocol setup, not the established stream's lifetime.
/// Both streams are owned here and close on error or cancellation. Half-close and
/// backpressure are handled by Tokio; the worker owns admission and task teardown.
async fn forward_tcp<I, R, F>(mut inbound: I, setup: F) -> io::Result<()>
where
    I: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
    F: Future<Output = io::Result<R>>,
{
    let mut remote = timeout(Duration::from_secs(60), setup)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP setup deadline."))??;
    tokio::io::copy_bidirectional(&mut inbound, &mut remote).await?;
    Ok(())
}

/// Includes broker queueing and writes, not just waiting for the next datagram.
/// Cancelling an in-flight broker exchange retains its channel-poison semantics.
async fn udp_deadline<F: Future>(operation: F) -> io::Result<F::Output> {
    timeout(Duration::from_secs(60), operation)
        .await
        .map_err(|_| io::Error::other("UDP inactivity deadline."))
}

/// Independently polled by the worker loop: a slow probe must not stop packet
/// dispatch or flow reaping. Sequential probes cannot overlap or catch up in bursts.
async fn monitor_health<F, P>(mut probe: P) -> io::Result<()>
where
    F: Future<Output = io::Result<()>>,
    P: FnMut() -> F,
{
    loop {
        tokio::time::sleep(Duration::from_secs(20)).await;
        timeout(Duration::from_secs(15), probe())
            .await
            .map_err(|_| io::Error::other("Proxy health timeout."))??;
    }
}

async fn tun_read(tun: &Async<std::fs::File>, buffer: &mut [u8]) -> io::Result<usize> {
    tun.read_with(|fd| rustix::io::read(fd, &mut *buffer).map_err(Into::into))
        .await
}
async fn tun_write(tun: &Async<std::fs::File>, bytes: &[u8]) -> io::Result<()> {
    let size = tun
        .write_with(|fd| rustix::io::write(fd, bytes).map_err(io::Error::from))
        .await?;
    if size != bytes.len() {
        return Err(io::Error::other("Short TUN packet write."));
    }
    Ok(())
}

async fn probe(
    profile: &nm_tunnel_profile::Profile,
    broker: &Broker,
    endpoint: SocketAddr,
) -> io::Result<()> {
    STAGE.store(10, Ordering::SeqCst);
    let socket = broker.open().await?;
    STAGE.store(11, Ordering::SeqCst);
    let udp = nm_tunnel_engine::connect_udp(
        profile,
        socket,
        endpoint,
        SocketAddr::from((network::VPN_DNS, 53)),
    )
    .await
    .map_err(|_| io::Error::other("Proxy UDP setup failed."))?;
    let (id, query) = network::dns_query()?;
    STAGE.store(12, Ordering::SeqCst);
    udp.send(&query)
        .await
        .map_err(|_| io::Error::other("Proxy DNS send failed."))?;
    STAGE.store(13, Ordering::SeqCst);
    let response = timeout(Duration::from_secs(5), udp.receive())
        .await
        .map_err(|_| io::Error::other("Proxy DNS timeout."))?
        .map_err(|_| io::Error::other("Proxy DNS refused."))?;
    STAGE.store(14, Ordering::SeqCst);
    network::dns_answer(id, &response)?;
    Ok(())
}

pub(crate) async fn run() -> io::Result<()> {
    if rustix::process::geteuid().is_root() {
        return Err(io::Error::other("Worker must be unprivileged."));
    }
    let statistics: std::os::unix::net::UnixDatagram =
        std::io::stdout().as_fd().try_clone_to_owned()?.into();
    statistics.set_nonblocking(true)?;
    let statistics = tokio::net::UnixDatagram::from_std(statistics)?;
    let meter = Arc::new(Meter::default());
    let _publisher = crate::activation::AbortTask(tokio::spawn(telemetry::publish(
        statistics,
        Arc::clone(&meter),
    )));
    let std_stream: std::os::unix::net::UnixStream =
        std::io::stderr().as_fd().try_clone_to_owned()?.into();
    std_stream.set_nonblocking(true)?;
    let mut stream = UnixStream::from_std(std_stream)?;
    let config = timeout(Duration::from_secs(5), wire::receive_config(&mut stream))
        .await
        .map_err(|_| io::Error::other("Worker configuration timeout."))??;
    STAGE.store(2, Ordering::SeqCst);
    let profile = Arc::new(
        schema::decode(config.name, &config.data, &config.secrets, false)
            .map_err(io::Error::other)?,
    );
    let endpoint = config.endpoint;
    drop(config.data);
    drop(config.secrets);
    let broker = Arc::new(Broker::new(stream));
    timeout(Duration::from_secs(15), probe(&profile, &broker, endpoint))
        .await
        .map_err(|_| io::Error::other("Proxy readiness timeout."))??;
    STAGE.store(3, Ordering::SeqCst);
    let file: std::fs::File = std::io::stdin().as_fd().try_clone_to_owned()?.into();
    let tun = Arc::new(Async::new(file)?);
    let (stack, mut tcp, udp) = lwip::NetStack::with_buffer_size(64, 64)
        .map_err(|_| io::Error::other("Netstack initialization failed."))?;
    STAGE.store(4, Ordering::SeqCst);
    let mut done = stack.core_done();
    let (mut sink, mut packets) = stack.split();
    let (udp_send, mut udp_receive) = udp.split();
    let udp_send = Arc::new(udp_send);
    let mut tasks: JoinSet<io::Result<()>> = JoinSet::new();
    let ingress = Arc::clone(&tun);
    let ingress_meter = Arc::clone(&meter);
    tasks.spawn(async move {
        let mut buffer = vec![0; 65535];
        loop {
            let length = tun_read(&ingress, &mut buffer).await?;
            if length == 0 {
                return Err(io::Error::other("TUN closed."));
            }
            ingress_meter.packet(true, length);
            if length >= 20 && buffer[0] >> 4 == 4 && matches!(buffer[9], 6 | 17) {
                sink.send(buffer[..length].to_vec()).await?;
            } else {
                ingress_meter.dropped();
            }
        }
    });
    let egress_meter = Arc::clone(&meter);
    tasks.spawn(async move {
        while let Some(packet) = packets.next().await {
            let packet = packet?;
            tun_write(&tun, &packet).await?;
            egress_meter.packet(false, packet.len());
        }
        Err(io::Error::other("Netstack stopped."))
    });
    broker.ready().await?;
    STAGE.store(7, Ordering::SeqCst);
    let tcp_slots = Arc::new(Semaphore::new(TCP_FLOW_LIMIT));
    let mut flows = JoinSet::new();
    let mut udp_flows: HashMap<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>> = HashMap::new();
    let health = monitor_health(|| async {
        if broker.poisoned.load(Ordering::SeqCst) {
            return Err(io::Error::other("Broker cancelled."));
        }
        probe(&profile, &broker, endpoint).await
    });
    tokio::pin!(health);
    let outcome = loop {
        tokio::select! {
            _ = tasks.join_next() => break Err(io::Error::other("Packet pump failed.")),
            result = &mut health => break result,
            Some((inbound, _, destination)) = tcp.next() => {
                if !destination.is_ipv4() { meter.dropped(); continue; }
                let Ok(slot) = Arc::clone(&tcp_slots).try_acquire_owned() else { meter.dropped(); continue; };
                let broker = Arc::clone(&broker); let profile = Arc::clone(&profile);
                let flow = meter.flow(true);
                flows.spawn(async move {
                    let _slot = slot;
                    let result = forward_tcp(inbound, async {
                        let socket = broker.open().await?;
                        nm_tunnel_engine::connect_tcp(&profile, socket, endpoint, destination).await.map_err(|_| io::Error::other("TCP proxy failed."))
                    }).await;
                    if result.is_err() { flow.failed(); }
                });
            }
            Ok((payload, source, destination)) = udp_receive.recv_from() => {
                if !source.is_ipv4() || !destination.is_ipv4() || payload.len() > 65507 { meter.dropped(); continue; }
                udp_flows.retain(|_, sender| !sender.is_closed());
                let key = (source, destination);
                if !udp_flows.contains_key(&key) {
                    if udp_flows.len() >= 64 { meter.dropped(); continue; }
                    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(16);
                    udp_flows.insert(key, tx);
                    let broker = Arc::clone(&broker); let profile = Arc::clone(&profile); let sender = Arc::clone(&udp_send);
                    let flow = meter.flow(false);
                    let udp_meter = Arc::clone(&meter);
                    flows.spawn(async move {
                        let result = async {
                            // Engine setup already has its own ten-second bound;
                            // this outer deadline also covers waiting for the broker.
                            let remote = udp_deadline(async {
                                let socket = broker.open().await?;
                                nm_tunnel_engine::connect_udp(&profile, socket, endpoint, destination).await.map_err(|_| io::Error::other("UDP proxy failed."))
                            }).await??;
                            let mut reading = Box::pin(remote.receive());
                            loop {
                                enum Activity { Send(Option<Vec<u8>>), Receive(Result<Vec<u8>, nm_tunnel_engine::Error>) }
                                let activity = udp_deadline(async {
                                    tokio::select! {
                                        data = rx.recv() => Activity::Send(data),
                                        data = &mut reading => Activity::Receive(data),
                                    }
                                }).await?;
                                match activity {
                                    Activity::Send(Some(data)) => udp_deadline(remote.send(&data)).await?.map_err(|_| io::Error::other("UDP write failed."))?,
                                    Activity::Send(None) => return Ok(()),
                                    Activity::Receive(data) => {
                                            let data = data.map_err(|_| io::Error::other("UDP read failed."))?;
                                            match sender.send_to(&data, &destination, &source) {
                                                 Err(e) if e.kind() == io::ErrorKind::WouldBlock => { udp_meter.dropped(); Ok(()) }, other => other,
                                            }?;
                                            reading = Box::pin(remote.receive());
                                    }
                                }
                            }
                        };
                        let result: io::Result<()> = result.await;
                        if result.is_err() { flow.failed(); }
                    });
                }
                if let Some(sender) = udp_flows.get(&key) && sender.try_send(payload).is_err() { meter.dropped(); }
            }
            _ = flows.join_next(), if !flows.is_empty() => {}
        }
    };
    flows.abort_all();
    tasks.abort_all();
    while flows.join_next().await.is_some() {}
    while tasks.join_next().await.is_some() {}
    drop(tcp);
    drop(udp_receive);
    drop(udp_send);
    drop(udp_flows);
    let _ = timeout(Duration::from_secs(2), done.wait_for(|complete| *complete)).await;
    outcome
}
