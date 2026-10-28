//! Packet/flow scheduling over a supplied packet device and host capabilities.
use crate::{Host, LanScope, datagram, inspection, resolver, stream::route_tcp};
use futures_util::{SinkExt, StreamExt};
use std::{collections::HashMap, future::Future, io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    sync::{Semaphore, mpsc},
    task::JoinSet,
    time::timeout,
};

// Leave headroom below the pinned lwIP TCP PCB pool for handshake/closing states.
const TCP_FLOW_LIMIT: usize = 512;

/// A platform-owned packet device, already configured and protected by its owner.
/// Exactly one reader/writer is used. Drop must release owned handles; cancellation
/// must not publish partial packets or silently start another device.
#[async_trait::async_trait]
pub trait PacketIo: Send + Sync + 'static {
    /// Read one whole IP packet. Zero means closed; truncation must error.
    async fn read(&self, buffer: &mut [u8]) -> io::Result<usize>;
    /// Write one whole IP packet or error, including short writes.
    async fn write(&self, bytes: &[u8]) -> io::Result<()>;
}

/// An observation-only flow lease. Drop releases the active count, including abort.
pub trait Flow: Send {
    /// Record a setup/I/O failure, not explicit session cancellation.
    fn failed(&self);
}

/// Nonblocking, observation-only packet/flow counters; no lifecycle authority.
pub trait Observer: Send + Sync + 'static {
    /// An owned active-flow lease, released on completion or cancellation.
    type Flow: Flow;
    /// Count a successfully read/written packet, not protocol payload bytes.
    fn packet(&self, upload: bool, bytes: usize);
    /// Count a rejected packet or queue/admission backpressure drop.
    fn dropped(&self);
    /// Admit one observed flow; owns no sockets or networking permissions.
    fn flow(self: &Arc<Self>, tcp: bool) -> Self::Flow;
}

/// One checked activation. The caller owns configuration, protection and teardown.
pub struct Context<H, L, P, M> {
    /// Checked immutable profile; secrets never enter diagnostics.
    pub profile: Arc<nm_tunnel_profile::Profile>,
    /// Platform authority; no implicit sockets or resolver exist in this runtime.
    pub host: Arc<H>,
    /// Fixed approved proxy endpoint for this activation.
    pub endpoint: SocketAddr,
    /// Activation-local LAN eligibility, independent of platform authorization.
    pub lan: Arc<L>,
    /// Already configured packet device; runtime never allocates TUN or routes.
    pub packets: Arc<P>,
    /// Observation-only counters.
    pub observer: Arc<M>,
}

/// Includes host queueing and writes, not only waiting for the next datagram.
pub async fn udp_deadline<F: Future>(operation: F) -> io::Result<F::Output> {
    timeout(Duration::from_secs(60), operation)
        .await
        .map_err(|_| io::Error::other("UDP inactivity deadline."))
}

/// Run the existing IPv4 TCP/UDP packet pipeline with bounded queues and flows.
///
/// One pinned lwIP core is allowed per worker process. `ready` is called only
/// after stack/pump creation; `health` is polled beside dispatch, never as a task
/// that can outlive the session. Stage observations retain the existing 4/7 codes.
/// Any terminal error aborts and joins flows/pumps before stack shutdown (bounded
/// to two seconds). Dropping this future aborts owned tasks via JoinSet; the platform
/// must retain its external teardown barrier and guards until worker exit. Readiness
/// is not proof that platform routes/DNS are applied. No retries or direct fallback.
pub async fn run<H, L, P, M>(
    context: Context<H, L, P, M>,
    ready: impl Future<Output = io::Result<()>>,
    health: impl Future<Output = io::Result<()>>,
    stage: impl Fn(u8),
) -> io::Result<()>
where
    H: Host + 'static,
    L: LanScope + 'static,
    P: PacketIo,
    M: Observer,
{
    let Context {
        profile,
        host: broker,
        endpoint,
        lan,
        packets: tun,
        observer: meter,
    } = context;
    let (stack, mut tcp, udp) = lwip::NetStack::with_buffer_size(64, 64)
        .map_err(|_| io::Error::other("Netstack initialization failed."))?;
    stage(4);
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
            let length = ingress.read(&mut buffer).await?;
            if length == 0 {
                return Err(io::Error::other("TUN closed."));
            }
            if length > buffer.len() {
                return Err(io::Error::other("Invalid packet length."));
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
            tun.write(&packet).await?;
            egress_meter.packet(false, packet.len());
        }
        Err(io::Error::other("Netstack stopped."))
    });
    // Keep all exits inside the shutdown barrier, including readiness refusal.
    let outcome = async {
        ready.await?;
        stage(7);
        let tcp_slots = Arc::new(Semaphore::new(TCP_FLOW_LIMIT));
        let dns_slots = Arc::new(Semaphore::new(32));
        let mut flows = JoinSet::new();
        let mut udp_flows: HashMap<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>> = HashMap::new();
        tokio::pin!(health);
        let outcome = loop {
            tokio::select! {
                _ = tasks.join_next() => break Err(io::Error::other("Packet pump failed.")),
                result = &mut health => break result,
                Some((inbound, _, destination)) = tcp.next() => {
                    if !destination.is_ipv4() { meter.dropped(); continue; }
                    let Ok(slot) = Arc::clone(&tcp_slots).try_acquire_owned() else { meter.dropped(); continue; };
                    let broker = Arc::clone(&broker);
                    let profile = Arc::clone(&profile);
                    let lan = Arc::clone(&lan);
                    let flow = meter.flow(true);
                    flows.spawn(async move {
                        let _slot = slot;
                        let result = route_tcp(inbound, &profile, &broker, endpoint, destination, &lan).await;
                        if result.is_err() { flow.failed(); }
                    });
                }
                Ok((payload, source, destination)) = udp_receive.recv_from() => {
                    if !source.is_ipv4() || !destination.is_ipv4() || payload.len() > 65507 { meter.dropped(); continue; }
                    if resolver::handles(&profile, destination) || (profile.network().source().is_some() && inspection::dns_udp(&payload)) {
                        let Ok(slot) = Arc::clone(&dns_slots).try_acquire_owned() else { meter.dropped(); continue; };
                        let broker = Arc::clone(&broker);
                        let sender = Arc::clone(&udp_send);
                        let flow = meter.flow(false);
                        let dns_meter = Arc::clone(&meter);
                        let profile = Arc::clone(&profile);
                        flows.spawn(async move {
                            let _slot = slot;
                            let result = resolver::answer_query(&profile, &broker, endpoint, &payload, false).await;
                            match result {
                                Ok(response) => {
                                    if sender.send_to(&response, &destination, &source).is_err() { dns_meter.dropped(); }
                                }
                                _ => flow.failed(),
                            }
                        });
                        continue;
                    }
                    if profile.network().source().is_some() && inspection::bittorrent_udp(&payload) { meter.dropped(); continue; }
                    udp_flows.retain(|_, sender| !sender.is_closed());
                    let key = (source, destination);
                    if !udp_flows.contains_key(&key) {
                        if udp_flows.len() >= 64 { meter.dropped(); continue; }
                        let (tx, rx) = mpsc::channel::<Vec<u8>>(16);
                        udp_flows.insert(key, tx);
                        let context = UdpFlow {
                            profile: Arc::clone(&profile), host: Arc::clone(&broker), endpoint,
                            lan: Arc::clone(&lan), sender: Arc::clone(&udp_send), observer: Arc::clone(&meter),
                        };
                        let flow = meter.flow(false);
                        flows.spawn(async move {
                            if relay_udp(context, destination, source, rx).await.is_err() { flow.failed(); }
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
        drop(udp_flows);
        outcome
    }.await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    drop(tcp);
    drop(udp_receive);
    drop(udp_send);
    let _ = timeout(Duration::from_secs(2), done.wait_for(|complete| *complete)).await;
    outcome
}

struct UdpFlow<H, L, M> {
    profile: Arc<nm_tunnel_profile::Profile>,
    host: Arc<H>,
    endpoint: SocketAddr,
    lan: Arc<L>,
    sender: Arc<lwip::UdpSendHalf>,
    observer: Arc<M>,
}

async fn relay_udp<H: Host, L: LanScope, M: Observer>(
    context: UdpFlow<H, L, M>,
    destination: SocketAddr,
    source: SocketAddr,
    mut rx: mpsc::Receiver<Vec<u8>>,
) -> io::Result<()> {
    let UdpFlow {
        profile,
        host,
        endpoint,
        lan,
        sender,
        observer: meter,
    } = context;
    let first = udp_deadline(rx.recv())
        .await?
        .ok_or_else(|| io::Error::other("Datagram input closed."))?;
    let mut pending = vec![first];
    let mut hostname = None;
    if profile.network().source().is_some() && nm_tunnel_engine::QuicHostname::initial(&pending[0])
    {
        let mut inspection = nm_tunnel_engine::QuicHostname::default();
        hostname = inspection.inspect(&pending[0]);
        let deadline = tokio::time::Instant::now() + Duration::from_millis(300);
        while hostname.is_none() && pending.len() < 4 {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(bytes)) => {
                    hostname = inspection.inspect(&bytes);
                    pending.push(bytes);
                }
                _ => break,
            }
        }
    }
    let remote = udp_deadline(datagram::Route::connect_named(
        &profile,
        &host,
        endpoint,
        destination,
        &lan,
        hostname.as_deref(),
    ))
    .await??;
    for bytes in pending {
        udp_deadline(remote.send(&bytes)).await??;
    }
    let mut reading = Box::pin(remote.receive());
    loop {
        enum Activity {
            Send(Option<Vec<u8>>),
            Receive(io::Result<Vec<u8>>),
        }
        let activity = udp_deadline(async {
            tokio::select! {
                data = rx.recv() => Activity::Send(data),
                data = &mut reading => Activity::Receive(data),
            }
        })
        .await?;
        match activity {
            Activity::Send(Some(data)) => udp_deadline(remote.send(&data)).await??,
            Activity::Send(None) => return Ok(()),
            Activity::Receive(data) => {
                let data = data?;
                match sender.send_to(&data, &destination, &source) {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => meter.dropped(),
                    other => other?,
                }
                reading = Box::pin(remote.receive());
            }
        }
    }
}
