//! Root-owned request authority. Worker messages request, but never grant, privileges.
use crate::{
    network::{
        authority,
        sockets::{self, Outbound},
    },
    telemetry::Telemetry,
    wire,
};
use nm_tunnel_profile::Profile;
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::oneshot,
    time::timeout,
};

/// All authority comes from the supervisor's checked activation snapshot.
pub(super) struct Authority {
    pub profile: Profile,
    pub endpoint: SocketAddr,
    pub interface: String,
    pub dns: Ipv4Addr,
    pub lan: crate::lan::Plan,
    pub fake_state: Option<crate::fakeip::Shared>,
    pub telemetry: Telemetry,
}

/// A fixed-window grant limit with bounded backpressure, never a session failure.
struct SocketBudget {
    window: tokio::time::Instant,
    used: u32,
}
impl SocketBudget {
    fn new() -> Self {
        Self {
            window: tokio::time::Instant::now(),
            used: 0,
        }
    }
    async fn acquire(&mut self) {
        let end = self.window + Duration::from_secs(1);
        if self.used == 64 && tokio::time::Instant::now() < end {
            tokio::time::sleep_until(end).await;
        }
        if tokio::time::Instant::now() >= end {
            self.window = tokio::time::Instant::now();
            self.used = 0;
        }
        self.used += 1;
    }
}

/// A refused endpoint dial affects only its request. Ambiguous reply/FD writes are fatal.
async fn grant_endpoint(
    stream: &mut UnixStream,
    socket: io::Result<tokio::net::TcpStream>,
    relays: &mut tokio::task::JoinSet<io::Result<()>>,
) -> io::Result<()> {
    match socket {
        Ok(socket) => crate::stream_relay::grant(stream, socket, relays).await,
        Err(error) => {
            eprintln!(
                "VPN endpoint dial refused (kind {:?}, OS error {:?}); session retained.",
                error.kind(),
                error.raw_os_error()
            );
            stream.write_all(b"N").await
        }
    }
}

impl Authority {
    /// The serialized wire protocol deliberately keeps cancellation-poison semantics.
    /// Dropping this future closes the channel/resolver, but the external resource
    /// owner must join this task and shut down both borrowed relay sets.
    pub async fn serve(
        self,
        mut stream: UnixStream,
        ready_tx: oneshot::Sender<()>,
        relays: std::sync::Arc<tokio::sync::Mutex<super::resources::Relays>>,
    ) -> io::Result<()> {
        let Self {
            profile,
            endpoint,
            interface,
            dns,
            lan: broker_lan,
            fake_state,
            telemetry,
        } = self;
        let dns_override = profile.network().dns_override();
        let fake_ip = profile.network().fake_ip();
        let tcp_policy = profile.network().tcp_domains().cloned();
        let source_policy = profile.network().source().cloned();
        let mut source_resolver = source_policy
            .as_ref()
            .map(|_| crate::source_dns::Resolver::new(profile, endpoint, interface.clone(), dns));
        let mut relays = relays.lock().await;
        let super::resources::Relays {
            tcp: lan_tcp_relays,
            udp: lan_relays,
        } = &mut *relays;
        let mut ready_tx = Some(ready_tx);
        let mut budget = SocketBudget::new();
        loop {
            let code = stream.read_u8().await?;
            match code {
                b'O' => {
                    budget.acquire().await;
                    if !crate::stream_relay::available(lan_tcp_relays) {
                        stream.write_all(b"N").await?;
                        continue;
                    }
                    let socket = sockets::tcp(endpoint, &interface).await;
                    grant_endpoint(&mut stream, socket, lan_tcp_relays).await?;
                }
                b'D' | b'U' => {
                    let request: wire::DirectRequest =
                        wire::receive_json(&mut stream, wire::MAX_DIRECT_REQUEST).await?;
                    budget.acquire().await;
                    while lan_relays.try_join_next().is_some() {}
                    if (code == b'D' && !crate::stream_relay::available(lan_tcp_relays))
                        || (code == b'U'
                            && (!fake_ip || lan_relays.len() >= crate::lan_relay::LIMIT))
                    {
                        stream.write_all(b"N").await?;
                        continue;
                    }
                    let result = if let Some(policy) = &tcp_policy {
                        if code == b'D' {
                            authority::direct_tcp(
                                policy,
                                &request.domain,
                                request.destination,
                                &interface,
                                dns,
                            )
                            .await
                            .map(Outbound::Tcp)
                        } else {
                            authority::direct_udp(
                                fake_ip,
                                policy,
                                &request.domain,
                                request.destination,
                                &interface,
                                dns,
                            )
                            .await
                            .map(Outbound::Udp)
                        }
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "No direct policy.",
                        ))
                    };
                    grant_result(&mut stream, result, lan_tcp_relays, lan_relays).await?;
                }
                b'L' => {
                    let request = wire::receive_lan_request(&mut stream).await?;
                    budget.acquire().await;
                    if source_policy.is_some() {
                        stream.write_all(b"N").await?;
                        continue;
                    }
                    while lan_relays.try_join_next().is_some() {}
                    while lan_tcp_relays.try_join_next().is_some() {}
                    if !available(request.transport, lan_tcp_relays, lan_relays) {
                        stream.write_all(b"N").await?;
                        continue;
                    }
                    let result = match authority::lan(&broker_lan, request.destination, &interface)
                    {
                        Ok(grant) => match request.transport {
                            wire::LanTransport::Tcp => grant.tcp().await.map(Outbound::Tcp),
                            wire::LanTransport::Udp => grant.udp().await.map(Outbound::Udp),
                        },
                        Err(error) => Err(error),
                    };
                    grant_result(&mut stream, result, lan_tcp_relays, lan_relays).await?;
                }
                b'P' => {
                    let request: wire::PolicyRequest =
                        wire::receive_json(&mut stream, wire::MAX_DIRECT_REQUEST).await?;
                    budget.acquire().await;
                    while lan_relays.try_join_next().is_some() {}
                    if !available(request.transport, lan_tcp_relays, lan_relays) {
                        stream.write_all(b"N").await?;
                        continue;
                    }
                    let result = if let Some(resolver) = &mut source_resolver {
                        resolver.direct(&request).await
                    } else {
                        Err(io::Error::other("No source Direct authority."))
                    };
                    grant_result(&mut stream, result, lan_tcp_relays, lan_relays).await?;
                }
                b'Q' => {
                    let (tcp, request) = timeout(Duration::from_secs(5), async {
                        let transport = stream.read_u8().await?;
                        let size = stream.read_u16().await? as usize;
                        if transport > 1 || size == 0 || size > crate::dns::MAX_DNS_BYTES {
                            return Err(io::Error::other("Invalid DNS request frame."));
                        }
                        let mut bytes = vec![0; size];
                        stream.read_exact(&mut bytes).await?;
                        Ok((transport == 1, bytes))
                    })
                    .await
                    .map_err(|_| io::Error::other("DNS request frame deadline."))??;
                    budget.acquire().await;
                    let response = if let Some(resolver) = &mut source_resolver {
                        resolver.query(&request, tcp).await
                    } else {
                        super::uplink_dns::exchange(dns_override, &request, tcp, dns, &interface)
                            .await
                    };
                    reply_payload(&mut stream, response).await?;
                }
                b'F' => {
                    let (kind, bytes) = timeout(Duration::from_secs(5), async {
                        let kind = stream.read_u8().await?;
                        let size = stream.read_u16().await? as usize;
                        if !matches!(kind, b'D' | b'R')
                            || size == 0
                            || size > crate::dns::MAX_DNS_BYTES
                            || (kind == b'R' && size != 4)
                        {
                            return Err(io::Error::other("Invalid FakeIP request frame."));
                        }
                        let mut bytes = vec![0; size];
                        stream.read_exact(&mut bytes).await?;
                        Ok((kind, bytes))
                    })
                    .await
                    .map_err(|_| io::Error::other("FakeIP request deadline."))??;
                    budget.acquire().await;
                    let response = if let Some(state) = &fake_state {
                        if kind == b'D' {
                            crate::fakeip::dns(std::sync::Arc::clone(state), bytes).await
                        } else {
                            crate::fakeip::reverse(
                                std::sync::Arc::clone(state),
                                Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]),
                            )
                            .await
                        }
                    } else {
                        Err(io::Error::other("No FakeIP authority."))
                    };
                    reply_payload(&mut stream, response).await?;
                }
                b'R' => {
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(());
                    } else {
                        return Err(io::Error::other("Duplicate worker readiness."));
                    }
                }
                b'E' => {
                    let (stage, reason) = wire::receive_worker_failure(&mut stream).await?;
                    telemetry.worker_stage(stage);
                    eprintln!(
                        "Unprivileged worker failed at runtime stage {stage} (reason {reason:?})."
                    );
                    return Err(io::Error::other("Worker reported failure."));
                }
                _ => {
                    return Err(io::Error::other(
                        "Worker failed or sent invalid control data.",
                    ));
                }
            }
        }
    }
}

type Relays = tokio::task::JoinSet<io::Result<()>>;

fn available(transport: wire::LanTransport, tcp: &mut Relays, udp: &Relays) -> bool {
    match transport {
        wire::LanTransport::Tcp => crate::stream_relay::available(tcp),
        wire::LanTransport::Udp => udp.len() < crate::lan_relay::LIMIT,
    }
}

async fn grant_result(
    stream: &mut UnixStream,
    result: io::Result<Outbound>,
    tcp: &mut Relays,
    udp: &mut Relays,
) -> io::Result<()> {
    match result {
        Ok(Outbound::Tcp(socket)) => crate::stream_relay::grant(stream, socket, tcp).await,
        Ok(Outbound::Udp(socket)) => crate::lan_relay::grant(stream, socket, udp).await,
        Err(_) => stream.write_all(b"N").await,
    }
}

async fn reply_payload(stream: &mut UnixStream, response: io::Result<Vec<u8>>) -> io::Result<()> {
    match response {
        Ok(response) => timeout(Duration::from_secs(5), async {
            stream.write_all(b"A").await?;
            stream.write_u16(response.len() as u16).await?;
            stream.write_all(&response).await
        })
        .await
        .map_err(|_| io::Error::other("Broker response write deadline."))?,
        Err(_) => stream.write_all(b"N").await,
    }
}

#[cfg(test)]
#[path = "broker_tests.rs"]
mod tests;
