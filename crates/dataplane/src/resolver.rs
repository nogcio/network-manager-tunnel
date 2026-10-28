//! Bounded profile-selected DNS relay; fixed uplink RPC or supplied VLESS sockets.
use crate::dns::{framed, invalid, parse_query, validate_response};
use crate::{Host, dns};
use futures_util::{SinkExt, StreamExt};
use std::{io, net::SocketAddr, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};

/// Explicit interception precedes hostname routing, but only for packets reaching
/// our IPv4 netstack. Legacy profiles retain their previous dispatch unchanged.
pub fn handles(profile: &nm_tunnel_profile::Profile, destination: SocketAddr) -> bool {
    destination.is_ipv4()
        && destination.port() == 53
        && (profile.network().intercepts_dns()
            || (profile.network().dns_override() == nm_tunnel_profile::DnsOverride::CurrentNetwork
                && destination.ip() == dns::INTERNAL_DNS))
}

/// Serve framed queries sequentially. Idle/write deadlines close the owned stream;
/// cancellation drops it and retains the host's exchange-cancellation semantics.
pub async fn serve_tcp<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    broker: &(impl Host + ?Sized),
    profile: &nm_tunnel_profile::Profile,
    endpoint: SocketAddr,
) -> io::Result<()> {
    let mut stream = framed(stream);
    loop {
        let message = tokio::time::timeout(Duration::from_secs(60), stream.next())
            .await
            .map_err(|_| io::Error::other("DNS client idle deadline."))?;
        let Some(message) = message else {
            return Ok(());
        };
        let response = answer_query(profile, broker, endpoint, &message?, true).await?;
        tokio::time::timeout(Duration::from_secs(5), stream.send(response.as_slice()))
            .await
            .map_err(|_| io::Error::other("DNS response write deadline."))??;
    }
}

/// Answer a checked query with FakeIP or selected real DNS, never falling back.
/// Invalid messages error before host I/O; the total FakeIP deadline is ten seconds.
pub async fn answer_query(
    profile: &nm_tunnel_profile::Profile,
    broker: &(impl Host + ?Sized),
    endpoint: SocketAddr,
    request: &[u8],
    tcp: bool,
) -> io::Result<Vec<u8>> {
    let query = parse_query(request)?;
    if profile.network().fake_ip()
        && matches!(
            query.queries[0].query_type(),
            hickory_proto::rr::RecordType::A | hickory_proto::rr::RecordType::AAAA
        )
    {
        return tokio::time::timeout(Duration::from_secs(10), broker.fake_dns(request))
            .await
            .map_err(|_| io::Error::other("FakeIP DNS deadline."))?;
    }
    relay_query(profile, broker, endpoint, request, tcp).await
}

/// One bounded DNS exchange with the profile-selected upstream. The client never
/// supplies the upstream destination here. Local parsing precedes all broker I/O;
/// cancellation owns/closes tunnel streams and retains broker poison semantics.
/// Negative/truncated answers are relayed unchanged; no transport/resolver retry.
pub async fn relay_query(
    profile: &nm_tunnel_profile::Profile,
    broker: &(impl Host + ?Sized),
    endpoint: SocketAddr,
    request: &[u8],
    tcp: bool,
) -> io::Result<Vec<u8>> {
    let query = parse_query(request)?;
    tokio::time::timeout(Duration::from_secs(10), async {
        if profile.network().dns_override() == nm_tunnel_profile::DnsOverride::CurrentNetwork
            || profile.network().source().is_some()
        {
            return broker.query_dns(request, tcp).await;
        }
        let upstream = SocketAddr::from((dns::profile_dns(profile.network().dns_override()), 53));
        let socket = broker.open_endpoint(endpoint).await?;
        let response = if tcp {
            let tunnel = nm_tunnel_engine::connect_tcp(profile, socket, endpoint, upstream)
                .await
                .map_err(|_| io::Error::other("DNS proxy TCP setup failed."))?;
            let mut stream = framed(tunnel);
            stream.send(request).await.map_err(|_| invalid())?;
            stream
                .next()
                .await
                .ok_or_else(invalid)?
                .map_err(|_| invalid())?
                .to_vec()
        } else {
            let tunnel = nm_tunnel_engine::connect_udp(profile, socket, endpoint, upstream)
                .await
                .map_err(|_| io::Error::other("DNS proxy UDP setup failed."))?;
            tunnel.send(request).await.map_err(|_| invalid())?;
            tunnel.receive().await.map_err(|_| invalid())?
        };
        validate_response(&query, &response)?;
        Ok(response)
    })
    .await
    .map_err(|_| io::Error::other("DNS relay deadline."))?
}
