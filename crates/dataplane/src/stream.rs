//! One TCP relay executor; inspection scheduling preserves each checked policy's order.
use super::{
    destination, inspection, resolver,
    routing::{self, Decision},
};
use crate::{Host, LanScope, PayloadStream};
use nm_tunnel_profile::{Profile, RoutingPolicy};
use std::{future::Future, io, net::SocketAddr, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// Own both streams through completion, error and cancellation. Setup includes broker
/// queueing and prefix replay, not the established stream's bidirectional lifetime.
pub async fn forward_tcp<I, R, F>(mut inbound: I, setup: F) -> io::Result<()>
where
    I: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
    F: Future<Output = io::Result<R>>,
{
    let mut remote = tokio::time::timeout(Duration::from_secs(60), setup)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP setup deadline."))??;
    tokio::io::copy_bidirectional(&mut inbound, &mut remote).await?;
    Ok(())
}

/// Each decision has exactly one broker path. A refusal is final for this flow.
async fn open_remote(
    profile: &Profile,
    broker: &(impl Host + ?Sized),
    endpoint: SocketAddr,
    destination: SocketAddr,
    decision: Decision<'_>,
) -> io::Result<Box<dyn PayloadStream>> {
    match decision {
        Decision::Proxy => {
            let socket = broker.open_endpoint(endpoint).await?;
            Ok(Box::new(
                nm_tunnel_engine::connect_tcp(profile, socket, endpoint, destination)
                    .await
                    .map_err(|_| io::Error::other("TCP proxy failed."))?,
            ))
        }
        Decision::Lan | Decision::LegacyDirect(_) | Decision::PolicyDirect(_) => {
            broker.open_tcp(destination, decision).await
        }
        Decision::Block => Err(io::Error::other("Blocked TCP flow.")),
    }
}

/// Dispatch one owned TCP flow in checked DNS/classification/FakeIP/routing order.
/// Refusals never select another outbound. Setup/replay uses a sixty-second budget;
/// established bidirectional streams have no added lifetime deadline. Dropping the
/// future closes owned streams and preserves host cancellation semantics.
pub async fn route_tcp<I: AsyncRead + AsyncWrite + Unpin>(
    mut inbound: I,
    profile: &Profile,
    broker: &(impl Host + ?Sized),
    endpoint: SocketAddr,
    destination: SocketAddr,
    lan: &(impl LanScope + ?Sized),
) -> io::Result<()> {
    if resolver::handles(profile, destination) {
        return resolver::serve_tcp(inbound, broker, profile, endpoint).await;
    }
    let complete = matches!(profile.routing(), RoutingPolicy::Complete(_));
    // Complete classification must precede FakeIP reverse/DNS and every grant.
    // Legacy LAN bypass intentionally occurs before optional hostname inspection.
    let mut observed = if complete {
        Some(nm_tunnel_engine::inspect_tcp_hostname(&mut inbound).await?)
    } else {
        None
    };
    if let Some(observed) = &observed {
        if inspection::dns_tcp(observed.prefix()) {
            return resolver::serve_tcp(
                inspection::Replay::new(observed.prefix().to_vec(), inbound),
                broker,
                profile,
                endpoint,
            )
            .await;
        }
        if inspection::bittorrent_tcp(observed.prefix()) {
            return Ok(());
        }
    }
    let resolved = destination::resolve(profile, broker, endpoint, destination, lan).await?;
    if !complete {
        let early = routing::decide(
            profile.network(),
            lan,
            resolved.address,
            resolved.domain.as_deref(),
        )?;
        if early != Decision::Lan
            && profile.network().tcp_domains().is_some()
            && resolved.domain.is_none()
        {
            observed = Some(nm_tunnel_engine::inspect_tcp_hostname(&mut inbound).await?);
        }
    }
    let name = resolved
        .domain
        .as_deref()
        .or_else(|| observed.as_ref().and_then(|value| value.hostname()));
    let decision = routing::decide(profile.network(), lan, resolved.address, name)?;
    if decision == Decision::Block {
        return Ok(());
    }
    forward_tcp(inbound, async {
        let mut remote = open_remote(profile, broker, endpoint, resolved.address, decision).await?;
        if let Some(observed) = &observed {
            remote.write_all(observed.prefix()).await?;
        }
        Ok(remote)
    })
    .await
}
