//! Verified TLS wrappers and destination-free secure endpoint readiness.
use crate::{EndpointStream, Error, Tunnel};
use meow_transport::{
    Transport,
    tls::{TlsConfig, TlsLayer},
};
use std::time::Duration;

/// Add certificate-verified TLS to one owned, host-approved transport (a proxy
/// tunnel or fixed-peer direct relay). Used by the source DNS-over-TLS consumer.
/// No dialing, DNS lookup, fallback or verification override. The ten-second
/// deadline, failure and cancellation all release the supplied transport.
pub async fn wrap_verified_tls<S>(stream: S, server_name: &str) -> Result<Tunnel, Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
{
    let name = nm_tunnel_profile::canonical_domain(server_name)
        .or_else(|| {
            server_name
                .parse::<std::net::Ipv4Addr>()
                .ok()
                .map(|ip| ip.to_string())
        })
        .ok_or(Error::Configuration)?;
    let mut config = TlsConfig::new(&name);
    config.skip_cert_verify = false;
    let layer = TlsLayer::new(&config).map_err(|_| Error::Configuration)?;
    let verified = tokio::time::timeout(Duration::from_secs(10), layer.connect(Box::new(stream)))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| Error::Handshake)?;
    Ok(Tunnel(Box::new(meow_proxy::StreamConn(verified))))
}

/// Verify only the configured endpoint's TLS/REALITY and optional WebSocket
/// upgrade on a host-owned connected transport, then close it. Uses exactly the
/// application transport configuration and approved-peer checks. No VLESS request,
/// destination, resolver query, HTTP health URL or additional dial is created.
///
/// Success authenticates the secure peer, NOT the VLESS UUID, destination
/// reachability, UDP forwarding or Internet access. VLESS/Vision can defer
/// credential acceptance until real application I/O; failures remain flow-local.
/// Ownership transfers on entry; rejection, timeout and cancellation close the
/// supplied transport without retries or fallback.
///
/// # Errors
/// Returns [`Error::Endpoint`] on peer mismatch before I/O, [`Error::Configuration`]
/// for an unsupported transport, [`Error::Handshake`] for secure transport failure,
/// or [`Error::Timeout`] after one ten-second handshake deadline.
pub async fn verify_peer_transport(
    profile: &nm_tunnel_profile::Profile,
    socket: impl TryInto<EndpointStream>,
    endpoint: std::net::SocketAddr,
) -> Result<(), Error> {
    let socket = crate::checked_endpoint(profile, socket, endpoint)?;
    let chain = crate::adapter::transport(profile)?;
    let verified = tokio::time::timeout(Duration::from_secs(10), chain.connect(socket.inner))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| Error::Handshake)?;
    drop(verified);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test(start_paused = true)]
    async fn failed_or_cancelled_tls_wrapping_owns_and_closes_the_stream()
    -> Result<(), Box<dyn std::error::Error>> {
        for case in 0..3 {
            let invalid = case == 0;
            let (stream, mut peer) = tokio::io::duplex(16384);
            let mut verification = Box::pin(wrap_verified_tls(
                stream,
                if invalid {
                    "https://private-token.example"
                } else {
                    "peer.example"
                },
            ));
            if invalid {
                assert!(matches!(verification.await, Err(Error::Configuration)));
            } else {
                let pending = std::future::poll_fn(|cx| {
                    std::task::Poll::Ready(
                        std::future::Future::poll(verification.as_mut(), cx).is_pending(),
                    )
                })
                .await;
                assert!(pending);
                if case == 1 {
                    tokio::time::advance(Duration::from_secs(10)).await;
                    assert!(matches!(verification.await, Err(Error::Timeout)));
                } else {
                    drop(verification);
                }
            }
            let mut bytes = Vec::new();
            tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut bytes)).await??;
            if invalid {
                assert!(bytes.is_empty());
            }
        }
        Ok(())
    }
}
