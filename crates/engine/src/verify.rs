//! Certificate-verified destination TLS readiness over an already proxied stream.
use crate::{Error, Tunnel};
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

/// Complete a verified destination TLS handshake over an owned VPN tunnel, then
/// close it. Used when DNS itself deliberately goes outside the VPN: a successful
/// direct DNS lookup alone is not proof that the proxy carries application data.
/// No socket, DNS lookup, application HTTP request or implicit fallback is created.
/// Ownership transfers on entry; error, cancellation and the ten-second deadline
/// all close the stream. Certificate verification is mandatory. This proves only
/// this TCP/TLS exchange, not UDP, routing, guard installation or leak prevention.
pub async fn verify_tls_peer(stream: Tunnel, server_name: &str) -> Result<(), Error> {
    let name = nm_tunnel_profile::canonical_domain(server_name).ok_or(Error::Configuration)?;
    let mut config = TlsConfig::new(&name);
    config.skip_cert_verify = false;
    let layer = TlsLayer::new(&config).map_err(|_| Error::Configuration)?;
    let verified = tokio::time::timeout(Duration::from_secs(10), layer.connect(Box::new(stream)))
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
    async fn failed_or_cancelled_destination_verification_owns_and_closes_the_stream()
    -> Result<(), Box<dyn std::error::Error>> {
        for case in 0..3 {
            let invalid = case == 0;
            let (stream, mut peer) = tokio::io::duplex(16384);
            let tunnel = Tunnel(Box::new(meow_proxy::StreamConn(Box::new(stream))));
            let mut verification = Box::pin(verify_tls_peer(
                tunnel,
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
