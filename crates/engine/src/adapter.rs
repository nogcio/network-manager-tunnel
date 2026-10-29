//! Library configuration and a no-I/O dialer: connect_over must use the supplied socket.
use crate::Error;
use meow_proxy::{TransportChain, VlessAdapter, VlessFlow};
use meow_transport::tls::{RealityConfig, TlsConfig, TlsLayer};
use meow_transport::ws::{WsConfig, WsLayer};
use nm_tunnel_profile::{PeerSecurity, Profile, Transport};
use std::sync::Arc;

struct NoDialer;
#[async_trait::async_trait]
impl meow_proxy::dialer::TcpDialer for NoDialer {
    async fn dial(
        &self,
        _: &str,
        _: u16,
        _: bool,
    ) -> std::io::Result<Box<dyn meow_transport::Stream>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Implicit socket creation is forbidden.",
        ))
    }
}

fn tls_config(profile: &Profile) -> Result<TlsConfig, Error> {
    let node = profile.node();
    let mut tls = TlsConfig::new(node.server_name());
    if node.fingerprint() != "native"
        && !meow_transport::tls::is_supported_fingerprint(node.fingerprint())
    {
        return Err(Error::Configuration);
    }
    // The fork's REALITY encoder maps Android to Chrome. Do not silently
    // replace a requested wire profile just because ordinary TLS supports it.
    if matches!(node.security(), PeerSecurity::Reality(_)) && node.fingerprint() == "android" {
        return Err(Error::Configuration);
    }
    tls.fingerprint = (node.fingerprint() != "native").then(|| node.fingerprint().to_owned());
    tls.alpn = node.alpn().to_vec();
    if let PeerSecurity::Reality(reality) = node.security() {
        let mut short_id = [0; 8];
        short_id[..reality.short_id().len()].copy_from_slice(reality.short_id());
        tls.reality = Some(RealityConfig {
            public_key: *reality.public_key(),
            short_id,
            support_x25519_mlkem768: true,
        });
    }
    Ok(tls)
}

fn ws_config(profile: &Profile) -> Result<Option<WsConfig>, Error> {
    let node = profile.node();
    let Transport::WebSocket { path, host } = node.transport() else {
        return Ok(None);
    };
    let port = node.endpoint().port();
    let authority = host.clone().unwrap_or_else(|| {
        let server = if node.endpoint().host().contains(':') {
            format!("[{}]", node.endpoint().host())
        } else {
            node.endpoint().host().to_owned()
        };
        if port == 443 {
            server
        } else {
            format!("{server}:{port}")
        }
    });
    Ok(Some(WsConfig {
        path: path.clone(),
        host_header: Some(authority),
        ..Default::default()
    }))
}

pub(super) fn build(profile: &Profile) -> Result<VlessAdapter, Error> {
    build_with_dialer(profile, Arc::new(NoDialer))
}

pub(super) fn build_with_dialer(
    profile: &Profile,
    dialer: Arc<dyn meow_proxy::dialer::TcpDialer>,
) -> Result<VlessAdapter, Error> {
    let node = profile.node();
    let chain = transport(profile)?;
    Ok(VlessAdapter::new(
        "flow",
        node.endpoint().host(),
        node.endpoint().port(),
        *profile.credential().expose_uuid(),
        node.vision().then_some(VlessFlow::XtlsRprxVision),
        true,
        chain,
        dialer,
    ))
}

/// Same checked secure transport for application flows and endpoint readiness.
/// This does not send a VLESS destination or claim credential acceptance.
pub(super) fn transport(profile: &Profile) -> Result<TransportChain, Error> {
    let mut chain = TransportChain::empty();
    chain.push(Box::new(
        TlsLayer::new(&tls_config(profile)?).map_err(|_| Error::Configuration)?,
    ));
    if let Some(ws) = ws_config(profile)? {
        chain.push(Box::new(
            WsLayer::new(ws).map_err(|_| Error::Configuration)?,
        ));
    }
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(query: &str) -> Result<Profile, Box<dyn std::error::Error>> {
        let draft = nm_tunnel_profile::import_vless(&format!(
            "vless://12345678-1234-4234-8234-123456789abc@edge.example:8443?{query}#Synthetic"
        ))?;
        draft.validate().map_err(|_| "invalid fixture".into())
    }

    #[test]
    fn websocket_http_fields_do_not_replace_tls_identity() -> Result<(), Box<dyn std::error::Error>>
    {
        let profile = profile(
            "type=ws&security=tls&sni=certificate.example&host=cdn.example&path=%2Fsocket%3Fmode%3Dtest&fp=firefox&alpn=http%2F1.1",
        )?;
        let tls = tls_config(&profile).map_err(|_| "TLS config")?;
        let ws = ws_config(&profile)
            .map_err(|_| "WS config")?
            .ok_or("missing WS")?;
        assert_eq!(tls.sni.as_deref(), Some("certificate.example"));
        assert_eq!(tls.fingerprint.as_deref(), Some("firefox"));
        assert_eq!(tls.alpn, ["http/1.1"]);
        assert!(!tls.skip_cert_verify);
        assert!(tls.reality.is_none());
        assert_eq!(ws.host_header.as_deref(), Some("cdn.example"));
        assert_eq!(ws.path, "/socket?mode=test");
        assert_eq!(ws.max_early_data, 0);
        let default_host = profile_with_default_host()?;
        let ws = ws_config(&default_host)
            .map_err(|_| "WS config")?
            .ok_or("missing WS")?;
        assert_eq!(ws.host_header.as_deref(), Some("edge.example:8443"));
        Ok(())
    }

    fn profile_with_default_host() -> Result<Profile, Box<dyn std::error::Error>> {
        profile("type=ws&security=tls&sni=certificate.example")
    }

    #[test]
    fn reality_enables_the_reviewed_hybrid_option_and_pads_short_id()
    -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile(
            "security=reality&sni=cover.example&pbk=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE&sid=aabb&alpn=h2",
        )?;
        let tls = tls_config(&profile).map_err(|_| "TLS config")?;
        let reality = tls.reality.ok_or("missing REALITY")?;
        assert!(reality.support_x25519_mlkem768);
        assert_eq!(reality.public_key, [1; 32]);
        assert_eq!(reality.short_id, [0xaa, 0xbb, 0, 0, 0, 0, 0, 0]);
        assert_eq!(tls.alpn, ["h2"]);
        let mut android = profile.to_draft();
        android.fingerprint = "android".into();
        let android = android.validate().map_err(|_| "invalid fixture")?;
        assert!(matches!(tls_config(&android), Err(Error::Configuration)));
        Ok(())
    }

    #[tokio::test]
    async fn implicit_redial_is_denied_without_a_resolver_or_socket() {
        use meow_proxy::dialer::TcpDialer;
        let result = NoDialer.dial("untrusted.example", 443, false).await;
        assert!(
            matches!(result, Err(ref error) if error.kind() == std::io::ErrorKind::PermissionDenied)
        );
    }
}
