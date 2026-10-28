use super::*;
use nm_tunnel_profile::{Profile, TcpDomainPolicy};
use std::net::Ipv4Addr;

fn legacy() -> io::Result<Profile> {
    let mut draft = nm_tunnel_profile::import_vless("vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example").map_err(io::Error::other)?;
    draft.tcp_domain_policy = Some(TcpDomainPolicy::from_json(r#"{"version":1,"rules":[{"domain":["proxied.example"],"action":"proxy"},{"domain":["direct.example"],"action":"direct"},{"domain":["blocked.example"],"action":"block"}]}"#).map_err(io::Error::other)?);
    draft.lan_bypass = true;
    draft.dns_interception = true;
    draft
        .validate()
        .map_err(|_| io::Error::other("Invalid routing fixture."))
}

#[test]
fn legacy_lan_priority_and_named_outbounds_share_one_decision_without_widening_grants()
-> io::Result<()> {
    let profile = legacy()?;
    let lan = Plan::connected(&[(Ipv4Addr::new(192, 168, 1, 2), 24)])?.with_interception(true)?;
    let routes = lan.routes();
    for (name, address, expected) in [
        (None, "192.168.1.1:80", Decision::Lan),
        (Some("direct.example"), "192.168.1.1:80", Decision::Lan),
        (Some("proxied.example"), "192.168.1.1:80", Decision::Proxy),
        (Some("blocked.example"), "192.168.1.1:80", Decision::Block),
        (
            Some("direct.example"),
            "203.0.113.1:443",
            Decision::LegacyDirect("direct.example"),
        ),
        (Some("blocked.example"), "203.0.113.1:443", Decision::Block),
        (None, "203.0.113.1:443", Decision::Proxy),
    ] {
        assert_eq!(
            decide(
                profile.network(),
                &lan,
                address.parse().map_err(io::Error::other)?,
                name
            )?,
            expected
        );
    }
    for address in ["192.168.1.0:80", "192.168.1.255:80", "192.168.1.1:53"] {
        assert_eq!(
            decide(
                profile.network(),
                &lan,
                address.parse().map_err(io::Error::other)?,
                None
            )
            .err()
            .map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
    }
    assert_eq!(lan.routes(), routes);
    Ok(())
}

#[test]
fn complete_domain_actions_precede_private_ip_without_becoming_legacy_lan_authority()
-> io::Result<()> {
    let profile = crate::test_support::source_profile()?;
    let lan = Plan::private()?;
    for (name, address, expected) in [
        (None, "10.2.3.4:80", Decision::PolicyDirect(None)),
        (Some("proxied.example"), "10.2.3.4:80", Decision::Proxy),
        (Some("blocked.example"), "10.2.3.4:80", Decision::Block),
        (
            Some("direct.example"),
            "203.0.113.1:443",
            Decision::PolicyDirect(Some("direct.example")),
        ),
        (None, "203.0.113.1:443", Decision::Proxy),
    ] {
        assert_eq!(
            decide(
                profile.network(),
                &lan,
                address.parse().map_err(io::Error::other)?,
                name
            )?,
            expected
        );
    }
    assert!(
        !format!("{:?}", Decision::LegacyDirect("private-domain.example"))
            .contains("private-domain")
    );
    assert!(
        !format!(
            "{:?}",
            Decision::PolicyDirect(Some("private-domain.example"))
        )
        .contains("private-domain")
    );
    Ok(())
}
