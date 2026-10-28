use super::*;

#[test]
fn only_broad_private_grants_can_follow_unbound_physical_routes() -> io::Result<()> {
    let destination = "192.168.1.1:80".parse().map_err(io::Error::other)?;
    let connected =
        Plan::connected(&[(Ipv4Addr::new(192, 168, 1, 2), 24)])?.with_interception(true)?;
    let routes = connected.routes();
    let grant = lan(&connected, destination, "enp1s0")?;
    assert_eq!(grant.destination, destination);
    assert_eq!(grant.binding, Some("enp1s0"));
    assert_eq!(connected.routes(), routes);
    let broad = Plan::private()?;
    let grant = lan(&broad, destination, "enp1s0")?;
    assert_eq!(grant.destination, destination);
    assert!(grant.binding.is_none());
    Ok(())
}

#[test]
fn broad_private_root_grants_reject_public_dns_ipv6_and_fakeip_before_socket_setup()
-> io::Result<()> {
    let plan = crate::lan::Plan::private()?;
    for text in [
        "1.1.1.1:80",
        "10.2.2.1:53",
        "192.168.68.1:0",
        "198.18.0.2:80",
        "198.19.1.1:80",
        "100.64.0.1:80",
        "[fd00::1]:80",
    ] {
        assert_eq!(
            lan(
                &plan,
                text.parse().map_err(io::Error::other)?,
                "invalid-interface"
            )
            .err()
            .map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
    }
    Ok(())
}

#[test]
fn lan_grant_rejects_public_dns_and_unicast_boundary_targets_before_socket_creation()
-> io::Result<()> {
    let plan = crate::lan::Plan::connected(&[(Ipv4Addr::new(192, 168, 1, 2), 24)])?
        .with_interception(true)?;
    let before = plan.routes();
    for text in [
        "1.1.1.1:443",
        "192.168.1.1:53",
        "192.168.1.0:80",
        "192.168.1.255:80",
        "198.18.0.2:80",
        "192.168.2.1:80",
        "[fd00::1]:80",
    ] {
        assert_eq!(
            lan(
                &plan,
                text.parse().map_err(io::Error::other)?,
                "never-open-this"
            )
            .err()
            .map(|e| (e.kind(), e.to_string())),
            Some((
                io::ErrorKind::PermissionDenied,
                "LAN destination refused.".into()
            ))
        );
        assert_eq!(plan.routes(), before);
    }
    assert_eq!(
        lan(
            &crate::lan::Plan::default(),
            "192.168.1.1:80".parse().map_err(io::Error::other)?,
            "never-open-this"
        )
        .err()
        .map(|e| (e.kind(), e.to_string())),
        Some((
            io::ErrorKind::PermissionDenied,
            "LAN destination refused.".into()
        ))
    );
    Ok(())
}
use nm_tunnel_profile::TcpDomainPolicy;

fn policy() -> Result<TcpDomainPolicy, Box<dyn std::error::Error>> {
    Ok(TcpDomainPolicy::from_json(
        r#"{"version":1,"rules":[{"domain_suffix":["direct.example"],"action":"direct"}]}"#,
    )?)
}

#[tokio::test]
async fn unauthorized_direct_targets_are_rejected_before_privileged_socket_or_dns_work()
-> Result<(), Box<dyn std::error::Error>> {
    let policy = policy()?;
    for (domain, address) in [
        ("other.example", "1.1.1.1:443"),
        ("direct.example.evil", "1.1.1.1:443"),
        ("direct.example", "127.0.0.1:443"),
        ("direct.example", "192.168.1.1:443"),
        ("direct.example", "10.0.0.1:443"),
        ("direct.example", "169.254.169.254:80"),
        ("direct.example", "198.18.0.1:443"),
        ("direct.example", "198.19.0.4:443"),
        ("direct.example", "100.64.0.1:443"),
        ("direct.example", "224.0.0.1:443"),
        ("direct.example", "0.1.2.3:443"),
        ("direct.example", "1.1.1.1:0"),
        ("direct.example", "[::1]:443"),
        ("DIRECT.EXAMPLE", "1.1.1.1:443"),
    ] {
        let destination = address.parse()?;
        assert!(!direct_authorized(&policy, domain, destination));
        let error = direct_tcp(
            &policy,
            domain,
            destination,
            "invalid-interface-never-opened",
            Ipv4Addr::LOCALHOST,
        )
        .await
        .err();
        assert_eq!(
            error.map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        assert_eq!(
            direct_udp(
                true,
                &policy,
                domain,
                destination,
                "never-open-this",
                Ipv4Addr::LOCALHOST
            )
            .await
            .err()
            .map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
    }
    let destination = "1.1.1.1:443".parse()?;
    assert!(direct_authorized(&policy, "a.direct.example", destination));
    assert_eq!(
        direct_udp(
            false,
            &policy,
            "a.direct.example",
            destination,
            "never-open-this",
            Ipv4Addr::LOCALHOST
        )
        .await
        .err()
        .map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    Ok(())
}
