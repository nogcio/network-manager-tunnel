use nm_tunnel_profile::{DnsOverride, Field, import_vless};

#[test]
fn fakeip_cannot_be_saved_without_interception_or_erase_a_domain_rule()
-> Result<(), Box<dyn std::error::Error>> {
    let mut draft = import_vless(
        "vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example",
    )?;
    assert!(!draft.fake_ip);
    draft.fake_ip = true;
    assert!(
        draft
            .validate()
            .err()
            .is_some_and(|errors| errors.iter().any(|error| error.field == Field::Dns))
    );
    draft.dns_interception = true;
    draft.tcp_domain_policy = Some(nm_tunnel_profile::TcpDomainPolicy::from_json(
        r#"{"version":1,"rules":[{"domain":["owned.example"],"action":"proxy"}]}"#,
    )?);
    let profile = draft.validate().map_err(|_| "invalid FakeIP fixture")?;
    let policy = profile.network().tcp_domains().ok_or("missing policy")?;
    assert_eq!(
        policy.matched_action(Some("owned.example")),
        Some(nm_tunnel_profile::DomainAction::Proxy)
    );
    assert_eq!(policy.matched_action(Some("unmatched.example")), None);
    assert!(profile.network().fake_ip());
    assert!(draft.fake_ip && draft.dns_interception);
    Ok(())
}

#[test]
fn interception_is_opt_in_and_lan_combination_preserves_both_choices()
-> Result<(), Box<dyn std::error::Error>> {
    let mut draft = import_vless(
        "vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example",
    )?;
    assert!(!draft.dns_interception);
    draft.dns_interception = true;
    assert!(draft.validate().is_ok());
    draft.lan_bypass = true;
    let combined = draft
        .validate()
        .map_err(|_| "valid combined policy rejected")?;
    assert!(
        combined.network().intercepts_dns()
            && combined.lan_bypass() == nm_tunnel_profile::LanBypass::Connected
    );
    assert!(draft.dns_interception && draft.lan_bypass);
    draft.lan_bypass = false;
    for mode in [
        DnsOverride::Inherit,
        DnsOverride::CurrentNetwork,
        DnsOverride::ProxyIpv4("8.8.8.8".parse()?),
    ] {
        draft.dns_override = mode;
        assert!(
            draft
                .validate()
                .map_err(|_| "invalid interception fixture")?
                .network()
                .intercepts_dns()
        );
    }
    Ok(())
}

#[test]
fn dns_override_round_trips_without_capturing_dhcp_addresses_or_mutating_source()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(DnsOverride::default(), DnsOverride::Inherit);
    assert_eq!(DnsOverride::Inherit.to_nm(), None);
    for text in ["current-network", "proxy-ipv4:8.8.8.8"] {
        assert_eq!(DnsOverride::from_nm(text)?.to_nm().as_deref(), Some(text));
    }
    let original = import_vless(
        "vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example",
    )?;
    let mut changed = original.clone();
    changed.dns_override = DnsOverride::CurrentNetwork;
    assert!(changed.validate().is_ok());
    assert_eq!(original.dns_override, DnsOverride::Inherit);
    assert_eq!(
        changed.dns_override.to_nm().as_deref(),
        Some("current-network")
    );
    for address in [
        "127.0.0.1",
        "192.168.1.1",
        "169.254.1.1",
        "0.0.0.0",
        "224.0.0.1",
        "198.18.0.2",
        "100.64.0.1",
    ] {
        changed.dns_override = DnsOverride::ProxyIpv4(address.parse()?);
        let errors = changed.validate().err().ok_or("invalid DNS was admitted")?;
        assert!(errors.iter().any(|error| error.field == Field::Dns));
        assert!(!format!("{:?}", changed.dns_override).contains(address));
    }
    for text in [
        "inherit",
        "proxy-ipv4:1.1.1.1:53",
        "proxy-ipv4:::1",
        "proxy-ipv4:https://private-token.example",
        "unknown",
    ] {
        let error = DnsOverride::from_nm(text).err();
        assert!(error.is_some());
        assert!(!format!("{error:?}").contains("private-token"));
    }
    assert_eq!(original.dns_override, DnsOverride::Inherit);
    changed.tcp_domain_policy = Some(nm_tunnel_profile::TcpDomainPolicy::from_json(
        r#"{"version":1,"rules":[{"domain_suffix":["direct.example"],"action":"direct"}]}"#,
    )?);
    changed.dns_override = DnsOverride::ProxyIpv4("8.8.8.8".parse()?);
    let before = changed
        .tcp_domain_policy
        .as_ref()
        .map(|policy| policy.as_json().to_owned());
    assert!(
        changed
            .validate()
            .err()
            .is_some_and(|errors| errors.iter().any(|error| error.field == Field::Dns))
    );
    assert_eq!(
        changed
            .tcp_domain_policy
            .as_ref()
            .map(|policy| policy.as_json().to_owned()),
        before
    );
    changed.dns_override = DnsOverride::CurrentNetwork;
    assert!(changed.validate().is_ok());
    Ok(())
}
