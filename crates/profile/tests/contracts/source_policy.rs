use nm_tunnel_profile::{DnsOverride, DomainAction, SourcePolicy};

const POLICY: &str = r#"{"version":1,"dns":{"address":"1.1.1.1","port":853,"transport":"tls","via_proxy":true,"tls_name":"1.1.1.1"},"domain_policy":"{\"version\":1,\"rules\":[{\"domain_suffix\":[\"direct.example\"],\"action\":\"direct\"},{\"domain\":[\"proxy.example\"],\"action\":\"proxy\"},{\"domain\":[\"blocked.example\"],\"action\":\"block\"}]}","fakeip_range":"198.18.0.0/15","tun_address":"172.19.0.1","tun_prefix":30,"mtu":1400}"#;

#[test]
fn doh_policy_round_trips_and_refuses_unsafe_paths_without_changing_legacy_json()
-> Result<(), Box<dyn std::error::Error>> {
    let legacy = SourcePolicy::from_json(POLICY)?;
    assert!(!legacy.as_json().contains("http_path"));
    let mut value: serde_json::Value = serde_json::from_str(POLICY)?;
    value["dns"]["transport"] = serde_json::json!("https");
    value["dns"]["port"] = serde_json::json!(443);
    let policy = SourcePolicy::from_json(&value.to_string())?;
    assert_eq!(policy.dns().http_path, "/dns-query");
    assert_eq!(
        SourcePolicy::from_json(policy.as_json())?.as_json(),
        policy.as_json()
    );
    for path in ["/custom", "/"] {
        value["dns"]["http_path"] = serde_json::json!(path);
        assert_eq!(
            SourcePolicy::from_json(&value.to_string())?.dns().http_path,
            path
        );
    }
    for path in [
        "//other.invalid",
        "https://other.invalid",
        "/dns-query?token=private",
        "/bad\r\nHeader:x",
        "/dns#fragment",
    ] {
        value["dns"]["http_path"] = serde_json::json!(path);
        let before = value.to_string();
        let error = SourcePolicy::from_json(&before)
            .err()
            .ok_or("Unsafe path accepted")?;
        assert!(!error.to_string().contains("private"));
        assert_eq!(value.to_string(), before);
    }
    value["dns"]["http_path"] = serde_json::json!("/dns-query");
    value["dns"]["transport"] = serde_json::json!("tls");
    assert!(SourcePolicy::from_json(&value.to_string()).is_err());
    assert!(!format!("{policy:?}").contains("dns-query"));
    Ok(())
}

#[test]
fn complete_policy_order_does_not_confuse_non_public_with_global_address_classification()
-> Result<(), Box<dyn std::error::Error>> {
    let policy = SourcePolicy::from_json(POLICY)?;
    for ip in [
        "10.1.2.3",
        "172.20.1.2",
        "192.168.1.2",
        "127.0.0.1",
        "169.254.1.2",
        "224.0.0.1",
        "0.0.0.0",
    ] {
        let address = format!("{ip}:443").parse()?;
        assert_eq!(policy.action(None, address, false), DomainAction::Direct);
        assert_eq!(
            policy.action(Some("proxy.example"), address, false),
            DomainAction::Proxy
        );
        assert_eq!(
            policy.action(Some("blocked.example"), address, false),
            DomainAction::Block
        );
        assert_eq!(
            policy.action(Some("sub.direct.example"), address, true),
            DomainAction::Block
        );
    }
    for ip in [
        "1.1.1.1",
        "100.64.1.2",
        "198.18.1.2",
        "192.0.2.1",
        "255.255.255.255",
    ] {
        let address = format!("{ip}:443").parse()?;
        assert_eq!(policy.action(None, address, false), DomainAction::Proxy);
    }
    assert!(policy.synthetic("198.19.1.2".parse()?));
    assert!(!policy.synthetic("198.20.1.2".parse()?));
    assert_eq!(
        SourcePolicy::from_json(policy.as_json())?.as_json(),
        policy.as_json()
    );
    assert!(!format!("{policy:?}").contains("direct.example"));
    Ok(())
}

#[test]
fn complete_policy_is_atomic_and_requires_its_runtime_not_legacy_route_overlays()
-> Result<(), Box<dyn std::error::Error>> {
    for text in [
        POLICY.replace("\"version\":1", "\"version\":2"),
        POLICY.replace("\"port\":853", "\"port\":0"),
        POLICY.replace("198.18.0.0/15", "10.0.0.0/8"),
        POLICY.replace("172.19.0.1", "172.19.0.0"),
        POLICY.replace("\"mtu\":1400", "\"mtu\":65535"),
        POLICY.replace(
            "\"tls_name\":\"1.1.1.1\"",
            "\"tls_name\":\"https://private-token.example\"",
        ),
    ] {
        let before = text.clone();
        let error = SourcePolicy::from_json(&text)
            .err()
            .ok_or("Invalid policy admitted")?;
        assert!(!error.to_string().contains("private-token"));
        assert_eq!(text, before);
    }
    let mut draft = nm_tunnel_profile::import_vless(
        "vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example",
    )?;
    draft.source_policy = Some(SourcePolicy::from_json(POLICY)?);
    assert!(draft.validate().is_err());
    draft.fake_ip = true;
    draft.dns_interception = true;
    let compiled = draft
        .validate()
        .map_err(|_| "Valid complete policy rejected")?;
    assert_eq!(compiled.node().udp_mode(), nm_tunnel_profile::UdpMode::Xudp);
    assert_eq!(
        compiled.network().dns_handling(),
        nm_tunnel_profile::DnsHandling::FakeIp
    );
    assert!(compiled.network().tcp_domains().is_none());
    assert_eq!(compiled.lan_bypass(), nm_tunnel_profile::LanBypass::None);
    assert_eq!(
        compiled
            .to_draft()
            .source_policy
            .as_ref()
            .map(SourcePolicy::as_json),
        compiled.network().source().map(SourcePolicy::as_json)
    );
    draft.lan_bypass = true;
    assert!(draft.validate().is_err());
    draft.lan_bypass = false;
    draft.dns_override = DnsOverride::CurrentNetwork;
    assert!(draft.validate().is_ok());
    draft.dns_override = DnsOverride::ProxyIpv4("8.8.8.8".parse()?);
    assert!(draft.validate().is_ok());
    assert!(draft.source_policy.is_some());
    Ok(())
}
