use super::*;

#[test]
fn supported_complete_ipv4_source_has_owned_policy_on_every_selected_node_and_explicit_disclosure()
-> Result<(), Box<dyn std::error::Error>> {
    let source = fixtures::configuration();
    let bytes = serde_json::to_vec(&source)?;
    let before = bytes.clone();
    let result = admit(&bytes)?;
    assert_eq!(result.supported_count(), 2);
    assert!(
        result
            .native_policy_notice()
            .is_some_and(|notice| notice.contains("XUDP")
                && notice.contains("IPv6")
                && notice.contains("terminal failure")
                && notice.contains("without VPN")
                && !notice.contains("retained on failure"))
    );
    for entry in result.entries() {
        let profile = entry.profile().map_err(|_| "Unsupported fixture")?;
        assert!(profile.network().fake_ip() && profile.network().intercepts_dns());
        assert_eq!(profile.lan_bypass(), nm_tunnel_profile::LanBypass::None);
        let policy = profile.network().source().ok_or("Missing policy")?;
        assert_eq!(policy.dns().transport, nm_tunnel_profile::DnsTransport::Tls);
        assert!(policy.dns().via_proxy);
        assert_eq!(
            policy.action(Some("sub.direct.example"), "1.1.1.1:443".parse()?, false),
            nm_tunnel_profile::DomainAction::Direct
        );
        assert_eq!(
            policy.action(None, "10.2.3.4:443".parse()?, false),
            nm_tunnel_profile::DomainAction::Direct
        );
        assert_eq!(
            policy.action(Some("direct.example"), "10.2.3.4:443".parse()?, true),
            nm_tunnel_profile::DomainAction::Block
        );
        assert_eq!(
            policy.action(None, "100.64.1.1:443".parse()?, false),
            nm_tunnel_profile::DomainAction::Proxy
        );
        assert!(policy.synthetic("198.19.0.4".parse()?));
        assert!(!policy.as_json().contains("synthetic-controller-secret"));
        assert!(!policy.as_json().contains("not-fetched"));
        assert!(!policy.as_json().contains("12345678-1234"));
    }
    assert_eq!(bytes, before);
    assert!(!format!("{result:?}").contains("proxy.example"));
    Ok(())
}

#[test]
fn unsupported_required_settings_and_nested_duplicates_reject_the_entire_complete_source()
-> Result<(), Box<dyn std::error::Error>> {
    for (pointer, value) in [
        ("/dns/independent_cache", serde_json::json!(false)),
        ("/dns/final", serde_json::json!("missing")),
        ("/dns/fakeip/inet4_range", serde_json::json!("10.0.0.0/8")),
        ("/outbounds/1/tls/insecure", serde_json::json!(true)),
        (
            "/outbounds/2/uuid",
            serde_json::json!("private-invalid-credential"),
        ),
        ("/outbounds/1/packet_encoding", serde_json::json!("")),
        ("/outbounds/1/server", serde_json::json!("2001:db8::1")),
        ("/route/rules/2/outbound", serde_json::json!("direct")),
        (
            "/experimental/clash_api/default_mode",
            serde_json::json!("global"),
        ),
        (
            "/inbounds/0/sniff_override_destination",
            serde_json::json!(true),
        ),
    ] {
        let mut source = fixtures::configuration();
        // Some forbidden fields are deliberately absent in the good fixture.
        let (parent, key) = pointer.rsplit_once('/').ok_or("Bad fixture pointer")?;
        source
            .pointer_mut(parent)
            .and_then(Value::as_object_mut)
            .ok_or("Bad fixture object")?
            .insert(key.into(), value);
        let bytes = serde_json::to_vec(&source)?;
        let before = bytes.clone();
        let error = admit(&bytes)
            .err()
            .ok_or("Unsupported full policy admitted")?;
        assert!(!error.to_string().contains("private-invalid-credential"));
        assert_eq!(bytes, before);
    }
    let good = serde_json::to_string(&fixtures::configuration())?;
    let duplicate = good.replacen("\"mtu\":1400", "\"mtu\":1400,\"mtu\":1500", 1);
    assert_ne!(good, duplicate);
    assert_eq!(
        admit(duplicate.as_bytes()).err(),
        Some(SubscriptionError::Format)
    );
    let mut reordered = fixtures::configuration();
    reordered["route"]["rules"]
        .as_array_mut()
        .ok_or("Missing rules")?
        .swap(2, 3);
    assert!(admit(&serde_json::to_vec(&reordered)?).is_err());
    Ok(())
}

#[test]
fn resolver_hostnames_require_local_bootstrap_and_disabled_mux_still_has_a_checked_shape()
-> Result<(), Box<dyn std::error::Error>> {
    let mut source = fixtures::configuration();
    source["dns"]["servers"][0]["address"] = serde_json::json!("tls://resolver.example");
    assert_eq!(admit(&serde_json::to_vec(&source)?)?.supported_count(), 2);
    source["dns"]["servers"][0]
        .as_object_mut()
        .ok_or("Missing server")?
        .remove("address_resolver");
    assert!(admit(&serde_json::to_vec(&source)?).is_err());
    for mux in [
        serde_json::json!({"enabled":false,"protocol":17}),
        serde_json::json!({"enabled":false,"max_streams":-1}),
        serde_json::json!({"enabled":false,"padding":"yes"}),
        serde_json::json!({"enabled":false,"brutal":{"enabled":false,"unknown":1}}),
    ] {
        let mut source = fixtures::configuration();
        source["outbounds"][1]["multiplex"] = mux;
        let before = source.clone();
        assert!(admit(&serde_json::to_vec(&source)?).is_err());
        assert_eq!(source, before);
    }
    Ok(())
}

#[test]
fn complete_documents_never_extract_nodes_while_global_policy_is_unsupported() {
    for (policy, issue) in [
        (r#""dns":{"fakeip":{"enabled":true}},"#, PolicyIssue::FakeIp),
        (
            r#""dns":{"servers":[{"type":"fakeip"}]},"#,
            PolicyIssue::FakeIp,
        ),
        (
            r#""dns":{"servers":[{"address":"fakeip"}]},"#,
            PolicyIssue::FakeIp,
        ),
        (
            r#""dns":{"servers":[{"address":"local"}]},"#,
            PolicyIssue::Dns,
        ),
        (
            r#""route":{"rules":[{"domain_suffix":["private.example"],"outbound":"direct"}]},"#,
            PolicyIssue::Routing,
        ),
        (
            r#""experimental":{"external_ui_download_url":"https://example.com/private-token"},"#,
            PolicyIssue::ClientIntegration,
        ),
        (
            r#""inbounds":[{"type":"mixed","listen":"0.0.0.0"}],"#,
            PolicyIssue::ClientIntegration,
        ),
        ("", PolicyIssue::Configuration),
    ] {
        let body = format!(
            r#"{{{policy}"outbounds":[{{"type":"vless","uuid":"private-credential","server":"private.example"}}]}}"#
        );
        let before = body.clone();
        let error = admit(body.as_bytes()).err();
        assert_eq!(error, Some(SubscriptionError::UnsupportedPolicy(issue)));
        assert_eq!(body, before);
        let display = format!("{error:?} {}", SubscriptionError::UnsupportedPolicy(issue));
        for sensitive in ["private-token", "private-credential", "private.example"] {
            assert!(!display.contains(sensitive));
        }
    }
}

#[test]
fn malformed_duplicate_unknown_or_oversized_documents_cannot_bypass_admission() {
    for text in [
        r#"{"outbounds":[]}"#,
        r#"{"outbounds":[{}]}"#,
        r#"{"outbounds":[{"type":"vless"}],"outbounds":[]}"#,
        r#"{"outbounds":[{"type":"vless"}],"unknown-policy":true}"#,
        r#"{"outbounds":[{"type":"vless"}],"dns":{},"dns":null}"#,
        r#"{"outbounds":[{"type":"vless"}]"#,
    ] {
        assert_eq!(
            admit(text.as_bytes()).err(),
            Some(SubscriptionError::Format)
        );
    }
    assert_eq!(
        admit(&vec![b' '; MAX_BYTES + 1]).err(),
        Some(SubscriptionError::TooLarge)
    );
    let excessive = vec![r#"{"type":"vless"}"#; MAX_ENTRIES + 1].join(",");
    let text = format!(r#"{{"outbounds":[{excessive}]}}"#);
    assert_eq!(
        admit(text.as_bytes()).err(),
        Some(SubscriptionError::TooManyEntries)
    );
    for text in [
        "vless://synthetic@example.com:443",
        "dmxlc3M6Ly9zeW50aGV0aWM=",
        "<html>private-token</html>",
    ] {
        assert_eq!(
            admit(text.as_bytes()).err(),
            Some(SubscriptionError::FullConfigurationRequired)
        );
    }
}
