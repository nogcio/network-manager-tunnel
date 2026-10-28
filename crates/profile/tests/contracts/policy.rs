use nm_tunnel_profile::{DomainAction, MAX_POLICY_BYTES, TcpDomainPolicy, canonical_domain};

#[test]
fn ordered_domain_rules_keep_label_boundaries_and_subdomains_only_semantics()
-> Result<(), Box<dyn std::error::Error>> {
    let policy = TcpDomainPolicy::from_json(
        r#"{"version":1,"rules":[
        {"domain":["Denied.Example."],"action":"block"},
        {"domain_suffix":["example"],"action":"direct"},
        {"domain_suffix":[".only.test"],"action":"block"}
    ]}"#,
    )?;
    for (host, action) in [
        (Some("DENIED.EXAMPLE."), DomainAction::Block),
        (Some("example"), DomainAction::Direct),
        (Some("a.example"), DomainAction::Direct),
        (Some("notexample"), DomainAction::Proxy),
        (Some("example.evil.test"), DomainAction::Proxy),
        (Some("only.test"), DomainAction::Proxy),
        (Some("a.only.test"), DomainAction::Block),
        (Some("http://a.example"), DomainAction::Proxy),
        (Some("1.2.3.4"), DomainAction::Proxy),
        (None, DomainAction::Proxy),
    ] {
        assert_eq!(policy.action(host), action);
    }
    let encoded = policy.as_json().to_owned();
    assert_eq!(TcpDomainPolicy::from_json(&encoded)?.as_json(), encoded);
    assert!(!format!("{policy:?}").contains("example"));
    Ok(())
}

#[test]
fn invalid_or_unsupported_rules_are_atomic_and_do_not_change_a_previous_policy()
-> Result<(), Box<dyn std::error::Error>> {
    let valid = r#"{"version":1,"rules":[{"domain":["valid.example"],"action":"direct"}]}"#;
    let previous = TcpDomainPolicy::from_json(valid)?;
    let before = previous.as_json().to_owned();
    for invalid in [
        valid.replace("\"version\":1", "\"version\":2"),
        valid.replace("\"domain\"", "\"domain_regex\""),
        valid.replace("valid.example", "*.example"),
        valid.replace("valid.example", "secret@host.example"),
        valid.replace("valid.example", "-bad.example"),
        valid.replace("valid.example", "a..example"),
        valid.replace("\"direct\"", "\"unknown-action\""),
        valid.replace("\"domain\"", "\"network\":\"udp\",\"domain\""),
        r#"{"version":1,"rules":[]}"#.into(),
        r#"{"version":1,"rules":[{"action":"direct"}]}"#.into(),
        r#"{"version":1,"version":2,"rules":[]}"#.into(),
        " ".repeat(MAX_POLICY_BYTES + 1),
    ] {
        let error = TcpDomainPolicy::from_json(&invalid).err();
        assert!(error.is_some());
        assert!(!format!("{error:?}").contains("secret"));
        assert_eq!(previous.as_json(), before);
        assert_eq!(previous.action(Some("valid.example")), DomainAction::Direct);
    }
    for name in [
        "host:443",
        "localhost/evil",
        "a%2eexample",
        "tést.example",
        "",
    ] {
        assert!(canonical_domain(name).is_none());
    }
    Ok(())
}

#[test]
fn rule_and_name_budgets_are_enforced() {
    let rule = r#"{"domain":["a.example"],"action":"proxy"}"#;
    let input = format!(r#"{{"version":1,"rules":[{}]}}"#, vec![rule; 65].join(","));
    assert!(TcpDomainPolicy::from_json(&input).is_err());
    let names = vec!["\"a.example\""; 129].join(",");
    let input = format!(r#"{{"version":1,"rules":[{{"domain":[{names}],"action":"proxy"}}]}}"#);
    assert!(TcpDomainPolicy::from_json(&input).is_err());
}
