//! Complete v2 destination predicates, without network or privileged capabilities.
use nm_tunnel_profile::{DomainAction, SourcePolicy};
use serde_json::{Value, json};

fn document(rules: Value) -> Value {
    json!({"version":2,"dns":{"address":"1.1.1.1","port":53,"transport":"udp","via_proxy":true,"tls_name":""},
        "route_policy":json!({"version":1,"rules":rules}).to_string(),
        "fakeip_range":"198.18.0.0/15","tun_address":"172.19.0.1","tun_prefix":30,"mtu":1400})
}

#[test]
fn destination_groups_ports_logic_and_inversion_preserve_order()
-> Result<(), Box<dyn std::error::Error>> {
    let value = document(json!([
        {"condition":{"type":"match","domain":["PRIORITY.EXAMPLE."],"ports":[[443,443]]},"action":"proxy"},
        {"condition":{"type":"logical","mode":"and","rules":[
            {"type":"match","domain_suffix":["example"],"ip_cidr":["192.0.2.123/24"]},
            {"type":"match","ports":[[443,445],[8443,8443]]}
        ]},"action":"block"},
        {"condition":{"type":"logical","mode":"or","invert":true,"rules":[
            {"type":"match","domain":["keep.invalid"]},
            {"type":"match","ip_cidr":["10.0.0.0/8"]}
        ]},"action":"direct"}
    ]));
    let before = value.to_string();
    let policy = SourcePolicy::from_json(&before)?;
    for (name, address, expected) in [
        (
            Some("priority.example"),
            "192.0.2.1:443",
            DomainAction::Proxy,
        ),
        (
            Some("priority.example"),
            "192.0.2.1:444",
            DomainAction::Block,
        ),
        (Some("sub.example"), "203.0.113.1:8443", DomainAction::Block),
        (None, "192.0.2.1:445", DomainAction::Block),
        (Some("notexample"), "203.0.113.1:443", DomainAction::Direct),
        (Some("keep.invalid"), "203.0.113.1:443", DomainAction::Proxy),
        (None, "10.0.0.1:80", DomainAction::Direct),
    ] {
        assert_eq!(policy.action(name, address.parse()?, false), expected);
        assert_eq!(
            policy.action(name, address.parse()?, true),
            DomainAction::Block
        );
    }
    assert_eq!(
        policy.unresolved_action(Some("priority.example"), 443),
        Some(DomainAction::Proxy)
    );
    assert_eq!(
        policy.unresolved_action(Some("sub.example"), 443),
        Some(DomainAction::Block)
    );
    assert_eq!(policy.unresolved_action(Some("keep.invalid"), 443), None);
    assert_eq!(
        SourcePolicy::from_json(policy.as_json())?.as_json(),
        policy.as_json()
    );
    assert!(!policy.as_json().contains("192.0.2.123"));
    assert!(!format!("{policy:?}").contains("example"));
    assert_eq!(value.to_string(), before);
    Ok(())
}

#[test]
fn unresolved_names_do_not_get_an_ip_from_fakeip_or_trigger_ip_rule_resolution()
-> Result<(), Box<dyn std::error::Error>> {
    let policy = SourcePolicy::from_json(
        &document(json!([
            {"condition":{"type":"match","ip_cidr":["0.0.0.0/0"]},"action":"block"},
            {"condition":{"type":"match","ports":[[443,443]]},"action":"direct"}
        ]))
        .to_string(),
    )?;
    assert_eq!(
        policy.unresolved_action(Some("owned.invalid"), 443),
        Some(DomainAction::Direct)
    );
    assert_eq!(policy.unresolved_action(Some("owned.invalid"), 80), None);
    assert_eq!(
        policy.action(Some("owned.invalid"), "192.0.2.1:443".parse()?, false),
        DomainAction::Block
    );
    assert_eq!(policy.domain_action(Some("owned.invalid")), None);
    Ok(())
}

#[test]
fn malformed_v2_and_ambiguous_versions_reject_without_changing_previous_policy()
-> Result<(), Box<dyn std::error::Error>> {
    let valid =
        document(json!([{ "condition":{"type":"match","ports":[[443,443]]},"action":"proxy" }]));
    let previous = SourcePolicy::from_json(&valid.to_string())?;
    let before = previous.as_json().to_owned();
    for condition in [
        json!({"type":"match"}),
        json!({"type":"match","ip_cidr":["2001:db8::/32"]}),
        json!({"type":"match","ip_cidr":["private-token.invalid/33"]}),
        json!({"type":"match","ports":[[0,443]]}),
        json!({"type":"match","ports":[[445,443]]}),
        json!({"type":"match","domain":["https://private-token.invalid"]}),
        json!({"type":"match","ports":[[443,443]],"process_name":"curl"}),
        json!({"type":"logical","mode":"xor","rules":[]}),
        json!({"type":"logical","mode":"and","rules":[]}),
    ] {
        let value = document(json!([{ "condition":condition,"action":"direct" }]));
        let text = value.to_string();
        let error = SourcePolicy::from_json(&text)
            .err()
            .ok_or("Invalid predicate accepted")?;
        assert!(!error.to_string().contains("private-token"));
        assert_eq!(text, value.to_string());
        assert_eq!(previous.as_json(), before);
    }
    for version in [1, 3] {
        let mut invalid = valid.clone();
        invalid["version"] = json!(version);
        assert!(SourcePolicy::from_json(&invalid.to_string()).is_err());
    }
    let mut both = valid;
    both["domain_policy"] = json!("{}");
    assert!(SourcePolicy::from_json(&both.to_string()).is_err());
    for depth in [8, 9] {
        let mut condition = json!({"type":"match","ports":[[443,443]]});
        for _ in 1..depth {
            condition = json!({"type":"logical","mode":"and","rules":[condition]});
        }
        assert_eq!(
            SourcePolicy::from_json(
                &document(json!([{ "condition":condition,"action":"proxy" }])).to_string()
            )
            .is_ok(),
            depth == 8
        );
    }
    Ok(())
}

#[test]
fn predicate_tree_and_match_value_budgets_are_independent() -> Result<(), Box<dyn std::error::Error>>
{
    use nm_tunnel_profile::RoutePolicy;
    for count in [127, 128] {
        let rules: Vec<_> = (0..count)
            .map(|_| json!({"type":"match","ports":[[443,443]]}))
            .collect();
        let native = json!({"version":1,"rules":[{"condition":{"type":"logical","mode":"or","rules":rules},"action":"proxy"}]});
        assert_eq!(
            RoutePolicy::from_json(&native.to_string()).is_ok(),
            count == 127
        );
    }
    for count in [256, 257] {
        let native = json!({"version":1,"rules":[{"condition":{"type":"match","ports":vec![[443,443];count]},"action":"proxy"}]});
        assert_eq!(
            RoutePolicy::from_json(&native.to_string()).is_ok(),
            count == 256
        );
    }
    let text = json!({"version":1,"rules":[{"condition":{"type":"match","domain":["identifying.example"]},"action":"proxy"}]}).to_string();
    let policy = RoutePolicy::from_json(&text)?;
    assert!(!format!("{policy:?}").contains("identifying"));
    assert_eq!(
        policy.matched_action(Some("https://identifying.example"), None, 443),
        None
    );
    assert_eq!(
        policy.matched_action(Some("identifying.example"), None, 0),
        None
    );
    Ok(())
}
