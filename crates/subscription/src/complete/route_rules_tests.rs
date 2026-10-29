//! Import and execute the bounded current-style destination-rule contract.
use super::super::{admit, fixtures};
use nm_tunnel_profile::DomainAction;
use serde_json::{Value, json};

fn source(rule: Value) -> Value {
    let mut value = fixtures::configuration();
    value["route"]["rules"][3] = rule;
    value
}

#[test]
fn modern_destination_conditions_are_compiled_and_executed_not_flattened()
-> Result<(), Box<dyn std::error::Error>> {
    let value = source(json!({"type":"logical","mode":"and","rules":[
        {"domain_suffix":"direct.example","ip_cidr":"192.0.2.123/24"},
        {"type":"logical","mode":"or","rules":[{"port":[443,8443]},{"port_range":"1000:2000"}]},
        {"domain":"blocked.direct.example","invert":true}
    ],"action":"route","outbound":"direct"}));
    let bytes = serde_json::to_vec(&value)?;
    let result = admit(&bytes)?;
    for entry in result.entries() {
        let profile = entry.profile().map_err(|_| "Invalid profile")?;
        let policy = profile.network().source().ok_or("No source policy")?;
        assert!(policy.as_json().contains("route_policy"));
        assert!(!policy.as_json().contains("domain_policy"));
        for (name, address, expected) in [
            (
                Some("sub.direct.example"),
                "203.0.113.1:443",
                DomainAction::Direct,
            ),
            (None, "192.0.2.9:8443", DomainAction::Direct),
            (
                Some("blocked.direct.example"),
                "192.0.2.9:443",
                DomainAction::Proxy,
            ),
            (
                Some("direct.example"),
                "203.0.113.1:999",
                DomainAction::Proxy,
            ),
            (
                Some("other.example"),
                "203.0.113.1:443",
                DomainAction::Proxy,
            ),
        ] {
            assert_eq!(policy.action(name, address.parse()?, false), expected);
        }
        assert_eq!(
            policy.unresolved_action(Some("direct.example"), 1500),
            Some(DomainAction::Direct)
        );
        assert_eq!(policy.unresolved_action(Some("other.example"), 1500), None);
    }
    assert_eq!(bytes, serde_json::to_vec(&value)?);
    Ok(())
}

#[test]
fn inline_domain_references_keep_port_constraints_and_open_ranges()
-> Result<(), Box<dyn std::error::Error>> {
    let mut value =
        source(json!({"rule_set":"domains","port_range":[":100","65000:"],"action":"reject"}));
    value["route"]["rule_set"] =
        json!([{ "tag":"domains","rules":[{"domain":"blocked.example"}] }]);
    let result = admit(&serde_json::to_vec(&value)?)?;
    let policy = result.entries()[0]
        .profile()
        .map_err(|_| "No profile")?
        .network()
        .source()
        .ok_or("No policy")?;
    for (port, blocked) in [
        (1, true),
        (100, true),
        (101, false),
        (64999, false),
        (65000, true),
        (65535, true),
    ] {
        assert_eq!(
            policy.unresolved_action(Some("blocked.example"), port) == Some(DomainAction::Block),
            blocked
        );
    }
    assert_eq!(policy.unresolved_action(Some("other.example"), 53), None);
    Ok(())
}

#[test]
fn unsupported_predicates_ranges_and_nested_actions_are_atomic_rejections()
-> Result<(), Box<dyn std::error::Error>> {
    let previous = admit(&serde_json::to_vec(&fixtures::configuration())?)?;
    for rule in [
        json!({"ip_cidr":"::/0","outbound":"direct"}),
        json!({"ip_cidr":"192.0.2.0/33","outbound":"direct"}),
        json!({"port":0,"outbound":"direct"}),
        json!({"port":65536,"outbound":"direct"}),
        json!({"port":"443","outbound":"direct"}),
        json!({"port":[],"outbound":"direct"}),
        json!({"port_range":[],"outbound":"direct"}),
        json!({"port_range":"443:80","outbound":"direct"}),
        json!({"port_range":"1:2:3","outbound":"direct"}),
        json!({"port_range":"+1:443","outbound":"direct"}),
        json!({"type":"logical","mode":"and","rules":[{"port":443,"action":"reject"}],"outbound":"direct"}),
        json!({"type":"logical","mode":"or","rules":[],"outbound":"direct"}),
        json!({"ip_cidr":"192.0.2.0/24","process_name":"private-token","outbound":"direct"}),
        json!({"port":443,"action":"route","outbound":"direct","override_port":8443}),
    ] {
        let bytes = serde_json::to_vec(&source(rule))?;
        let original = bytes.clone();
        let error = admit(&bytes).err().ok_or("Unsupported rule admitted")?;
        assert!(!error.to_string().contains("private-token"));
        assert_eq!(bytes, original);
        assert_eq!(previous.supported_count(), 2);
    }
    Ok(())
}
