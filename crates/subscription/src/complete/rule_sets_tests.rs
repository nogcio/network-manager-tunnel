//! Contracts for compile-time expansion; no network/filesystem capabilities exist.
use super::super::route_rules::MAX_DEPTH;
use super::super::{admit, fixtures};
use super::*;
use nm_tunnel_profile::DomainAction;
use serde_json::json;

fn source(sets: Value, references: Value) -> Result<Value, Box<dyn std::error::Error>> {
    let mut source = fixtures::configuration();
    source["route"]["rule_set"] = sets;
    source["route"]["rules"][3] = json!({"rule_set":references,"outbound":"direct"});
    Ok(source)
}

#[test]
fn inline_sets_preserve_or_suffix_boundaries_and_first_matching_action()
-> Result<(), Box<dyn std::error::Error>> {
    let mut source = source(
        json!([
            {"type":"inline","tag":"suffixes","rules":[
                {"type":"logical","mode":"or","rules":[
                    {"domain_suffix":["direct.example",".children.example"]},
                    {"domain":"EXACT.EXAMPLE."}
                ]}
            ]},
            {"tag":"overlap","rules":[{"type":"default","domain":"priority.example","invert":false}]},
            {"tag":"blocked","rules":[{"domain_suffix":["direct.example","blocked.example"]}]}
        ]),
        json!(["suffixes", "overlap"]),
    )?;
    let rules = source["route"]["rules"]
        .as_array_mut()
        .ok_or("Fixture rules")?;
    rules.insert(
        3,
        json!({"domain":"priority.example","action":"route","outbound":"proxy"}),
    );
    rules.insert(5, json!({"rule_set":"blocked","action":"reject"}));
    let bytes = serde_json::to_vec(&source)?;
    let before = bytes.clone();
    let result = admit(&bytes)?;
    assert_eq!(result.supported_count(), 2);
    for entry in result.entries() {
        let profile = entry.profile().map_err(|_| "Fixture profile")?;
        let policy = profile.network().source().ok_or("Missing policy")?;
        for (name, expected) in [
            ("priority.example", Some(DomainAction::Proxy)),
            ("direct.example", Some(DomainAction::Direct)),
            ("sub.direct.example", Some(DomainAction::Direct)),
            ("exact.example", Some(DomainAction::Direct)),
            ("sub.children.example", Some(DomainAction::Direct)),
            ("blocked.example", Some(DomainAction::Block)),
            ("children.example", None),
            ("notdirect.example", None),
            ("other.example", None),
        ] {
            assert_eq!(policy.domain_action(Some(name)), expected);
        }
        assert_eq!(policy.domain_action(None), None);
        assert!(!policy.as_json().contains("rule_set"));
        assert!(!policy.as_json().contains("suffixes"));
    }
    assert_eq!(bytes, before);
    Ok(())
}

#[test]
fn invalid_or_unused_sets_and_nonrepresentable_combinations_reject_atomically()
-> Result<(), Box<dyn std::error::Error>> {
    let good = json!({"tag":"good","rules":[{"domain_suffix":"direct.example"}]});
    let previous = admit(&serde_json::to_vec(&source(
        json!([good.clone()]),
        json!("good"),
    )?)?)?;
    for bad in [
        json!({"type":"remote","tag":"bad","url":"https://private-token.example/not-fetched"}),
        json!({"type":"local","tag":"bad","path":"/not-read/sets.json"}),
        json!({"tag":"bad","rules":[]}),
        json!({"tag":"bad","rules":[{}]}),
        json!({"tag":"bad","rules":[{"domain":"https://private-token.example"}]}),
        json!({"tag":"bad","rules":[{"domain":"valid.example","port":0}]}),
        json!({"tag":"bad","rules":[{"ip_cidr":"2001:db8::/32"}]}),
        json!({"tag":"bad","rules":[{"domain_regex":".*"}]}),
        json!({"tag":"bad","rules":[{"domain":"valid.example","invert":"true"}]}),
        json!({"tag":"bad","rules":[{"type":"logical","mode":"xor","rules":[{"domain":"valid.example"}]}]}),
        json!({"tag":"bad","rules":[{"type":"logical","mode":"or","rules":[]}]}),
        json!({"tag":"bad","rules":[{"rule_set":"good"}]}),
        json!({"tag":"bad","rules":[{"domain":"valid.example","action":"reject"}]}),
        json!({"tag":"good","rules":[{"domain":"duplicate-tag.example"}]}),
    ] {
        let source = source(json!([good.clone(), bad]), json!("good"))?;
        let bytes = serde_json::to_vec(&source)?;
        let before = bytes.clone();
        let error = admit(&bytes)
            .err()
            .ok_or("Unsupported declaration admitted")?;
        assert!(!error.to_string().contains("private-token"));
        assert_eq!(bytes, before);
        assert_eq!(previous.supported_count(), 2);
    }
    for reference in [
        json!("missing"),
        json!([]),
        json!(["good", "missing"]),
        Value::Null,
    ] {
        assert!(
            admit(&serde_json::to_vec(&source(
                json!([good.clone()]),
                reference
            )?)?)
            .is_err()
        );
    }
    for (key, value) in [
        ("domain", json!("extra.example")),
        ("domain_suffix", json!([])),
        ("invert", json!(true)),
        ("rule_set_ip_cidr_match_source", json!(true)),
    ] {
        let mut source = source(json!([good.clone()]), json!("good"))?;
        source["route"]["rules"][3][key] = value;
        if key != "rule_set_ip_cidr_match_source" {
            // Group merging and inversion are representable in source v2.
            let admitted = admit(&serde_json::to_vec(&source)?)?;
            let policy = admitted.entries()[0]
                .profile()
                .map_err(|_| "No profile")?
                .network()
                .source()
                .ok_or("No policy")?;
            assert_eq!(
                policy.unresolved_action(Some("direct.example"), 443),
                if key == "invert" {
                    None
                } else {
                    Some(DomainAction::Direct)
                }
            );
            assert_eq!(
                policy.unresolved_action(Some("other.example"), 443),
                if key == "invert" {
                    Some(DomainAction::Direct)
                } else {
                    None
                }
            );
            if key == "domain" {
                assert_eq!(
                    policy.unresolved_action(Some("extra.example"), 443),
                    Some(DomainAction::Direct)
                );
            }
        } else {
            assert!(admit(&serde_json::to_vec(&source)?).is_err());
        }
    }
    Ok(())
}

#[test]
fn declaration_depth_nodes_names_and_expansion_have_independent_bounds()
-> Result<(), Box<dyn std::error::Error>> {
    for depth in [MAX_DEPTH, MAX_DEPTH + 1] {
        let mut rule = json!({"domain":"direct.example"});
        for _ in 1..depth {
            rule = json!({"type":"logical","mode":"or","rules":[rule]});
        }
        let bytes = serde_json::to_vec(&source(
            json!([{"tag":"set","rules":[rule]}]),
            json!("set"),
        )?)?;
        assert_eq!(admit(&bytes).is_ok(), depth == MAX_DEPTH);
    }
    for count in [MAX_NAMES, MAX_NAMES + 1] {
        let names: Vec<_> = (0..count).map(|i| format!("name{i}.example")).collect();
        let source = source(
            json!([{"tag":"set","rules":[{"domain":names}]}]),
            json!("set"),
        )?;
        assert_eq!(
            admit(&serde_json::to_vec(&source)?).is_ok(),
            count == MAX_NAMES
        );
    }
    for count in [MAX_NODES, MAX_NODES + 1] {
        let rules: Vec<_> = (0..count)
            .map(|_| json!({"domain":"same.example"}))
            .collect();
        assert_eq!(
            InlineSets::parse(Some(&json!([{"tag":"set","rules":rules}]))).is_ok(),
            count == MAX_NODES
        );
    }
    for count in [MAX_SETS, MAX_SETS + 1] {
        let sets: Vec<_> = (0..count)
            .map(|i| json!({"tag":format!("set{i}"),"rules":[{"domain":"same.example"}]}))
            .collect();
        assert_eq!(
            InlineSets::parse(Some(&json!(sets))).is_ok(),
            count == MAX_SETS
        );
    }
    let names: Vec<_> = (0..65).map(|i| format!("name{i}.example")).collect();
    let mut expanded = source(
        json!([{"tag":"set","rules":[{"domain":names}]}]),
        json!("set"),
    )?;
    let repeated = expanded["route"]["rules"][3].clone();
    expanded["route"]["rules"]
        .as_array_mut()
        .ok_or("Fixture rules")?
        .insert(3, repeated);
    assert!(
        admit(&serde_json::to_vec(&expanded)?).is_err(),
        "Repeated references count toward native name budget"
    );
    let long_name = format!(
        "{}.{}.{}.example",
        "a".repeat(60),
        "b".repeat(60),
        "c".repeat(60)
    );
    let oversized = json!([{"tag":"set","rules":[{"domain":vec![long_name;MAX_NAMES]}]}]);
    assert!(InlineSets::parse(Some(&oversized)).is_err());
    Ok(())
}

#[test]
fn inline_destination_sets_keep_cidr_port_and_logical_conditions()
-> Result<(), Box<dyn std::error::Error>> {
    let mut value = source(
        json!([{"tag":"private-set-metadata","rules":[
            {"type":"logical","mode":"and","rules":[
                {"domain_suffix":"blocked.example","ip_cidr":"203.0.113.91/24"},
                {"port_range":["400:499","8000:8099"]},
                {"domain":"permit.blocked.example","invert":true}
            ]},
            {"port":9000}
        ]}]),
        json!("private-set-metadata"),
    )?;
    value["route"]["rules"][3] = json!({"rule_set":"private-set-metadata","action":"reject"});
    let bytes = serde_json::to_vec(&value)?;
    let result = admit(&bytes)?;
    for entry in result.entries() {
        let profile = entry.profile().map_err(|_| "Missing profile")?;
        let policy = profile.network().source().ok_or("Missing policy")?;
        for (name, address, blocked) in [
            (None, "203.0.113.4:450", true),
            (Some("sub.blocked.example"), "192.0.2.4:8000", true),
            (Some("permit.blocked.example"), "203.0.113.4:450", false),
            (Some("sub.blocked.example"), "192.0.2.4:80", false),
            (None, "192.0.2.4:9000", true),
            (None, "192.0.2.4:450", false),
        ] {
            assert_eq!(
                policy.action(name, address.parse()?, false),
                if blocked {
                    DomainAction::Block
                } else {
                    DomainAction::Proxy
                }
            );
        }
        assert_eq!(
            policy.unresolved_action(Some("sub.blocked.example"), 450),
            Some(DomainAction::Block)
        );
        assert_eq!(policy.unresolved_action(None, 450), None);
        assert_eq!(
            policy.unresolved_action(None, 9000),
            Some(DomainAction::Block)
        );
        assert!(!policy.as_json().contains("private-set-metadata"));
        assert!(!policy.as_json().contains("rule_set"));
    }
    assert_eq!(bytes, serde_json::to_vec(&value)?);
    Ok(())
}

#[test]
fn set_shape_controls_group_merging_instead_of_flattening_conditions()
-> Result<(), Box<dyn std::error::Error>> {
    let shapes = [
        json!([{"ip_cidr":"203.0.113.0/24","port":443}]),
        json!([{"ip_cidr":"203.0.113.0/24"},{"port":443}]),
        json!([{"type":"logical","mode":"or","rules":[{"ip_cidr":"203.0.113.0/24"},{"port":443}]}]),
    ];
    for (index, rules) in shapes.into_iter().enumerate() {
        let mut value = source(json!([{"tag":"shape","rules":rules}]), json!("shape"))?;
        value["route"]["rules"][3] =
            json!({"rule_set":"shape","domain":"outer.example","port":8443,"action":"reject"});
        let result = admit(&serde_json::to_vec(&value)?)?;
        let profile = result.entries()[0]
            .profile()
            .map_err(|_| "Missing profile")?;
        let policy = profile.network().source().ok_or("Missing policy")?;
        for (name, address, merged, independent) in [
            (None, "203.0.113.2:443", true, false),
            (Some("outer.example"), "192.0.2.2:8443", true, false),
            (Some("outer.example"), "192.0.2.2:443", true, false),
            (None, "203.0.113.2:8443", true, false),
            (Some("outer.example"), "203.0.113.2:8443", true, true),
            (None, "192.0.2.2:443", false, false),
            (Some("outer.example"), "203.0.113.2:80", false, false),
        ] {
            let expected = if index == 0 { merged } else { independent };
            assert_eq!(
                policy.action(name, address.parse()?, false) == DomainAction::Block,
                expected
            );
        }
    }
    Ok(())
}

#[test]
fn different_set_tags_do_not_share_groups_and_outer_inversion_applies_last()
-> Result<(), Box<dyn std::error::Error>> {
    for invert in [false, true] {
        let mut value = source(
            json!([
                {"tag":"addresses","rules":[{"ip_cidr":"203.0.113.0/24"}]},
                {"tag":"ports","rules":[{"port":443}]}
            ]),
            json!(["addresses", "ports"]),
        )?;
        value["route"]["rules"][3] = json!({"rule_set":["addresses","ports"],"domain":"outer.example","port":8443,"invert":invert,"action":"reject"});
        let result = admit(&serde_json::to_vec(&value)?)?;
        let profile = result.entries()[0]
            .profile()
            .map_err(|_| "Missing profile")?;
        let policy = profile.network().source().ok_or("Missing policy")?;
        for (name, address, matched) in [
            (None, "203.0.113.4:443", false),
            (None, "203.0.113.4:8443", true),
            (Some("outer.example"), "192.0.2.4:443", true),
            (Some("other.example"), "192.0.2.4:443", false),
            (Some("outer.example"), "192.0.2.4:80", false),
        ] {
            assert_eq!(
                policy.action(name, address.parse()?, false) == DomainAction::Block,
                matched != invert
            );
        }
    }
    // An inverted single entry remains a complete predicate, never a mergeable
    // default entry whose groups could widen the outer domain condition.
    let mut value = source(
        json!([{"tag":"inverse","rules":[{"domain":"excluded.example","invert":true}]}]),
        json!("inverse"),
    )?;
    value["route"]["rules"][3] =
        json!({"rule_set":"inverse","domain":"outer.example","port":8443,"action":"reject"});
    let result = admit(&serde_json::to_vec(&value)?)?;
    let profile = result.entries()[0]
        .profile()
        .map_err(|_| "Missing profile")?;
    let policy = profile.network().source().ok_or("Missing policy")?;
    assert_eq!(
        policy.unresolved_action(Some("outer.example"), 8443),
        Some(DomainAction::Block)
    );
    assert_eq!(policy.unresolved_action(Some("other.example"), 8443), None);
    assert_eq!(policy.unresolved_action(Some("outer.example"), 443), None);
    Ok(())
}

#[test]
fn repeated_rich_set_expansion_counts_values_without_losing_previous_profiles()
-> Result<(), Box<dyn std::error::Error>> {
    let previous = admit(&serde_json::to_vec(&fixtures::configuration())?)?;
    for references in [2, 3] {
        let mut value = source(
            json!([{"tag":"ports","rules":[{"port":vec![443;100]}]}]),
            json!("ports"),
        )?;
        let repeated = value["route"]["rules"][3].clone();
        for _ in 1..references {
            value["route"]["rules"]
                .as_array_mut()
                .ok_or("Missing rules")?
                .insert(3, repeated.clone());
        }
        let bytes = serde_json::to_vec(&value)?;
        assert_eq!(admit(&bytes).is_ok(), references == 2);
        assert_eq!(bytes, serde_json::to_vec(&value)?);
        assert_eq!(previous.supported_count(), 2);
    }
    Ok(())
}

#[test]
fn unused_destination_sets_validate_without_upgrading_domain_only_policy()
-> Result<(), Box<dyn std::error::Error>> {
    let mut value = fixtures::configuration();
    let original = admit(&serde_json::to_vec(&value)?)?;
    value["route"]["rule_set"] =
        json!([{"tag":"unused","rules":[{"ip_cidr":"192.0.2.1/24","port_range":"1000:2000"}]}]);
    let admitted = admit(&serde_json::to_vec(&value)?)?;
    let before = original.entries()[0]
        .profile()
        .map_err(|_| "Missing profile")?
        .network()
        .source()
        .ok_or("Missing policy")?;
    let after = admitted.entries()[0]
        .profile()
        .map_err(|_| "Missing profile")?
        .network()
        .source()
        .ok_or("Missing policy")?;
    assert_eq!(after.as_json(), before.as_json());
    value["route"]["rule_set"][0]["rules"][0]["ip_cidr"] = json!("2001:db8::/32");
    assert!(admit(&serde_json::to_vec(&value)?).is_err());
    assert_eq!(admitted.supported_count(), 2);
    Ok(())
}
