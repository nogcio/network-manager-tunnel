//! Contracts for compile-time expansion; no network/filesystem capabilities exist.
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
        json!({"tag":"bad","rules":[{"domain":"valid.example","port":443}]}),
        json!({"tag":"bad","rules":[{"ip_cidr":"192.0.2.0/24"}]}),
        json!({"tag":"bad","rules":[{"domain_regex":".*"}]}),
        json!({"tag":"bad","rules":[{"domain":"valid.example","invert":true}]}),
        json!({"tag":"bad","rules":[{"type":"logical","mode":"and","rules":[{"domain":"valid.example"}]}]}),
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
        assert!(admit(&serde_json::to_vec(&source)?).is_err());
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
