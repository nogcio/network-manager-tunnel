//! Modern syntax must preserve the existing native pipeline, never broaden authority.
use super::*;
use serde_json::json;

#[test]
fn post_sniff_reject_without_block_outbound_preserves_native_actions_and_order()
-> Result<(), Box<dyn std::error::Error>> {
    let mut legacy = fixtures::configuration();
    legacy["route"]["rules"]
        .as_array_mut()
        .ok_or("Fixture rules")?
        .insert(3, json!({"domain":"blocked.example", "outbound":"block"}));
    let previous = admit(&serde_json::to_vec(&legacy)?)?;
    for method in [None, Some("default"), Some("drop")] {
        let mut source = legacy.clone();
        source["outbounds"]
            .as_array_mut()
            .ok_or("Fixture outbounds")?
            .retain(|v| v["type"] != "block");
        source["route"]["rules"][2] = json!({"protocol":"bittorrent", "action":"reject"});
        source["route"]["rules"][3] = json!({"domain":"blocked.example", "action":"reject"});
        if let Some(method) = method {
            source["route"]["rules"][2]["method"] = json!(method);
            source["route"]["rules"][3]["method"] = json!(method);
        }
        source["route"]["rules"][4]["action"] = json!("route");
        source["route"]["rules"][5]["action"] = json!("route");
        let before = source.clone();
        let result = admit(&serde_json::to_vec(&source)?)?;
        assert_eq!(source, before);
        for (old, new) in previous.entries().iter().zip(result.entries()) {
            let old = old.profile().map_err(|_| "Fixture profile")?;
            let new = new.profile().map_err(|_| "Fixture profile")?;
            assert_eq!(
                old.network().source().ok_or("Policy")?.as_json(),
                new.network().source().ok_or("Policy")?.as_json()
            );
        }
        assert_eq!(result.supported_count(), previous.supported_count());
    }
    Ok(())
}

#[test]
fn bootstrap_object_forms_and_dns_route_options_preserve_local_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let mut source = fixtures::configuration();
    let previous = admit(&serde_json::to_vec(&source)?)?;
    let resolver = json!({"server":"local", "strategy":"ipv4_only", "disable_cache":false,
        "rewrite_ttl":null,"client_subnet":null});
    source["route"]["default_domain_resolver"] = resolver.clone();
    source["dns"]["rules"] = json!([{"query_type":["A","AAAA"],"action":"route",
        "server":"fake","strategy":"ipv4_only","disable_cache":false,
        "rewrite_ttl":null,"client_subnet":null}]);
    for index in [1, 2] {
        source["outbounds"][index]["domain_resolver"] = resolver.clone();
    }
    let result = admit(&serde_json::to_vec(&source)?)?;
    assert_eq!(result.supported_count(), 2);
    for (old, new) in previous.entries().iter().zip(result.entries()) {
        let old = old.profile().map_err(|_| "Fixture profile")?;
        let new = new.profile().map_err(|_| "Fixture profile")?;
        assert_eq!(
            old.network().source().ok_or("Policy")?.as_json(),
            new.network().source().ok_or("Policy")?.as_json()
        );
    }
    Ok(())
}

#[test]
fn nonrepresentable_modifiers_and_ambiguous_actions_reject_atomically()
-> Result<(), Box<dyn std::error::Error>> {
    for (pointer, key, value) in [
        ("/route/rules/2", "action", json!("resolve")),
        ("/route/rules/2", "action", json!("reject")), // reject+outbound ambiguity
        (
            "/route/rules/3",
            "override_address",
            json!("private-token.example"),
        ),
        ("/route/rules/3", "udp_timeout", json!("30s")),
        ("/dns/rules/0", "rewrite_ttl", json!(0)),
        ("/dns/rules/0", "client_subnet", json!("192.0.2.0/24")),
        ("/dns/rules/0", "disable_cache", json!(true)),
        ("/dns/rules/0", "strategy", json!("prefer_ipv6")),
        (
            "/route",
            "default_domain_resolver",
            json!({"server":"remote"}),
        ),
        (
            "/route",
            "default_domain_resolver",
            json!({"server":"local","disable_cache":true}),
        ),
        (
            "/route",
            "default_domain_resolver",
            json!({"server":"local","rewrite_ttl":30}),
        ),
        (
            "/outbounds/1",
            "domain_resolver",
            json!({"server":"remote"}),
        ),
        (
            "/outbounds/1",
            "domain_resolver",
            json!({"server":"local","client_subnet":"192.0.2.0/24"}),
        ),
    ] {
        let mut source = fixtures::configuration();
        source
            .pointer_mut(pointer)
            .and_then(Value::as_object_mut)
            .ok_or("Fixture object")?
            .insert(key.into(), value);
        let bytes = serde_json::to_vec(&source)?;
        let before = bytes.clone();
        let error = admit(&bytes).err().ok_or("Unsupported action admitted")?;
        assert_eq!(bytes, before);
        assert!(!error.to_string().contains("private-token"));
    }
    for (key, value) in [
        ("no_drop", json!(true)),
        ("method", json!("invalid")),
        ("method", Value::Null),
    ] {
        let mut source = fixtures::configuration();
        source["route"]["rules"][2] = json!({"protocol":"bittorrent","action":"reject"});
        source["route"]["rules"][2][key] = value;
        assert!(admit(&serde_json::to_vec(&source)?).is_err());
    }
    let mut before_sniff = fixtures::configuration();
    before_sniff["route"]["rules"][0] = json!({"action":"reject"});
    assert!(admit(&serde_json::to_vec(&before_sniff)?).is_err());
    Ok(())
}
