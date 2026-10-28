//! Importer policy contracts, not upstream DNS-library tests.
use super::*;
use serde_json::json;

fn typed(kind: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let mut source = fixtures::configuration();
    source["dns"]
        .as_object_mut()
        .ok_or("Fixture object")?
        .remove("fakeip");
    source["dns"]["servers"] = json!([
        {"type":kind,"tag":"remote","server":"resolver.example","domain_resolver":"local","detour":"proxy"},
        {"type":"local","tag":"local"},
        {"type":"fakeip","tag":"fake","inet4_range":"198.18.0.0/15","inet6_range":"fd00::/16"}
    ]);
    source["dns"]["rules"] = json!([{"query_type":["A","AAAA"],"action":"route","server":"fake"}]);
    source["route"]["default_domain_resolver"] = json!("local");
    Ok(source)
}

#[test]
fn typed_servers_preserve_transport_bootstrap_tls_path_and_default_direct()
-> Result<(), Box<dyn std::error::Error>> {
    for (kind, transport, port) in [
        ("udp", nm_tunnel_profile::DnsTransport::Udp, 53),
        ("tcp", nm_tunnel_profile::DnsTransport::Tcp, 53),
        ("tls", nm_tunnel_profile::DnsTransport::Tls, 853),
        ("https", nm_tunnel_profile::DnsTransport::Https, 443),
    ] {
        for proxy in [false, true] {
            let mut source = typed(kind)?;
            if proxy {
                source["dns"]["servers"][0]["domain_resolver"] = json!({
                    "server":"local", "strategy":"ipv4_only", "disable_cache":false,
                    "rewrite_ttl":null,"client_subnet":null
                });
            }
            if !proxy {
                source["dns"]["servers"][0]
                    .as_object_mut()
                    .ok_or("Fixture")?
                    .remove("detour");
            }
            if matches!(kind, "tls" | "https") {
                source["dns"]["servers"][0]["tls"] =
                    json!({"enabled":true,"server_name":"verify.example"});
            }
            if kind == "https" {
                source["dns"]["servers"][0]["path"] = json!("/custom-dns");
            }
            let before = source.clone();
            let result = admit(&serde_json::to_vec(&source)?)?;
            for entry in result.entries() {
                let profile = entry.profile().map_err(|_| "Fixture unsupported")?;
                let dns = profile.network().source().ok_or("Missing policy")?.dns();
                assert_eq!(dns.transport, transport);
                assert_eq!(dns.port, port);
                assert_eq!(dns.host.as_deref(), Some("resolver.example"));
                assert_eq!(dns.via_proxy, proxy);
                assert_eq!(
                    dns.tls_name,
                    if matches!(kind, "tls" | "https") {
                        "verify.example"
                    } else {
                        ""
                    }
                );
                assert_eq!(
                    dns.http_path,
                    if kind == "https" { "/custom-dns" } else { "" }
                );
            }
            assert_eq!(source, before);
        }
    }
    // Legacy URL-form HTTPS receives the same native execution contract.
    let mut source = fixtures::configuration();
    source["dns"]["servers"][0]["address"] = json!("https://resolver.example/dns-query");
    let result = admit(&serde_json::to_vec(&source)?)?;
    let profile = result.entries()[0]
        .profile()
        .map_err(|_| "Fixture unsupported")?;
    assert_eq!(
        profile.network().source().ok_or("Policy")?.dns().http_path,
        "/dns-query"
    );
    Ok(())
}

#[test]
fn unsupported_typed_dns_is_atomic_and_never_discards_security_or_bootstrap()
-> Result<(), Box<dyn std::error::Error>> {
    let good = typed("https")?;
    let admitted = admit(&serde_json::to_vec(&good)?)?;
    for (pointer, field, value) in [
        ("/dns/servers/0", "domain_resolver", json!("remote")),
        (
            "/dns/servers/0",
            "domain_resolver",
            json!({"server":"local","disable_cache":true}),
        ),
        ("/dns/servers/0", "tls", json!({"insecure":true})),
        ("/dns/servers/0", "tls", json!({"enabled":false})),
        (
            "/dns/servers/0",
            "tls",
            json!({"certificate_path":"/not-read"}),
        ),
        (
            "/dns/servers/0",
            "headers",
            json!({"Authorization":"private-token"}),
        ),
        (
            "/dns/servers/0",
            "path",
            json!("/dns-query?token=private-token"),
        ),
        ("/dns/servers/0", "path", json!("//other.invalid")),
        ("/dns/servers/0", "path", json!("/a/../dns-query")),
        ("/dns/servers/0", "server", json!("2001:db8::1")),
        ("/dns/servers/0", "server_port", json!(0)),
        ("/dns/servers/0", "type", json!("quic")),
        ("/dns/servers/1", "detour", json!("proxy")),
        ("/dns/servers/2", "inet4_range", json!("10.0.0.0/8")),
        (
            "/dns",
            "fakeip",
            json!({"enabled":true,"inet4_range":"198.18.0.0/15"}),
        ),
        ("/dns/rules/0", "action", json!("reject")),
        ("/route", "default_domain_resolver", json!("remote")),
    ] {
        let mut source = good.clone();
        source
            .pointer_mut(pointer)
            .and_then(Value::as_object_mut)
            .ok_or("Fixture")?
            .insert(field.into(), value);
        let bytes = serde_json::to_vec(&source)?;
        let before = bytes.clone();
        let error = admit(&bytes).err().ok_or("Invalid DNS admitted")?;
        assert!(!error.to_string().contains("private-token"));
        assert_eq!(bytes, before);
        assert_eq!(admitted.supported_count(), 2);
    }
    let mut missing = good.clone();
    missing["dns"]["servers"][0]
        .as_object_mut()
        .ok_or("Fixture")?
        .remove("domain_resolver");
    assert!(admit(&serde_json::to_vec(&missing)?).is_err());
    Ok(())
}

#[test]
fn unselected_dns_endpoints_receive_the_same_validation_as_the_selected_one()
-> Result<(), Box<dyn std::error::Error>> {
    for modern in [false, true] {
        for invalid in ["port", "address", "tls_identity", "http_path"] {
            let mut source = if modern {
                typed("https")?
            } else {
                fixtures::configuration()
            };
            let server = if modern {
                let mut server =
                    json!({"type":"https","tag":"unused","server":"1.1.1.1","detour":"direct"});
                match invalid {
                    "port" => server["server_port"] = json!(0),
                    "address" => server["server"] = json!("127.0.0.1"),
                    "tls_identity" => server["tls"] = json!({"server_name":"9.9.9.9"}),
                    _ => server["path"] = json!(format!("/{}", "a".repeat(1024))),
                }
                server
            } else {
                json!({"tag":"unused","address":match invalid {
                    "port" => "https://1.1.1.1:0/dns-query",
                    "address" => "https://127.0.0.1/dns-query",
                    "tls_identity" => "tls://0.0.0.0",
                    _ => "https://1.1.1.1/dns-query",
                },"detour":"direct"})
            };
            let mut server = server;
            if !modern && invalid == "http_path" {
                server["address"] = json!(format!("https://1.1.1.1/{}", "a".repeat(1024)));
            }
            source["dns"]["servers"]
                .as_array_mut()
                .ok_or("Fixture servers")?
                .push(server);
            let bytes = serde_json::to_vec(&source)?;
            let before = bytes.clone();
            assert!(admit(&bytes).is_err(), "modern={modern}, invalid={invalid}");
            assert_eq!(bytes, before);
        }
    }
    Ok(())
}
