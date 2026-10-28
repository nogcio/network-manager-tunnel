//! Subscription admission contracts use synthetic nodes; no external requests.
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use nm_tunnel_subscription::{
    MAX_BYTES, MAX_ENTRIES, SubscriptionError, parse_subscription, validate_url,
};

const LINK: &str = "vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=www.example.com#Example";

#[test]
fn plain_and_base64_lists_produce_the_same_nodes() -> Result<(), Box<dyn std::error::Error>> {
    let list = format!("{LINK}\r\n{LINK}\r\n");
    for body in [
        list.clone(),
        STANDARD.encode(&list),
        URL_SAFE_NO_PAD.encode(&list),
    ] {
        let subscription = parse_subscription(body.as_bytes())?;
        assert_eq!(subscription.entries().len(), 2);
        assert_eq!(subscription.supported_count(), 2);
        assert_eq!(subscription.entries()[0].name(), "Example");
        assert!(!format!("{subscription:?}").contains("12345678-1234"));
        assert!(!format!("{subscription:?}").contains("proxy.example"));
    }
    Ok(())
}

#[test]
fn unsupported_protocols_and_settings_remain_visible() -> Result<(), Box<dyn std::error::Error>> {
    let unsupported = LINK.replace("security=tls", "security=none");
    let body = format!("{LINK}\ntrojan://private-password@proxy.example:443#Other\n{unsupported}");
    let subscription = parse_subscription(body.as_bytes())?;
    assert_eq!(subscription.entries().len(), 3);
    assert_eq!(subscription.supported_count(), 1);
    assert_eq!(subscription.entries()[1].name(), "Other");
    for entry in &subscription.entries()[1..] {
        assert!(entry.profile().is_err());
        assert!(!format!("{entry:?}").contains("private-password"));
    }
    Ok(())
}

#[test]
fn ipv6_nodes_stay_visible_but_cannot_be_saved_as_supported_profiles()
-> Result<(), Box<dyn std::error::Error>> {
    let ipv6 = LINK
        .replace("proxy.example", "[2001:db8::1234]")
        .replace("#Example", "#IPv6 node");
    let body = format!("{LINK}\n{ipv6}");
    for bytes in [body.clone(), STANDARD.encode(&body)] {
        let list = parse_subscription(bytes.as_bytes())?;
        assert_eq!(list.entries().len(), 2);
        assert_eq!(list.supported_count(), 1);
        assert!(list.entries()[0].profile().is_ok());
        assert_eq!(list.entries()[1].name(), "IPv6 node");
        let error = list.entries()[1]
            .profile()
            .err()
            .ok_or("IPv6 node admitted")?;
        assert!(error.contains("IPv4-only"));
        assert!(!error.contains("2001:db8"));
        assert!(!error.contains("12345678-1234"));
    }
    Ok(())
}

#[test]
fn invalid_documents_and_limits_fail_atomically() {
    for input in [
        "",
        "   ",
        "not a subscription",
        "<html>https://example.com</html>",
        "{\"url\":\"https://example.com\"}",
        "proxies:\n  - name: test",
    ] {
        assert!(parse_subscription(input.as_bytes()).is_err());
    }
    assert_eq!(
        parse_subscription(&vec![b'a'; MAX_BYTES + 1]).err(),
        Some(SubscriptionError::TooLarge)
    );
    let excessive = format!("{LINK}\n").repeat(MAX_ENTRIES + 1);
    assert_eq!(
        parse_subscription(excessive.as_bytes()).err(),
        Some(SubscriptionError::TooManyEntries)
    );
    assert!(parse_subscription(format!("{LINK}\nmalformed second record").as_bytes()).is_err());
}

#[test]
fn opaque_yaml_and_embedded_urls_fail_atomically() {
    for line in [
        "proxies: https://example.com",
        "data:text/plain,https://example.com",
        "vless:ignored://proxy.example",
        "vl\tess://proxy.example",
    ] {
        for body in [line.to_owned(), format!("{LINK}\n{line}")] {
            for encoded in [body.clone(), STANDARD.encode(&body)] {
                assert_eq!(
                    parse_subscription(encoded.as_bytes()).err(),
                    Some(SubscriptionError::Format)
                );
            }
        }
    }
    assert!(parse_subscription(LINK.replace("vless://", "VLESS://").as_bytes()).is_ok());
}

#[test]
fn endpoint_policy_rejects_unsafe_schemes_userinfo_and_fragments() {
    assert!(validate_url("https://subscription.example/path?private-token=synthetic").is_ok());
    for url in [
        "http://example.com/list",
        "file:///etc/passwd",
        "https://user:password@example.com",
        "https://example.com/#token",
        "not a URL",
    ] {
        let error = validate_url(url).err();
        assert_eq!(error, Some(SubscriptionError::InvalidUrl));
        assert!(!format!("{error:?}").contains("password"));
    }
}

#[test]
fn missing_names_are_stable_and_match_the_saved_profile() -> Result<(), Box<dyn std::error::Error>>
{
    let body = LINK.split('#').next().ok_or("invalid fixture")?;
    let list = parse_subscription(body.as_bytes())?;
    let entry = &list.entries()[0];
    assert_eq!(entry.name(), "Profile 1");
    assert_eq!(
        entry.profile().map_err(|_| "valid entry rejected")?.name(),
        "Profile 1"
    );
    Ok(())
}

#[test]
fn mixed_tcp_reality_and_websocket_tls_subscriptions_import_all_nodes()
-> Result<(), Box<dyn std::error::Error>> {
    let reality = "vless://12345678-1234-4234-8234-123456789abc@tcp.example:443?encryption=none&type=tcp&security=reality&sni=www.example.com&fp=chrome&pbk=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE&sid=aabb";
    let websocket = "vless://12345678-1234-4234-8234-123456789abd@edge.example:443?encryption=none&type=ws&path=%2Fws&host=cdn.example&security=tls&sni=www.example.com&fp=firefox";
    let body = (0..3)
        .flat_map(|index| {
            [
                format!("{reality}#TCP-{index}"),
                format!("{websocket}#WS-{index}"),
            ]
        })
        .collect::<Vec<_>>()
        .join("\n");
    let subscription = parse_subscription(STANDARD.encode(body).as_bytes())?;
    assert_eq!(subscription.entries().len(), 6);
    assert_eq!(subscription.supported_count(), 6);
    for (index, entry) in subscription.entries().iter().enumerate() {
        let profile = entry
            .profile()
            .map_err(|_| "valid provider-shaped node rejected")?;
        assert!(matches!(
            (profile.node().transport(), index % 2),
            (nm_tunnel_profile::Transport::Tcp, 0)
                | (nm_tunnel_profile::Transport::WebSocket { .. }, 1)
        ));
    }
    Ok(())
}
