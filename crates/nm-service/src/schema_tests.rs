use super::*;
use zbus::zvariant::OwnedValue;

// Exercise public configuration separately from executable secret admission.
fn decode(
    name: String,
    data: &Strings,
    secrets: &Strings,
    allow_missing: bool,
) -> Result<nm_tunnel_schema::Configuration, &'static str> {
    if !allow_missing || secrets.get("uuid").is_some_and(|value| !value.is_empty()) {
        nm_tunnel_schema::decode(name.clone(), data, secrets)?;
    }
    nm_tunnel_schema::decode_configuration(name, data)
}

#[test]
fn private_bypass_is_explicit_and_does_not_widen_a_connected_profile()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = crate::test_support::settings()?;
    let (name, mut data, secrets) = data(&settings)?;
    data.insert("schema-version".into(), "2".into());
    data.insert("lan-bypass".into(), "connected-rfc1918".into());
    let connected = decode(name.clone(), &data, &secrets, true)?;
    assert!(connected.fields().lan_bypass && !connected.fields().private_lan_bypass);
    data.insert("lan-bypass".into(), "private-rfc1918".into());
    let before = data.clone();
    let private = decode(name.clone(), &data, &secrets, true)?;
    assert!(!private.fields().lan_bypass && private.fields().private_lan_bypass);
    assert_eq!(data, before);
    data.insert("schema-version".into(), "1".into());
    assert!(decode(name, &data, &secrets, true).is_err());
    Ok(())
}

#[test]
fn source_policy_is_checked_as_a_whole_and_cannot_be_downgraded_to_legacy()
-> Result<(), Box<dyn std::error::Error>> {
    let source = crate::test_support::source_profile()?;
    let settings = crate::test_support::settings()?;
    let (name, mut data, secrets) = data(&settings)?;
    data.insert("schema-version".into(), "2".into());
    data.insert(
        "source-policy".into(),
        source
            .network()
            .source()
            .ok_or("Missing policy")?
            .as_json()
            .into(),
    );
    let incomplete = data.clone();
    assert!(decode(name.clone(), &data, &secrets, true).is_err());
    assert_eq!(data, incomplete);
    data.insert("dns-interception".into(), "tun-port53".into());
    data.insert("dns-fakeip".into(), "persistent-ipv4-v1".into());
    assert!(
        decode(name.clone(), &data, &secrets, true)?
            .fields()
            .source_policy
            .is_some()
    );
    let valid = data.clone();
    for (key, value) in [
        ("schema-version", "1"),
        ("lan-bypass", "connected-rfc1918"),
        ("source-policy", "{\"version\":99}"),
    ] {
        let mut rejected = valid.clone();
        rejected.insert(key.into(), value.into());
        let before = rejected.clone();
        assert!(decode(name.clone(), &rejected, &secrets, true).is_err());
        assert_eq!(rejected, before);
    }
    Ok(())
}

#[test]
fn saved_ipv6_endpoints_reject_without_mutating_settings_or_secrets()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = crate::test_support::settings()?;
    let (name, mut data, secrets) = data(&settings)?;
    let original_secrets = secrets.clone();
    let original_server = data.get("server").ok_or("Missing fixture server")?.clone();
    for version in ["1", "2"] {
        data.insert("schema-version".into(), version.into());
        if version == "2" {
            data.insert("dns-override".into(), "current-network".into());
        }
        data.insert("server".into(), original_server.clone());
        assert!(decode(name.clone(), &data, &secrets, true).is_ok());
        for server in ["2001:db8::1234", "::ffff:192.0.2.1"] {
            data.insert("server".into(), server.into());
            let before = data.clone();
            assert!(decode(name.clone(), &data, &secrets, true).is_err());
            assert_eq!(data, before);
            assert_eq!(secrets, original_secrets);
        }
    }
    Ok(())
}

#[test]
fn persistent_fakeip_requires_explicit_interception_and_cannot_downgrade_to_v1()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = crate::test_support::settings()?;
    let (name, mut data, secrets) = data(&settings)?;
    let before = data.clone();
    data.insert("dns-fakeip".into(), "persistent-ipv4-v1".into());
    assert!(decode(name.clone(), &data, &secrets, true).is_err());
    data.insert("schema-version".into(), "2".into());
    assert!(decode(name.clone(), &data, &secrets, true).is_err());
    data.insert("dns-interception".into(), "tun-port53".into());
    assert!(
        decode(name.clone(), &data, &secrets, true)?
            .fields()
            .fake_ip
    );
    for unknown in ["true", "memory", "ipv6", "best-effort"] {
        data.insert("dns-fakeip".into(), unknown.into());
        assert!(decode(name.clone(), &data, &secrets, true).is_err());
        assert_eq!(data.get("server"), before.get("server"));
    }
    Ok(())
}

#[test]
fn dns_interception_is_explicit_v2_and_lan_combination_preserves_both_policies()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = crate::test_support::settings()?;
    let (name, mut data, secrets) = data(&settings)?;
    let before = data.clone();
    assert!(
        !decode(name.clone(), &data, &secrets, true)?
            .fields()
            .dns_interception
    );
    data.insert("dns-interception".into(), "tun-port53".into());
    assert!(decode(name.clone(), &data, &secrets, true).is_err());
    data.insert("schema-version".into(), "2".into());
    assert!(
        decode(name.clone(), &data, &secrets, true)?
            .fields()
            .dns_interception
    );
    data.insert("lan-bypass".into(), "connected-rfc1918".into());
    let combined = decode(name.clone(), &data, &secrets, true)?;
    assert!(combined.fields().lan_bypass && combined.fields().dns_interception);
    data.remove("lan-bypass");
    for invalid in ["true", "hijack-dns", "all-protocol-dns", ""] {
        data.insert("dns-interception".into(), invalid.into());
        assert!(decode(name.clone(), &data, &secrets, true).is_err());
        assert_eq!(data.get("server"), before.get("server"));
    }
    data.remove("dns-interception");
    assert!(decode(name, &data, &secrets, true).is_err());
    Ok(())
}

#[test]
fn lan_policy_is_explicit_and_unknown_scope_cannot_be_treated_as_rfc1918()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = crate::test_support::settings()?;
    let (name, mut data, secrets) = data(&settings)?;
    let original = data.clone();
    assert!(
        !decode(name.clone(), &data, &secrets, true)?
            .fields()
            .lan_bypass
    );
    data.insert("lan-bypass".into(), "connected-rfc1918".into());
    assert!(decode(name.clone(), &data, &secrets, true).is_err());
    data.insert("schema-version".into(), "2".into());
    assert!(
        decode(name.clone(), &data, &secrets, true)?
            .fields()
            .lan_bypass
    );
    for value in [
        "true",
        "ip_is_private",
        "0.0.0.0/0",
        "connected-rfc1918,ipv6",
        "",
    ] {
        data.insert("lan-bypass".into(), value.into());
        assert!(decode(name.clone(), &data, &secrets, true).is_err());
        assert_eq!(data.get("server"), original.get("server"));
    }
    data.remove("lan-bypass");
    assert!(decode(name, &data, &secrets, true).is_err());
    Ok(())
}

#[test]
fn resolver_override_is_explicit_v2_policy_and_cannot_downgrade_to_legacy()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = crate::test_support::settings()?;
    let (name, mut data, secrets) = data(&settings)?;
    let before = data.clone();
    data.insert("dns-override".into(), "current-network".into());
    assert!(decode(name.clone(), &data, &secrets, true).is_err());
    data.insert("schema-version".into(), "2".into());
    let profile = decode(name.clone(), &data, &secrets, true)?;
    assert_eq!(
        profile.fields().dns_override,
        nm_tunnel_profile::DnsOverride::CurrentNetwork
    );
    assert_eq!(
        crate::dns::profile_dns(profile.fields().dns_override),
        crate::dns::INTERNAL_DNS
    );
    data.insert("dns-override".into(), "proxy-ipv4:8.8.8.8".into());
    let profile = decode(name.clone(), &data, &secrets, true)?;
    assert_eq!(
        crate::dns::profile_dns(profile.fields().dns_override),
        std::net::Ipv4Addr::new(8, 8, 8, 8)
    );
    for invalid in ["unknown", "proxy-ipv4:192.168.1.1", "proxy-ipv4:::1"] {
        data.insert("dns-override".into(), invalid.into());
        assert!(decode(name.clone(), &data, &secrets, true).is_err());
        assert_eq!(data.get("server"), before.get("server"));
    }
    Ok(())
}

#[test]
fn tcp_policy_requires_schema_v2_and_unknown_rules_cannot_downgrade_to_legacy()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = crate::test_support::settings()?;
    let (name, mut data, secrets) = data(&settings)?;
    let original = data.clone();
    let policy = r#"{"version":1,"rules":[{"domain_suffix":["example"],"action":"block"}]}"#;
    data.insert("tcp-domain-policy".into(), policy.into());
    assert!(decode(name.clone(), &data, &secrets, true).is_err());
    data.insert("schema-version".into(), "2".into());
    let profile = decode(name.clone(), &data, &secrets, true)?;
    assert_eq!(
        profile
            .fields()
            .tcp_domain_policy
            .as_ref()
            .ok_or("missing policy")?
            .action(Some("a.example")),
        nm_tunnel_profile::DomainAction::Block
    );
    data.insert(
        "tcp-domain-policy".into(),
        policy.replace("domain_suffix", "domain_regex"),
    );
    assert!(decode(name.clone(), &data, &secrets, true).is_err());
    assert_eq!(data.get("server"), original.get("server"));
    data.remove("tcp-domain-policy");
    assert!(decode(name, &data, &secrets, true).is_err());
    Ok(())
}

#[test]
fn unsupported_ip_overrides_fail_without_changing_settings()
-> Result<(), Box<dyn std::error::Error>> {
    let mut settings = crate::test_support::settings()?;
    assert!(ip_policy(&settings).is_ok());
    settings
        .get_mut("ipv4")
        .ok_or("Missing IPv4")?
        .insert("dns-priority".into(), OwnedValue::from(0_i32));
    assert!(ip_policy(&settings).is_err());
    settings
        .get_mut("ipv4")
        .ok_or("Missing IPv4")?
        .insert("dns-priority".into(), OwnedValue::from(-100_i32));
    settings
        .get_mut("ipv4")
        .ok_or("Missing IPv4")?
        .insert("never-default".into(), OwnedValue::from(true));
    assert!(ip_policy(&settings).is_err());
    assert_eq!(
        settings
            .get("ipv4")
            .and_then(|v| v.get("never-default"))
            .and_then(|v| bool::try_from(v).ok()),
        Some(true)
    );
    settings
        .get_mut("ipv4")
        .ok_or("Missing IPv4")?
        .remove("never-default");
    settings.get_mut("ipv6").ok_or("Missing IPv6")?.insert(
        "method".into(),
        OwnedValue::from(zbus::zvariant::Str::from("auto")),
    );
    assert!(ip_policy(&settings).is_err());
    Ok(())
}

#[test]
fn missing_secret_is_only_permitted_for_need_secrets_validation()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = crate::test_support::settings()?;
    let (name, data, secrets) = data(&settings)?;
    assert!(decode(name.clone(), &data, &secrets, true).is_ok());
    assert!(decode(name.clone(), &data, &secrets, false).is_err());
    let secrets = Strings::from([("uuid".into(), "12345678-1234-4234-8234-123456789abc".into())]);
    assert!(decode(name, &data, &secrets, false).is_ok());
    Ok(())
}

#[test]
fn unknown_schema_and_credentials_in_data_fail_without_private_diagnostics()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = crate::test_support::settings()?;
    let (name, mut data, secrets) = data(&settings)?;
    let before = data.clone();
    data.insert("schema-version".into(), "999".into());
    assert!(decode(name.clone(), &data, &secrets, true).is_err());
    data = before.clone();
    data.insert("uuid".into(), "private-synthetic-value".into());
    let result = decode(name, &data, &secrets, true);
    assert!(result.is_err());
    assert!(!format!("{result:?}").contains("private-synthetic-value"));
    assert_eq!(data.get("server"), before.get("server"));
    Ok(())
}
