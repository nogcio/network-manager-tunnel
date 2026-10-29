//! Cross-boundary schema contracts: writer, observer and service admission agree.
use nm_tunnel_profile::{DnsOverride, Profile};
use nm_tunnel_schema::{
    Settings, Strings, data, decode, decode_configuration, decode_policy, encode_profile,
};

fn settings(profile: &Profile) -> Result<Settings, Box<dyn std::error::Error>> {
    encode_profile(profile)
        .values()
        .iter()
        .map(|(section, values)| {
            let values = values
                .iter()
                .map(|(key, value)| Ok((key.clone(), value.try_to_owned()?)))
                .collect::<Result<_, Box<dyn std::error::Error>>>()?;
            Ok((section.clone(), values))
        })
        .collect()
}

fn draft() -> Result<nm_tunnel_profile::Draft, Box<dyn std::error::Error>> {
    Ok(nm_tunnel_profile::import_vless(
        "vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example#Synthetic",
    )?)
}

#[test]
fn supported_policy_modes_round_trip_without_schema_or_secret_loss()
-> Result<(), Box<dyn std::error::Error>> {
    let plain = draft()?;
    let mut connected = plain.clone();
    connected.lan_bypass = true;
    connected.dns_interception = true;
    let mut private = plain.clone();
    private.private_lan_bypass = true;
    private.dns_interception = true;
    private.fake_ip = true;
    let mut network_dns = plain.clone();
    network_dns.dns_override = DnsOverride::CurrentNetwork;
    let mut manual_dns = plain.clone();
    manual_dns.dns_override = DnsOverride::ProxyIpv4("8.8.8.8".parse()?);
    for draft in [plain, connected, private, network_dns, manual_dns] {
        let profile = draft.validate().map_err(|_| "Invalid fixture")?;
        let (name, original, secrets) = data(&settings(&profile)?)?;
        let decoded = decode(name.clone(), &original, &secrets)?;
        let configuration = decode_configuration(name, &original)?;
        let observed = decode_policy(&original)?;
        let (_, encoded, encoded_secrets) = data(&settings(&decoded)?)?;
        assert_eq!(encoded, original);
        assert_eq!(encoded_secrets, secrets);
        assert_eq!(
            configuration.fields().dns_override,
            decoded.network().dns_override()
        );
        assert_eq!(observed.lan_bypass(), decoded.lan_bypass());
        assert!(!format!("{configuration:?} {observed:?}").contains("peer.example"));
    }
    Ok(())
}

#[test]
fn source_versions_survive_writer_observer_and_service_admission_without_policy_loss()
-> Result<(), Box<dyn std::error::Error>> {
    use nm_tunnel_profile::{DomainAction, SourceDnsSelection, SourcePolicy};
    let domain =
        r#""{\"version\":1,\"rules\":[{\"domain\":[\"direct.example\"],\"action\":\"direct\"}]}""#;
    let routes = r#""{\"version\":1,\"rules\":[{\"condition\":{\"type\":\"match\",\"ip_cidr\":[\"203.0.113.0/24\"],\"ports\":[[443,443]]},\"action\":\"block\"}]}""#;
    let dns_rules = r#", "dns_policy":{"version":1,"resolvers":[{"type":"current_network"}],"rules":[{"domain_suffix":["work.example"],"resolver":0}]}"#;
    for (version, field, routing, dns) in [
        (1, "domain_policy", domain, ""),
        (2, "route_policy", routes, ""),
        (3, "domain_policy", domain, dns_rules),
        (3, "route_policy", routes, dns_rules),
    ] {
        let source = format!(
            r#"{{
            "version":{version},
            "dns":{{"address":"1.1.1.1","port":853,"transport":"tls","via_proxy":true,"tls_name":"1.1.1.1"}},
            "{field}":{routing},
            "fakeip_range":"198.18.0.0/15","tun_address":"172.19.0.1","tun_prefix":30,"mtu":1400
            {dns}
        }}"#
        );
        let policy = SourcePolicy::from_json(&source)?;
        let mut draft = draft()?;
        draft.source_policy = Some(policy.clone());
        draft.fake_ip = true;
        draft.dns_interception = true;
        let profile = draft.validate().map_err(|_| "Invalid fixture")?;
        let (name, values, secrets) = data(&settings(&profile)?)?;
        assert_eq!(values["schema-version"], "2");
        assert_eq!(values["source-policy"], policy.as_json());
        assert!(
            !values
                .values()
                .any(|value| value.contains("12345678-1234-4234-8234-123456789abc"))
        );
        let executable = decode(name.clone(), &values, &secrets)?;
        let configuration = decode_configuration(name.clone(), &values)?;
        let observed = decode_policy(&values)?;
        for decoded in [
            executable.network().source().ok_or("Executable policy")?,
            configuration
                .fields()
                .source_policy
                .as_ref()
                .ok_or("Public policy")?,
            observed.source().ok_or("Observed policy")?,
        ] {
            assert_eq!(decoded.as_json(), policy.as_json());
            assert_eq!(
                decoded.action(None, "203.0.113.2:443".parse()?, false),
                if field == "route_policy" {
                    DomainAction::Block
                } else {
                    DomainAction::Proxy
                }
            );
            assert_eq!(
                matches!(
                    decoded.dns_for("sub.work.example")?,
                    SourceDnsSelection::CurrentNetwork {}
                ),
                version == 3
            );
        }
        let (_, encoded, encoded_secrets) = data(&settings(&executable)?)?;
        assert_eq!(encoded, values);
        assert_eq!(encoded_secrets, secrets);
        for (key, value) in [
            ("schema-version", "1"),
            ("dns-fakeip", "off"),
            ("source-policy", "{\"version\":99}"),
        ] {
            let mut invalid = values.clone();
            invalid.insert(key.into(), value.into());
            let before = invalid.clone();
            assert!(decode(name.clone(), &invalid, &secrets).is_err());
            assert!(decode_configuration(name.clone(), &invalid).is_err());
            assert!(decode_policy(&invalid).is_err());
            assert_eq!(invalid, before);
        }
    }
    Ok(())
}

#[test]
fn public_configuration_never_manufactures_an_executable_credential()
-> Result<(), Box<dyn std::error::Error>> {
    use secrecy::ExposeSecret;
    let profile = draft()?.validate().map_err(|_| "Invalid fixture")?;
    let (name, values, _) = data(&settings(&profile)?)?;
    let before = values.clone();
    let public = decode_configuration(name.clone(), &values)?;
    assert!(public.fields().credential.expose_secret().is_empty());
    assert!(public.fields().validate().is_err());
    for secrets in [
        Strings::new(),
        Strings::from([("uuid".into(), "private-invalid-credential".into())]),
        Strings::from([("unknown".into(), "private-value".into())]),
    ] {
        let original = secrets.clone();
        let result = decode(name.clone(), &values, &secrets);
        assert!(result.is_err());
        assert!(!format!("{result:?}").contains("private-"));
        assert_eq!(secrets, original);
        assert_eq!(values, before);
    }
    Ok(())
}

#[test]
fn metadata_and_service_reject_the_same_contradictory_network_modes()
-> Result<(), Box<dyn std::error::Error>> {
    let profile = draft()?.validate().map_err(|_| "Invalid fixture")?;
    let (name, base, secrets) = data(&settings(&profile)?)?;
    for additions in [
        vec![("dns-fakeip", "persistent-ipv4-v1")],
        vec![
            ("lan-bypass", "private-rfc1918"),
            (
                "tcp-domain-policy",
                r#"{"version":1,"rules":[{"domain":["direct.example"],"action":"direct"}]}"#,
            ),
        ],
        vec![
            ("dns-override", "proxy-ipv4:8.8.8.8"),
            (
                "tcp-domain-policy",
                r#"{"version":1,"rules":[{"domain":["direct.example"],"action":"direct"}]}"#,
            ),
        ],
    ] {
        let mut values = base.clone();
        values.insert("schema-version".into(), "2".into());
        for (key, value) in additions {
            values.insert(key.into(), value.into());
        }
        let before = values.clone();
        assert!(decode_policy(&values).is_err());
        assert!(decode_configuration(name.clone(), &values).is_err());
        assert!(decode(name.clone(), &values, &secrets).is_err());
        assert_eq!(values, before);
    }
    Ok(())
}

#[test]
fn narrow_edits_preserve_protocol_identity_and_reject_secret_or_source_downgrades()
-> Result<(), Box<dyn std::error::Error>> {
    use nm_tunnel_schema::{LanBypass, ProfileChanges};
    let profile = draft()?.validate().map_err(|_| "Invalid fixture")?;
    let mut current = settings(&profile)?;
    let changes = ProfileChanges {
        name: "Renamed".into(),
        dns: DnsOverride::CurrentNetwork,
        lan: LanBypass::Connected,
        intercept: true,
        fake_ip: false,
    };
    assert!(
        changes.apply(current.clone()).is_err(),
        "secret-bearing inputs are never echoed in an edit"
    );
    current
        .get_mut("vpn")
        .ok_or("Missing VPN")?
        .remove("secrets");
    let before = current.clone();
    let edited = changes.apply(current.clone())?;
    let (name, values, secrets) = data(&edited)?;
    assert_eq!(name, "Renamed");
    assert!(secrets.is_empty());
    assert_eq!(values["server"], "proxy.example");
    assert_eq!(edited["connection"]["uuid"], before["connection"]["uuid"]);
    assert_eq!(edited["ipv4"], before["ipv4"]);
    assert_eq!(edited["ipv6"], before["ipv6"]);
    assert!(!format!("{changes:?}").contains("Renamed"));
    assert_eq!(current, before);
    let mut source = draft()?;
    source.dns_interception = true;
    source.fake_ip = true;
    source.source_policy = Some(nm_tunnel_profile::SourcePolicy::from_json(
        r#"{"version":1,"dns":{"address":"1.1.1.1","port":853,"transport":"tls","via_proxy":true,"tls_name":"1.1.1.1"},"domain_policy":"{\"version\":1,\"rules\":[{\"domain_suffix\":[\"direct.example\"],\"action\":\"direct\"}]}","fakeip_range":"198.18.0.0/15","tun_address":"172.19.0.1","tun_prefix":30,"mtu":1400}"#,
    )?);
    let source = source.validate().map_err(|_| "Invalid source")?;
    let mut current = settings(&source)?;
    current
        .get_mut("vpn")
        .ok_or("Missing VPN")?
        .remove("secrets");
    let before = current.clone();
    let mut changes = changes;
    changes.lan = LanBypass::None;
    assert!(changes.apply(current.clone()).is_err());
    changes.fake_ip = true;
    assert!(changes.apply(current.clone()).is_ok());
    changes.intercept = false;
    assert!(changes.apply(current.clone()).is_err());
    assert_eq!(current, before);
    Ok(())
}
