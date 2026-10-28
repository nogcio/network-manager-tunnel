//! Versioned NM setting conversion with an explicit data/secret boundary.
use nm_tunnel_profile::{Profile, SERVICE_TYPE, Security, Transport};
use secrecy::ExposeSecret;
use std::collections::HashMap;
use zbus::zvariant::Value;

/// D-Bus settings contain credentials. Debug output is always redacted.
pub struct EncodedProfile(HashMap<String, HashMap<String, Value<'static>>>);

impl std::fmt::Debug for EncodedProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EncodedProfile([redacted])")
    }
}

impl EncodedProfile {
    /// Borrow serialized settings, including credentials in `vpn.secrets`.
    /// The dictionary must never be logged or used as diagnostic context.
    pub fn values(&self) -> &HashMap<String, HashMap<String, Value<'static>>> {
        &self.0
    }
}

/// Convert validated input to experimental NM schema v1/v2 without I/O.
/// UUID credentials appear only in vpn.secrets, never vpn.data. Connection UUIDs
/// are independently generated. Autoconnect is always disabled; IP policy is
/// full-tunnel IPv4 DNS priority excludes other NM DNS servers while activated.
pub fn encode_profile(profile: &Profile) -> EncodedProfile {
    let draft = profile.to_draft();
    let mut data = HashMap::<String, String>::from([
        (
            "schema-version".into(),
            if draft.tcp_domain_policy.is_some()
                || draft.dns_override != nm_tunnel_profile::DnsOverride::Inherit
                || draft.lan_bypass
                || draft.private_lan_bypass
                || draft.dns_interception
                || draft.fake_ip
                || draft.source_policy.is_some()
            {
                "2"
            } else {
                "1"
            }
            .into(),
        ),
        ("protocol".into(), "vless".into()),
        ("server".into(), draft.server.clone()),
        ("port".into(), draft.port.clone()),
        (
            "transport".into(),
            match draft.transport {
                Transport::Tcp => "tcp",
                Transport::WebSocket { .. } => "ws",
            }
            .into(),
        ),
        (
            "security".into(),
            match draft.security {
                Security::Tls => "tls",
                Security::Reality => "reality",
            }
            .into(),
        ),
        ("server-name".into(), draft.server_name.clone()),
        ("fingerprint".into(), draft.fingerprint.clone()),
        (
            "flow".into(),
            if draft.vision { "xtls-rprx-vision" } else { "" }.into(),
        ),
        ("alpn".into(), draft.alpn.clone()),
        // NM secret flags: NONE = stored by the settings service, not agent-owned.
        ("uuid-flags".into(), "0".into()),
    ]);
    if let Some(policy) = &draft.tcp_domain_policy {
        data.insert("tcp-domain-policy".into(), policy.as_json().into());
    }
    if let Some(value) = draft.dns_override.to_nm() {
        data.insert("dns-override".into(), value);
    }
    if draft.lan_bypass {
        data.insert("lan-bypass".into(), "connected-rfc1918".into());
    }
    if draft.private_lan_bypass {
        data.insert("lan-bypass".into(), "private-rfc1918".into());
    }
    if draft.dns_interception {
        data.insert("dns-interception".into(), "tun-port53".into());
    }
    if draft.fake_ip {
        data.insert("dns-fakeip".into(), "persistent-ipv4-v1".into());
    }
    if let Some(policy) = &draft.source_policy {
        data.insert("source-policy".into(), policy.as_json().into());
    }
    if draft.security == Security::Reality {
        data.insert("public-key".into(), draft.public_key.clone());
        data.insert("short-id".into(), draft.short_id.clone());
    }
    if let Transport::WebSocket { path, host } = &draft.transport {
        data.insert("websocket-path".into(), path.clone());
        if let Some(host) = host {
            data.insert("websocket-host".into(), host.clone());
        }
    }
    let secrets =
        HashMap::<String, String>::from([("uuid".into(), draft.credential.expose_secret().into())]);
    let connection = HashMap::from([
        ("id".into(), Value::from(draft.name.clone())),
        ("uuid".into(), Value::from(uuid::Uuid::new_v4().to_string())),
        ("type".into(), Value::from("vpn".to_owned())),
        ("autoconnect".into(), Value::from(false)),
    ]);
    let vpn = HashMap::from([
        ("service-type".into(), Value::from(SERVICE_TYPE.to_owned())),
        ("data".into(), Value::from(data)),
        ("secrets".into(), Value::from(secrets)),
    ]);
    EncodedProfile(HashMap::from([
        ("connection".into(), connection),
        ("vpn".into(), vpn),
        (
            "ipv4".into(),
            HashMap::from([
                ("method".into(), Value::from("auto")),
                ("dns-priority".into(), Value::from(-100_i32)),
                ("dns-search".into(), Value::from(vec!["~.".to_owned()])),
            ]),
        ),
        (
            "ipv6".into(),
            HashMap::from([("method".into(), Value::from("disabled"))]),
        ),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_dns_interception_alone_selects_v2_without_an_upstream_snapshot()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut draft = nm_tunnel_profile::import_vless(
            "vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example",
        )?;
        draft.dns_interception = true;
        let encoded = encode_profile(&draft.validate().map_err(|_| "invalid fixture")?);
        let data =
            HashMap::<String, String>::try_from(encoded.values()["vpn"]["data"].try_clone()?)?;
        assert_eq!(data.get("schema-version").map(String::as_str), Some("2"));
        assert_eq!(
            data.get("dns-interception").map(String::as_str),
            Some("tun-port53")
        );
        assert!(!data.contains_key("dns-override"));
        assert!(!data.contains_key("lan-bypass"));
        assert!(!data.values().any(|value| value.contains("192.168.")));
        Ok(())
    }

    #[test]
    fn lan_bypass_alone_uses_v2_without_storing_network_addresses()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut draft = nm_tunnel_profile::import_vless(
            "vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example",
        )?;
        draft.lan_bypass = true;
        let encoded = encode_profile(&draft.validate().map_err(|_| "invalid fixture")?);
        let data =
            HashMap::<String, String>::try_from(encoded.values()["vpn"]["data"].try_clone()?)?;
        assert_eq!(data.get("schema-version").map(String::as_str), Some("2"));
        assert_eq!(
            data.get("lan-bypass").map(String::as_str),
            Some("connected-rfc1918")
        );
        assert!(!data.contains_key("dns-override"));
        assert!(!data.values().any(|value| value.contains("192.168.")));
        assert!(!encoded.values()["ipv4"].contains_key("routes"));
        Ok(())
    }

    #[test]
    fn all_private_bypass_has_a_distinct_persisted_mode_without_network_snapshots()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut draft = nm_tunnel_profile::import_vless(
            "vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example",
        )?;
        draft.private_lan_bypass = true;
        let profile = draft.validate().map_err(|_| "Invalid fixture")?;
        let encoded = encode_profile(&profile);
        let data =
            HashMap::<String, String>::try_from(encoded.values()["vpn"]["data"].try_clone()?)?;
        assert_eq!(data["schema-version"], "2");
        assert_eq!(data["lan-bypass"], "private-rfc1918");
        assert!(!data.values().any(|v| v.contains("10.2.2")));
        draft.lan_bypass = true;
        assert!(draft.validate().is_err());
        Ok(())
    }

    #[test]
    fn dns_override_is_saved_per_profile_without_saving_a_dhcp_resolver_address()
    -> Result<(), Box<dyn std::error::Error>> {
        for mode in [
            nm_tunnel_profile::DnsOverride::CurrentNetwork,
            nm_tunnel_profile::DnsOverride::ProxyIpv4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
        ] {
            let mut draft = nm_tunnel_profile::import_vless(
                "vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example",
            )?;
            draft.dns_override = mode;
            let profile = draft.validate().map_err(|_| "Invalid DNS fixture")?;
            let encoded = encode_profile(&profile);
            let data =
                HashMap::<String, String>::try_from(encoded.values()["vpn"]["data"].try_clone()?)?;
            assert_eq!(data.get("schema-version").map(String::as_str), Some("2"));
            assert_eq!(data.get("dns-override"), mode.to_nm().as_ref());
            assert!(!data.contains_key("tcp-domain-policy"));
            assert!(!data.values().any(|value| value.contains("12345678-1234")));
            if mode == nm_tunnel_profile::DnsOverride::CurrentNetwork {
                assert!(!data.values().any(|value| value.contains("192.168.")));
            }
        }
        Ok(())
    }

    #[test]
    fn tcp_policy_uses_v2_without_putting_credentials_in_policy_data()
    -> Result<(), Box<dyn std::error::Error>> {
        let credential = "12345678-1234-4234-8234-123456789abc";
        let mut draft = nm_tunnel_profile::import_vless(&format!(
            "vless://{credential}@proxy.example:443?security=tls&sni=www.example.com#Test"
        ))?;
        let legacy = encode_profile(&draft.validate().map_err(|_| "Invalid fixture")?);
        let legacy_data =
            HashMap::<String, String>::try_from(legacy.values()["vpn"]["data"].try_clone()?)?;
        assert_eq!(
            legacy_data.get("schema-version").map(String::as_str),
            Some("1")
        );
        assert!(!legacy_data.contains_key("tcp-domain-policy"));
        let policy = nm_tunnel_profile::TcpDomainPolicy::from_json(
            r#"{"version":1,"rules":[{"domain_suffix":["direct.example"],"action":"direct"}]}"#,
        )?;
        draft.tcp_domain_policy = Some(policy.clone());
        let encoded = encode_profile(&draft.validate().map_err(|_| "Invalid fixture")?);
        let data =
            HashMap::<String, String>::try_from(encoded.values()["vpn"]["data"].try_clone()?)?;
        assert_eq!(data.get("schema-version").map(String::as_str), Some("2"));
        assert_eq!(
            data.get("tcp-domain-policy").map(String::as_str),
            Some(policy.as_json())
        );
        assert!(!data.values().any(|value| value.contains(credential)));
        assert!(!format!("{encoded:?}").contains("direct.example"));
        assert_eq!(
            bool::try_from(&encoded.values()["connection"]["autoconnect"]),
            Ok(false)
        );
        Ok(())
    }

    #[test]
    fn credentials_are_separate_from_data_and_autoconnect_is_disabled()
    -> Result<(), Box<dyn std::error::Error>> {
        let credential = "12345678-1234-4234-8234-123456789abc";
        let draft = nm_tunnel_profile::import_vless(&format!(
            "vless://{credential}@proxy.example:443?security=tls&sni=www.example.com#Test"
        ))?;
        let profile = draft.validate().map_err(|_| "invalid fixture")?;
        let encoded = encode_profile(&profile);
        let settings = encoded.values();
        let data = HashMap::<String, String>::try_from(settings["vpn"]["data"].try_clone()?)?;
        let secrets = HashMap::<String, String>::try_from(settings["vpn"]["secrets"].try_clone()?)?;
        assert!(!data.values().any(|value| value.contains(credential)));
        assert!(!data.contains_key("uuid"));
        assert_eq!(secrets.get("uuid").map(String::as_str), Some(credential));
        assert_eq!(data.get("uuid-flags").map(String::as_str), Some("0"));
        assert_eq!(data.get("schema-version").map(String::as_str), Some("1"));
        assert_eq!(
            bool::try_from(&settings["connection"]["autoconnect"]),
            Ok(false)
        );
        assert_ne!(
            <&str>::try_from(&settings["connection"]["uuid"])?,
            credential
        );
        assert!(!format!("{encoded:?}").contains(credential));
        Ok(())
    }

    #[test]
    fn websocket_route_and_host_survive_nm_conversion() -> Result<(), Box<dyn std::error::Error>> {
        let draft = nm_tunnel_profile::import_vless(
            "vless://12345678-1234-4234-8234-123456789abc@edge.example:443?type=ws&security=tls&sni=certificate.example&path=%2Fws&host=cdn.example&fp=firefox#WebSocket",
        )?;
        let profile = draft.validate().map_err(|_| "invalid fixture")?;
        let encoded = encode_profile(&profile);
        let data =
            HashMap::<String, String>::try_from(encoded.values()["vpn"]["data"].try_clone()?)?;
        for (key, expected) in [
            ("transport", "ws"),
            ("websocket-path", "/ws"),
            ("websocket-host", "cdn.example"),
            ("server-name", "certificate.example"),
            ("fingerprint", "firefox"),
        ] {
            assert_eq!(data.get(key).map(String::as_str), Some(expected));
        }
        assert!(!data.contains_key("uuid"));
        Ok(())
    }
}
