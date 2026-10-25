//! Versioned NM setting conversion with an explicit data/secret boundary.
use nm_tunnel_profile::{Profile, SERVICE_TYPE, Security, Transport};
use secrecy::ExposeSecret;
use std::collections::HashMap;
use zbus::zvariant::Value;

/// D-Bus settings contain credentials. Debug output is always redacted.
pub(crate) struct EncodedProfile(HashMap<String, HashMap<String, Value<'static>>>);

impl std::fmt::Debug for EncodedProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EncodedProfile([redacted])")
    }
}

impl EncodedProfile {
    pub(crate) fn values(&self) -> &HashMap<String, HashMap<String, Value<'static>>> {
        &self.0
    }
}

/// Convert validated input to the experimental schema v1 without I/O.
/// UUID credentials appear only in vpn.secrets, never vpn.data. Connection UUIDs
/// are independently generated. Autoconnect is always disabled; IP policy is
/// full-tunnel IPv4 DNS priority excludes other NM DNS servers while activated.
pub(crate) fn encode_profile(profile: &Profile) -> EncodedProfile {
    let draft = profile.fields();
    let mut data = HashMap::<String, String>::from([
        ("schema-version".into(), "1".into()),
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
