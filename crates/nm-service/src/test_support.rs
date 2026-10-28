//! Synthetic dictionaries for private schema/authorization contracts.
use crate::schema::{Settings, Strings};
use std::collections::HashMap;
use zbus::zvariant::{OwnedValue, Str, Value};

pub(crate) fn source_profile() -> std::io::Result<nm_tunnel_profile::Profile> {
    let domains = r#"{"version":1,"rules":[{"domain_suffix":["direct.example"],"action":"direct"},{"domain":["blocked.example"],"action":"block"},{"domain":["proxied.example"],"action":"proxy"}]}"#;
    let policy = serde_json::json!({"version":1,
        "dns":{"address":"1.1.1.1","port":853,"transport":"tls","via_proxy":true,"tls_name":"1.1.1.1"},
        "domain_policy":domains,"fakeip_range":"198.18.0.0/15","tun_address":"172.19.0.1","tun_prefix":30,"mtu":1400});
    let mut draft = nm_tunnel_profile::import_vless("vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example").map_err(std::io::Error::other)?;
    draft.source_policy = Some(
        nm_tunnel_profile::SourcePolicy::from_json(&policy.to_string())
            .map_err(std::io::Error::other)?,
    );
    draft.fake_ip = true;
    draft.dns_interception = true;
    draft
        .validate()
        .map_err(|_| std::io::Error::other("Invalid source fixture."))
}

pub(crate) fn settings() -> Result<Settings, Box<dyn std::error::Error>> {
    let data: Strings = [
        ("schema-version", "1"),
        ("protocol", "vless"),
        ("server", "proxy.example"),
        ("port", "443"),
        ("transport", "tcp"),
        ("security", "tls"),
        ("server-name", "certificate.example"),
        ("fingerprint", "chrome"),
        ("flow", ""),
        ("alpn", ""),
        ("uuid-flags", "0"),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    Ok(HashMap::from([
        (
            "ipv4".into(),
            HashMap::from([
                ("method".into(), OwnedValue::from(Str::from("auto"))),
                ("dns-priority".into(), OwnedValue::from(-100_i32)),
                (
                    "dns-search".into(),
                    OwnedValue::try_from(Value::from(vec!["~.".to_owned()]))?,
                ),
            ]),
        ),
        (
            "ipv6".into(),
            HashMap::from([("method".into(), OwnedValue::from(Str::from("disabled")))]),
        ),
        (
            "connection".into(),
            HashMap::from([
                ("id".into(), OwnedValue::from(Str::from("Synthetic"))),
                ("type".into(), OwnedValue::from(Str::from("vpn"))),
            ]),
        ),
        (
            "vpn".into(),
            HashMap::from([
                (
                    "service-type".into(),
                    OwnedValue::from(Str::from(nm_tunnel_profile::SERVICE_TYPE)),
                ),
                ("data".into(), OwnedValue::try_from(Value::from(data))?),
            ]),
        ),
    ]))
}
