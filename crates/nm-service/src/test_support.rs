//! Synthetic dictionaries for private schema/authorization contracts.
use crate::schema::{Settings, Strings};
use std::collections::HashMap;
use zbus::zvariant::{OwnedValue, Str, Value};

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
