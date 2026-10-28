//! Fail-closed versioned decoding. Raw NM dictionaries and secrets are never logged.
use nm_tunnel_profile::{Draft, Profile, SERVICE_TYPE, Security, Transport};
use std::collections::HashMap;
use zbus::zvariant::OwnedValue;

/// NM settings dictionary. May contain secrets; never log it.
pub type Settings = HashMap<String, HashMap<String, OwnedValue>>;
/// VPN data or secrets dictionary. The caller owns its privacy and lifetime.
pub type Strings = HashMap<String, String>;

/// Reject IP policy this experimental full-tunnel runtime cannot honor.
/// Runs before lifecycle state changes, TUN creation or firewall setup.
pub fn ip_policy(settings: &Settings) -> Result<(), &'static str> {
    let ip4 = settings
        .get("ipv4")
        .ok_or("IPv4 full-tunnel settings are required.")?;
    let ip6 = settings
        .get("ipv6")
        .ok_or("Explicitly disabled IPv6 is required.")?;
    let text = |section: &HashMap<String, OwnedValue>, key: &str| {
        section
            .get(key)
            .and_then(|v| <&str>::try_from(v).ok())
            .map(str::to_owned)
    };
    if text(ip4, "method").as_deref() != Some("auto")
        || text(ip6, "method").as_deref() != Some("disabled")
        || !ip4
            .get("dns-priority")
            .and_then(|v| i32::try_from(v).ok())
            .is_some_and(|v| v < 0)
    {
        return Err("Only full-tunnel IPv4 with exclusive DNS and disabled IPv6 is supported.");
    }
    let domains = ip4
        .get("dns-search")
        .and_then(|v| v.try_clone().ok())
        .and_then(|v| Vec::<String>::try_from(v).ok());
    if domains.as_deref() != Some(&["~.".to_owned()]) {
        return Err("The full-tunnel DNS routing domain is required.");
    }
    for key in ["never-default", "ignore-auto-dns", "ignore-auto-routes"] {
        if ip4
            .get(key)
            .is_some_and(|v| bool::try_from(v).ok() != Some(false))
        {
            return Err("Unsupported IPv4 override.");
        }
    }
    for key in [
        "addresses",
        "address-data",
        "routes",
        "route-data",
        "routing-rules",
        "dns",
        "dns-data",
        "dns-options",
    ] {
        if ip4
            .get(key)
            .is_some_and(|v| !matches!(&**v, zbus::zvariant::Value::Array(a) if a.is_empty()))
        {
            return Err("Custom addresses, routes and DNS are not supported.");
        }
    }
    if text(ip4, "gateway").is_some_and(|v| !v.is_empty())
        || ip4
            .get("route-table")
            .is_some_and(|v| u32::try_from(v).ok() != Some(0))
        || ip4
            .get("route-metric")
            .is_some_and(|v| i64::try_from(v).ok() != Some(-1))
    {
        return Err("Custom IPv4 gateway, table and metric are not supported.");
    }
    Ok(())
}

/// Extract this service's bounded VPN dictionaries without I/O or source mutation.
/// Errors are static and never contain imported settings or credentials.
pub fn data(settings: &Settings) -> Result<(String, Strings, Strings), &'static str> {
    if settings.len() > 16 || settings.values().any(|section| section.len() > 64) {
        return Err("Oversized settings.");
    }
    let connection = settings
        .get("connection")
        .ok_or("Missing connection settings.")?;
    if connection
        .get("type")
        .and_then(|v| <&str>::try_from(v).ok())
        != Some("vpn")
    {
        return Err("Wrong connection type.");
    }
    let name = connection
        .get("id")
        .and_then(|v| <&str>::try_from(v).ok())
        .ok_or("Missing name.")?
        .to_owned();
    let vpn = settings.get("vpn").ok_or("Missing VPN settings.")?;
    if vpn
        .get("service-type")
        .and_then(|v| <&str>::try_from(v).ok())
        != Some(SERVICE_TYPE)
    {
        return Err("Wrong VPN service.");
    }
    let data = Strings::try_from(
        vpn.get("data")
            .ok_or("Missing VPN data.")?
            .try_clone()
            .map_err(|_| "Invalid data.")?,
    )
    .map_err(|_| "Invalid data map.")?;
    let secrets = vpn
        .get("secrets")
        .map(|v| {
            v.try_clone()
                .map_err(|_| "Invalid secrets.")
                .and_then(|v| Strings::try_from(v).map_err(|_| "Invalid secrets map."))
        })
        .transpose()?
        .unwrap_or_default();
    Ok((name, data, secrets))
}

/// Non-secret checked configuration. It is not an authenticated executable profile.
/// Debug is redacted; credential availability is checked separately by [`decode`].
#[derive(Clone, Debug)]
pub struct Configuration(Draft);

impl Configuration {
    /// Borrow checked fields; the credential is empty in this non-secret projection.
    pub fn fields(&self) -> &Draft {
        &self.0
    }
}

/// Decode executable settings with a mandatory, validated credential.
/// Errors are static; input dictionaries are never changed.
pub fn decode(name: String, data: &Strings, secrets: &Strings) -> Result<Profile, &'static str> {
    if secrets.len() != 1
        || secrets.keys().any(|key| key != "uuid")
        || secrets.values().any(|value| value.len() > 128)
    {
        return Err("The VLESS secret is required.");
    }
    let mut draft = decode_configuration(name, data)?.0;
    draft.credential = secrets
        .get("uuid")
        .ok_or("The VLESS secret is required.")?
        .clone()
        .into();
    draft.validate().map_err(|_| "Invalid VPN profile.")
}

/// Validate public configuration without manufacturing authentication material.
/// No secret lookup, I/O, resource allocation or source mutation occurs.
pub fn decode_configuration(name: String, data: &Strings) -> Result<Configuration, &'static str> {
    const KEYS: &[&str] = &[
        "schema-version",
        "protocol",
        "server",
        "port",
        "transport",
        "security",
        "server-name",
        "fingerprint",
        "flow",
        "alpn",
        "uuid-flags",
        "public-key",
        "short-id",
        "websocket-path",
        "websocket-host",
        "tcp-domain-policy",
        "dns-override",
        "lan-bypass",
        "dns-interception",
        "dns-fakeip",
        "source-policy",
    ];
    if data.len() > KEYS.len()
        || data.keys().any(|k| !KEYS.contains(&k.as_str()))
        || data.iter().any(|(key, value)| {
            value.len()
                > if matches!(key.as_str(), "tcp-domain-policy" | "source-policy") {
                    nm_tunnel_profile::MAX_POLICY_BYTES
                } else {
                    2048
                }
        })
    {
        return Err("Unknown or oversized VPN settings.");
    }
    let required = |key: &str| {
        data.get(key)
            .map(String::as_str)
            .ok_or("Missing VPN field.")
    };
    let policy = crate::decode_policy(data)?;
    if required("protocol")? != "vless" || !matches!(required("uuid-flags")?, "0" | "1" | "2") {
        return Err("Unsupported schema, protocol or secret flags.");
    }
    let security = match required("security")? {
        "tls" => Security::Tls,
        "reality" => Security::Reality,
        _ => return Err("Unsupported security."),
    };
    let transport = match required("transport")? {
        "tcp" if !data.contains_key("websocket-path") && !data.contains_key("websocket-host") => {
            Transport::Tcp
        }
        "ws" => Transport::WebSocket {
            path: required("websocket-path")?.into(),
            host: data.get("websocket-host").cloned(),
        },
        _ => return Err("Unsupported transport fields."),
    };
    let vision = match required("flow")? {
        "" => false,
        "xtls-rprx-vision" => true,
        _ => return Err("Unsupported flow."),
    };
    if security == Security::Tls
        && (data.contains_key("public-key") || data.contains_key("short-id"))
    {
        return Err("Unexpected REALITY fields.");
    }
    let mut draft = Draft {
        name,
        server: required("server")?.into(),
        port: required("port")?.into(),
        credential: String::new().into(),
        security,
        transport,
        server_name: required("server-name")?.into(),
        fingerprint: required("fingerprint")?.into(),
        public_key: data.get("public-key").cloned().unwrap_or_default(),
        short_id: data.get("short-id").cloned().unwrap_or_default(),
        vision,
        alpn: required("alpn")?.into(),
        ..Draft::default()
    };
    policy.apply_to(&mut draft);
    draft
        .validate_configuration()
        .map_err(|_| "Invalid VPN profile.")?;
    Ok(Configuration(draft))
}
