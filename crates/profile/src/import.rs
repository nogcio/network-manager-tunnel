//! URL parsing is delegated to url; this module admits our supported profile subset.
use crate::{Draft, Field, Security, Transport, ValidationError};
use percent_encoding::percent_decode_str;
use secrecy::SecretString;
use std::collections::BTreeMap;

/// Import VLESS TCP + TLS/REALITY (optional Vision), or WebSocket + TLS.
///
/// No fetching, subscription discovery, disk writes or fallback interpretation.
/// Rejects unknown/duplicate parameters and never includes input in errors.
/// A failed import leaves the caller's current draft untouched.
pub fn import_vless(input: &str) -> Result<Draft, ValidationError> {
    let error = |message| ValidationError::new(Field::Link, message);
    if input.len() > 8192 {
        return Err(error("Share link exceeds the 8 KiB import limit."));
    }
    let url =
        url::Url::parse(input.trim()).map_err(|_| error("Enter a valid vless:// share link."))?;
    if url.scheme() != "vless" || url.password().is_some() || !matches!(url.path(), "" | "/") {
        return Err(error(
            "Only a single vless:// share link without a password or path is supported.",
        ));
    }
    let credential = percent_decode_str(url.username())
        .decode_utf8()
        .map_err(|_| error("The link contains invalid credential encoding."))?;
    let server = match url.host() {
        Some(url::Host::Domain(value)) => value.to_owned(),
        Some(url::Host::Ipv4(value)) => value.to_string(),
        Some(url::Host::Ipv6(value)) => value.to_string(),
        None => return Err(error("The link needs a server hostname or IP address.")),
    };
    let mut params = BTreeMap::new();
    for (key, value) in url.query_pairs() {
        if !matches!(
            key.as_ref(),
            "type"
                | "security"
                | "flow"
                | "sni"
                | "fp"
                | "pbk"
                | "sid"
                | "encryption"
                | "alpn"
                | "path"
                | "host"
        ) {
            return Err(error(
                "The link contains an unsupported parameter; it was not imported.",
            ));
        }
        if params
            .insert(key.into_owned(), value.into_owned())
            .is_some()
        {
            return Err(error(
                "The link contains duplicate parameters; it was not imported.",
            ));
        }
    }
    let get = |key: &str| params.get(key).map(String::as_str).unwrap_or("");
    if !matches!(get("encryption"), "" | "none") {
        return Err(error("Only VLESS encryption=none is supported."));
    }
    let transport = match get("type") {
        "" | "tcp" | "raw" => {
            if params.contains_key("host") || params.contains_key("path") {
                return Err(error("TCP does not support WebSocket host/path fields."));
            }
            Transport::Tcp
        }
        "ws" => Transport::WebSocket {
            path: params.get("path").cloned().unwrap_or_else(|| "/".into()),
            host: params.get("host").cloned(),
        },
        _ => {
            return Err(error(
                "Only TCP and TLS-protected WebSocket transports are supported.",
            ));
        }
    };
    let security = match get("security") {
        "tls" => Security::Tls,
        "reality" => Security::Reality,
        _ => {
            return Err(error(
                "The link must explicitly select TLS or REALITY security.",
            ));
        }
    };
    let vision = match get("flow") {
        "" => false,
        "xtls-rprx-vision" => true,
        _ => return Err(error("The link uses an unsupported VLESS flow.")),
    };
    let name = percent_decode_str(url.fragment().unwrap_or("VLESS profile"))
        .decode_utf8()
        .map_err(|_| error("The link contains an invalid profile name."))?
        .into_owned();
    let draft = Draft {
        name,
        server: server.clone(),
        port: url
            .port()
            .ok_or_else(|| error("The link must include a server port."))?
            .to_string(),
        credential: SecretString::from(credential.into_owned()),
        security,
        transport,
        server_name: if get("sni").is_empty() {
            server
        } else {
            get("sni").into()
        },
        fingerprint: if get("fp").is_empty() {
            "chrome".into()
        } else {
            get("fp").into()
        },
        public_key: get("pbk").into(),
        short_id: get("sid").into(),
        vision,
        alpn: get("alpn").into(),
    };
    draft
        .validate()
        .map_err(|_| error("The link contains invalid or incomplete profile fields."))?;
    Ok(draft)
}
