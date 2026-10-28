//! Checked VLESS nodes and one native selector; no foreign runtime is launched.
use super::{PolicyIssue, value::*};
use nm_tunnel_profile::{Draft, Profile, Security, Transport};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
const ISSUE: PolicyIssue = PolicyIssue::Configuration;

pub(super) struct Outbounds {
    pub proxy: String,
    pub direct: String,
    pub block: String,
    pub nodes: Vec<(String, Draft)>,
}

pub(super) fn parse(values: &[Value]) -> Result<Outbounds, PolicyIssue> {
    let mut tags = HashSet::new();
    let mut nodes = HashMap::new();
    let mut selector = None;
    let mut direct = None;
    let mut block = None;
    for value in values {
        let map = value.as_object().ok_or(ISSUE)?;
        let tag = text(map, "tag", ISSUE)?;
        if !label(tag) || !tags.insert(tag.to_owned()) {
            return Err(ISSUE);
        }
        match text(map, "type", ISSUE)? {
            "selector" => {
                object(
                    value,
                    &[
                        "type",
                        "tag",
                        "outbounds",
                        "default",
                        "interrupt_exist_connections",
                    ],
                    ISSUE,
                )?;
                if selector.is_some() {
                    return Err(ISSUE);
                }
                let entries = strings(map.get("outbounds").ok_or(ISSUE)?, ISSUE)?;
                let default = optional_text(map, "default", ISSUE)?;
                if entries.is_empty()
                    || entries.iter().collect::<HashSet<_>>().len() != entries.len()
                    || (!default.is_empty() && !entries.iter().any(|tag| tag == default))
                {
                    return Err(ISSUE);
                }
                flag(map, "interrupt_exist_connections", false, ISSUE)?;
                selector = Some((tag.to_owned(), entries));
            }
            "direct" | "block" => {
                object(value, &["type", "tag"], ISSUE)?;
                let target = if text(map, "type", ISSUE)? == "direct" {
                    &mut direct
                } else {
                    &mut block
                };
                if target.replace(tag.to_owned()).is_some() {
                    return Err(ISSUE);
                }
            }
            "vless" => {
                nodes.insert(tag.to_owned(), node(value)?);
            }
            _ => return Err(ISSUE),
        }
    }
    let (proxy, selected) = selector.ok_or(ISSUE)?;
    if selected.len() != nodes.len() {
        return Err(ISSUE);
    }
    let nodes = selected
        .into_iter()
        .map(|tag| nodes.remove(&tag).map(|node| (tag, node)).ok_or(ISSUE))
        .collect::<Result<_, _>>()?;
    Ok(Outbounds {
        proxy,
        nodes,
        direct: direct.ok_or(ISSUE)?,
        block: block.ok_or(ISSUE)?,
    })
}

fn node(value: &Value) -> Result<Draft, PolicyIssue> {
    let map = object(
        value,
        &[
            "type",
            "tag",
            "server",
            "server_port",
            "uuid",
            "flow",
            "tls",
            "transport",
            "packet_encoding",
            "multiplex",
            "domain_strategy",
            "network",
            "tcp_fast_open",
            "tcp_multi_path",
        ],
        ISSUE,
    )?;
    if !matches!(optional_text(map, "packet_encoding", ISSUE)?, "" | "xudp")
        || map.get("packet_encoding").is_some_and(|v| v == "")
    {
        return Err(ISSUE);
    }
    if !matches!(
        optional_text(map, "domain_strategy", ISSUE)?,
        "" | "prefer_ipv4" | "ipv4_only" | "prefer_ipv6"
    ) || flag(map, "tcp_fast_open", false, ISSUE)?
        || flag(map, "tcp_multi_path", false, ISSUE)?
    {
        return Err(ISSUE);
    }
    if let Some(network) = map.get("network") {
        let mut network = strings(network, ISSUE)?;
        network.sort();
        if network != ["tcp", "udp"] {
            return Err(ISSUE);
        }
    }
    if let Some(mux) = map.get("multiplex") {
        let mux = object(
            mux,
            &[
                "enabled",
                "protocol",
                "max_connections",
                "min_streams",
                "max_streams",
                "padding",
                "brutal",
            ],
            ISSUE,
        )?;
        if flag(mux, "enabled", false, ISSUE)? {
            return Err(ISSUE);
        }
        if !matches!(
            optional_text(mux, "protocol", ISSUE)?,
            "" | "smux" | "yamux" | "h2mux"
        ) {
            return Err(ISSUE);
        }
        flag(mux, "padding", false, ISSUE)?;
        for key in ["max_connections", "min_streams", "max_streams"] {
            if mux
                .get(key)
                .is_some_and(|v| v.as_u64().is_none_or(|n| n > u32::MAX.into()))
            {
                return Err(ISSUE);
            }
        }
        if let Some(brutal) = mux.get("brutal") {
            let brutal = object(brutal, &["enabled", "up_mbps", "down_mbps"], ISSUE)?;
            if flag(brutal, "enabled", false, ISSUE)? {
                return Err(ISSUE);
            }
            for key in ["up_mbps", "down_mbps"] {
                if brutal
                    .get(key)
                    .is_some_and(|v| v.as_u64().is_none_or(|n| n > u32::MAX.into()))
                {
                    return Err(ISSUE);
                }
            }
        }
    }
    let tls = object(
        map.get("tls").ok_or(ISSUE)?,
        &[
            "enabled",
            "server_name",
            "insecure",
            "alpn",
            "utls",
            "reality",
            "disable_sni",
        ],
        ISSUE,
    )?;
    if !flag(tls, "enabled", false, ISSUE)?
        || flag(tls, "insecure", false, ISSUE)?
        || flag(tls, "disable_sni", false, ISSUE)?
    {
        return Err(ISSUE);
    }
    let server = text(map, "server", ISSUE)?.to_owned();
    let mut draft = Draft {
        name: text(map, "tag", ISSUE)?.into(),
        server: server.clone(),
        port: map
            .get("server_port")
            .and_then(Value::as_u64)
            .filter(|p| *p > 0 && *p <= 65535)
            .ok_or(ISSUE)?
            .to_string(),
        credential: text(map, "uuid", ISSUE)?.to_owned().into(),
        security: Security::Tls,
        vision: false,
        server_name: tls
            .get("server_name")
            .map_or(Ok(server.as_str()), |v| v.as_str().ok_or(ISSUE))?
            .into(),
        fingerprint: "native".into(),
        ..Default::default()
    };
    if let Some(utls) = tls.get("utls") {
        let utls = object(utls, &["enabled", "fingerprint"], ISSUE)?;
        if flag(utls, "enabled", false, ISSUE)? {
            draft.fingerprint = match optional_text(utls, "fingerprint", ISSUE)? {
                "" => "chrome",
                other => other,
            }
            .into();
        }
    }
    if let Some(reality) = tls.get("reality") {
        let reality = object(reality, &["enabled", "public_key", "short_id"], ISSUE)?;
        if flag(reality, "enabled", false, ISSUE)? {
            draft.security = Security::Reality;
            draft.public_key = text(reality, "public_key", ISSUE)?.into();
            draft.short_id = optional_text(reality, "short_id", ISSUE)?.into();
        }
    }
    draft.vision = match optional_text(map, "flow", ISSUE)? {
        "" => false,
        "xtls-rprx-vision" => true,
        _ => return Err(ISSUE),
    };
    if let Some(alpn) = tls.get("alpn") {
        draft.alpn = strings(alpn, ISSUE)?.join(",");
    }
    if let Some(transport) = map.get("transport") {
        let transport = object(
            transport,
            &[
                "type",
                "path",
                "headers",
                "max_early_data",
                "early_data_header_name",
            ],
            ISSUE,
        )?;
        if text(transport, "type", ISSUE)? != "ws"
            || transport
                .get("max_early_data")
                .is_some_and(|v| v.as_u64() != Some(0))
            || !optional_text(transport, "early_data_header_name", ISSUE)?.is_empty()
        {
            return Err(ISSUE);
        }
        let host = if let Some(headers) = transport.get("headers") {
            let headers = object(headers, &["Host", "host"], ISSUE)?;
            if headers.len() > 1 {
                return Err(ISSUE);
            }
            headers
                .values()
                .next()
                .map(|v| {
                    let list = strings(v, ISSUE)?;
                    if list.len() != 1 {
                        return Err(ISSUE);
                    }
                    Ok(list[0].clone())
                })
                .transpose()?
        } else {
            None
        };
        draft.transport = Transport::WebSocket {
            path: transport
                .get("path")
                .map_or(Ok("/"), |v| v.as_str().ok_or(ISSUE))?
                .into(),
            host,
        };
    }
    let _: Profile = draft.validate().map_err(|_| ISSUE)?;
    if draft.security == Security::Reality
        && matches!(draft.fingerprint.as_str(), "android" | "native")
    {
        return Err(ISSUE);
    }
    Ok(draft)
}
