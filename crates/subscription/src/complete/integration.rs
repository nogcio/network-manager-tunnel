//! Owner-approved client exclusions; networking effects still require checked mapping.
use super::{PolicyIssue, value::*};
use serde_json::Value;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
const ISSUE: PolicyIssue = PolicyIssue::ClientIntegration;

pub(super) struct Tun {
    pub address: Ipv4Addr,
    pub prefix: u8,
    pub mtu: u16,
}

pub(super) fn ipv6_prefix(value: &str) -> Result<(), PolicyIssue> {
    let (ip, prefix) = value.split_once('/').ok_or(ISSUE)?;
    ip.parse::<Ipv6Addr>().map_err(|_| ISSUE)?;
    if prefix.parse::<u8>().map_err(|_| ISSUE)? > 128 {
        return Err(ISSUE);
    }
    Ok(())
}

pub(super) fn parse(
    inbounds: Option<&Value>,
    experimental: Option<&Value>,
    log: Option<&Value>,
) -> Result<Tun, PolicyIssue> {
    let mut tun = None;
    if let Some(inbounds) = inbounds {
        let inbounds = inbounds.as_array().ok_or(ISSUE)?;
        if inbounds.len() > 8 {
            return Err(ISSUE);
        }
        for inbound in inbounds {
            let kind = inbound.get("type").and_then(Value::as_str).ok_or(ISSUE)?;
            match kind {
                "tun" => {
                    if tun.is_some() {
                        return Err(ISSUE);
                    }
                    tun = Some(parse_tun(inbound)?);
                }
                "mixed" => {
                    let map = object(
                        inbound,
                        &[
                            "type",
                            "tag",
                            "listen",
                            "listen_port",
                            "users",
                            "set_system_proxy",
                            "sniff",
                            "sniff_override_destination",
                            "domain_strategy",
                        ],
                        ISSUE,
                    )?;
                    optional_text(map, "tag", ISSUE)?;
                    if let Some(listen) = map.get("listen") {
                        listen
                            .as_str()
                            .ok_or(ISSUE)?
                            .parse::<IpAddr>()
                            .map_err(|_| ISSUE)?;
                    }
                    if map
                        .get("listen_port")
                        .is_some_and(|v| v.as_u64().is_none_or(|p| p == 0 || p > 65535))
                    {
                        return Err(ISSUE);
                    }
                    for key in ["set_system_proxy", "sniff", "sniff_override_destination"] {
                        flag(map, key, false, ISSUE)?;
                    }
                    optional_text(map, "domain_strategy", ISSUE)?;
                    if let Some(users) = map.get("users") {
                        let users = users.as_array().ok_or(ISSUE)?;
                        if users.len() > 64 {
                            return Err(ISSUE);
                        }
                        for user in users {
                            let user = object(user, &["username", "password"], ISSUE)?;
                            text(user, "username", ISSUE)?;
                            text(user, "password", ISSUE)?;
                        }
                    }
                }
                _ => return Err(ISSUE),
            }
        }
    }
    if let Some(value) = experimental {
        let map = object(value, &["cache_file", "clash_api"], ISSUE)?;
        if let Some(cache) = map.get("cache_file") {
            let cache = object(
                cache,
                &[
                    "enabled",
                    "path",
                    "cache_id",
                    "store_fakeip",
                    "store_rdrc",
                    "rdrc_timeout",
                ],
                ISSUE,
            )?;
            flag(cache, "enabled", false, ISSUE)?;
            flag(cache, "store_fakeip", false, ISSUE)?;
            if flag(cache, "store_rdrc", false, ISSUE)? {
                return Err(ISSUE);
            }
            for key in ["path", "cache_id", "rdrc_timeout"] {
                optional_text(cache, key, ISSUE)?;
            }
        }
        if let Some(api) = map.get("clash_api") {
            let api = object(
                api,
                &[
                    "external_controller",
                    "external_ui",
                    "external_ui_download_url",
                    "external_ui_download_detour",
                    "secret",
                    "default_mode",
                    "access_control_allow_origin",
                    "access_control_allow_private_network",
                ],
                ISSUE,
            )?;
            for key in [
                "external_controller",
                "external_ui",
                "external_ui_download_url",
                "external_ui_download_detour",
                "secret",
            ] {
                optional_text(api, key, ISSUE)?;
            }
            if !matches!(optional_text(api, "default_mode", ISSUE)?, "" | "rule") {
                return Err(ISSUE);
            }
            if let Some(origins) = api.get("access_control_allow_origin") {
                strings(origins, ISSUE)?;
            }
            flag(api, "access_control_allow_private_network", false, ISSUE)?;
        }
    }
    if let Some(value) = log {
        let log = object(value, &["disabled", "level", "output", "timestamp"], ISSUE)?;
        flag(log, "disabled", false, ISSUE)?;
        flag(log, "timestamp", false, ISSUE)?;
        if !matches!(
            optional_text(log, "level", ISSUE)?,
            "" | "trace" | "debug" | "info" | "warn" | "error" | "fatal" | "panic"
        ) {
            return Err(ISSUE);
        }
        optional_text(log, "output", ISSUE)?;
    }
    Ok(tun.unwrap_or(Tun {
        address: Ipv4Addr::new(172, 19, 0, 1),
        prefix: 30,
        mtu: 9000,
    }))
}

fn parse_tun(value: &Value) -> Result<Tun, PolicyIssue> {
    let map = object(
        value,
        &[
            "type",
            "tag",
            "interface_name",
            "address",
            "inet4_address",
            "inet6_address",
            "mtu",
            "auto_route",
            "strict_route",
            "stack",
            "sniff",
            "sniff_override_destination",
            "domain_strategy",
            "platform",
            "auto_redirect",
            "endpoint_independent_nat",
            "udp_timeout",
            "gso",
            "route_address",
            "route_exclude_address",
            "include_interface",
            "exclude_interface",
        ],
        ISSUE,
    )?;
    for key in ["tag", "interface_name"] {
        optional_text(map, key, ISSUE)?;
    }
    if !flag(map, "auto_route", true, ISSUE)?
        || !flag(map, "strict_route", true, ISSUE)?
        || flag(map, "sniff_override_destination", false, ISSUE)?
        || flag(map, "endpoint_independent_nat", false, ISSUE)?
        || flag(map, "auto_redirect", false, ISSUE)?
        || flag(map, "gso", false, ISSUE)?
        || !matches!(
            optional_text(map, "stack", ISSUE)?,
            "" | "mixed" | "system" | "gvisor"
        )
        || !matches!(
            optional_text(map, "domain_strategy", ISSUE)?,
            "" | "ipv4_only" | "prefer_ipv4" | "prefer_ipv6"
        )
        || !matches!(optional_text(map, "udp_timeout", ISSUE)?, "" | "60s")
    {
        return Err(ISSUE);
    }
    flag(map, "sniff", false, ISSUE)?;
    for key in [
        "route_address",
        "route_exclude_address",
        "include_interface",
        "exclude_interface",
    ] {
        if map
            .get(key)
            .is_some_and(|v| v.as_array().is_none_or(|values| !values.is_empty()))
        {
            return Err(ISSUE);
        }
    }
    let mtu = map.get("mtu").map_or(Ok(9000), |v| {
        v.as_u64().and_then(|n| u16::try_from(n).ok()).ok_or(ISSUE)
    })?;
    let mut address = None;
    for key in ["address", "inet4_address", "inet6_address"] {
        if let Some(values) = map.get(key) {
            for value in strings(values, ISSUE)? {
                let (ip, prefix) = value.split_once('/').ok_or(ISSUE)?;
                match ip.parse::<IpAddr>().map_err(|_| ISSUE)? {
                    IpAddr::V6(_) => ipv6_prefix(&value)?,
                    IpAddr::V4(ip) => {
                        let prefix = prefix.parse::<u8>().map_err(|_| ISSUE)?;
                        if address.replace((ip, prefix)).is_some() {
                            return Err(ISSUE);
                        }
                    }
                }
            }
        }
    }
    if let Some(platform) = map.get("platform") {
        let platform = object(platform, &["http_proxy"], ISSUE)?;
        if let Some(proxy) = platform.get("http_proxy") {
            let proxy = object(
                proxy,
                &[
                    "enabled",
                    "server",
                    "server_port",
                    "bypass_domain",
                    "match_domain",
                ],
                ISSUE,
            )?;
            flag(proxy, "enabled", false, ISSUE)?;
            optional_text(proxy, "server", ISSUE)?;
            if proxy
                .get("server_port")
                .is_some_and(|v| v.as_u64().is_none_or(|p| p > 65535))
            {
                return Err(ISSUE);
            }
            for key in ["bypass_domain", "match_domain"] {
                if let Some(v) = proxy.get(key) {
                    strings(v, ISSUE)?;
                }
            }
        }
    }
    let (address, prefix) = address.ok_or(ISSUE)?;
    Ok(Tun {
        address,
        prefix,
        mtu,
    })
}
