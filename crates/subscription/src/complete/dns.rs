//! Supported DNS roles: client A/AAAA FakeIP, outbound bootstrap local, one real upstream.
use super::{PolicyIssue, outbounds::Outbounds, value::*};
use nm_tunnel_profile::{DnsTransport, SourceDns};
use serde_json::Value;
use std::collections::HashMap;
mod modern;
pub(super) mod options;
const ISSUE: PolicyIssue = PolicyIssue::Dns;

pub(super) struct Dns {
    pub upstream: SourceDns,
    pub range: String,
    pub local: String,
}
pub(super) fn parse(value: &Value, outbounds: &Outbounds) -> Result<Dns, PolicyIssue> {
    if value
        .get("servers")
        .and_then(Value::as_array)
        .is_some_and(|servers| servers.iter().any(|s| s.get("type").is_some()))
    {
        return modern::parse(value, outbounds);
    }
    parse_legacy(value, outbounds)
}

fn parse_legacy(value: &Value, outbounds: &Outbounds) -> Result<Dns, PolicyIssue> {
    let dns = object(
        value,
        &[
            "servers",
            "rules",
            "final",
            "strategy",
            "disable_cache",
            "disable_expire",
            "independent_cache",
            "reverse_mapping",
            "fakeip",
        ],
        ISSUE,
    )?;
    if flag(dns, "disable_cache", false, ISSUE)?
        || flag(dns, "disable_expire", false, ISSUE)?
        || !flag(dns, "independent_cache", false, ISSUE)?
        || flag(dns, "reverse_mapping", false, ISSUE)?
        || !matches!(
            optional_text(dns, "strategy", ISSUE)?,
            "" | "prefer_ipv4" | "prefer_ipv6" | "ipv4_only"
        )
    {
        return Err(ISSUE);
    }
    let fake = object(
        dns.get("fakeip").ok_or(PolicyIssue::FakeIp)?,
        &["enabled", "inet4_range", "inet6_range"],
        PolicyIssue::FakeIp,
    )?;
    if !flag(fake, "enabled", false, PolicyIssue::FakeIp)? {
        return Err(PolicyIssue::FakeIp);
    }
    let range = text(fake, "inet4_range", PolicyIssue::FakeIp)?;
    if !matches!(range, "198.18.0.0/16" | "198.18.0.0/15") {
        return Err(PolicyIssue::FakeIp);
    }
    if let Some(ipv6) = fake.get("inet6_range") {
        super::integration::ipv6_prefix(ipv6.as_str().ok_or(PolicyIssue::FakeIp)?)
            .map_err(|_| PolicyIssue::FakeIp)?;
    }
    let values = dns.get("servers").and_then(Value::as_array).ok_or(ISSUE)?;
    if values.len() > 8 || values.is_empty() {
        return Err(ISSUE);
    }
    let mut servers = HashMap::new();
    let mut local = None;
    let mut fake_tag = None;
    for value in values {
        let server = object(
            value,
            &[
                "tag",
                "address",
                "detour",
                "address_resolver",
                "strategy",
                "address_strategy",
            ],
            ISSUE,
        )?;
        let tag = text(server, "tag", ISSUE)?;
        if !label(tag) || servers.contains_key(tag) {
            return Err(ISSUE);
        }
        for key in ["strategy", "address_strategy"] {
            if !matches!(
                optional_text(server, key, ISSUE)?,
                "" | "prefer_ipv4" | "prefer_ipv6" | "ipv4_only"
            ) {
                return Err(ISSUE);
            }
        }
        let address = text(server, "address", ISSUE)?;
        let detour = optional_text(server, "detour", ISSUE)?;
        match address {
            "local" => {
                if local.replace(tag.to_owned()).is_some()
                    || (!detour.is_empty() && detour != outbounds.direct)
                {
                    return Err(ISSUE);
                }
            }
            "fakeip" => {
                if fake_tag.replace(tag.to_owned()).is_some() || !detour.is_empty() {
                    return Err(PolicyIssue::FakeIp);
                }
            }
            _ => {
                if detour != outbounds.proxy && detour != outbounds.direct {
                    return Err(ISSUE);
                }
                parse_upstream(address, detour == outbounds.proxy)?;
            }
        }
        servers.insert(tag.to_owned(), server);
    }
    let local = local.ok_or(ISSUE)?;
    let fake_tag = fake_tag.ok_or(PolicyIssue::FakeIp)?;
    for server in servers.values() {
        let bootstrap = optional_text(server, "address_resolver", ISSUE)?;
        if !bootstrap.is_empty() && bootstrap != local {
            return Err(ISSUE);
        }
        let address = text(server, "address", ISSUE)?;
        if !matches!(address, "local" | "fakeip")
            && parse_upstream(address, false)?.host.is_some()
            && bootstrap != local
        {
            return Err(ISSUE);
        }
    }
    let selected = dns.get("final").map_or_else(
        || text(values[0].as_object().ok_or(ISSUE)?, "tag", ISSUE),
        |v| v.as_str().ok_or(ISSUE),
    )?;
    let selected = servers.get(selected).ok_or(ISSUE)?;
    let upstream = parse_upstream(
        text(selected, "address", ISSUE)?,
        text(selected, "detour", ISSUE)? == outbounds.proxy,
    )?;
    let rules = dns.get("rules").and_then(Value::as_array).ok_or(ISSUE)?;
    if rules.len() != 2 {
        return Err(ISSUE);
    }
    let mut client = false;
    let mut outbound = false;
    for rule in rules {
        let rule = object(
            rule,
            &[
                "query_type",
                "outbound",
                "server",
                "action",
                "strategy",
                "disable_cache",
                "rewrite_ttl",
                "client_subnet",
            ],
            ISSUE,
        )?;
        options::route_options(rule)?;
        if !matches!(optional_text(rule, "action", ISSUE)?, "" | "route") {
            return Err(ISSUE);
        }
        if rule.contains_key("query_type") && !rule.contains_key("outbound") {
            let mut types = strings(rule.get("query_type").ok_or(ISSUE)?, ISSUE)?;
            types.sort();
            if client || types != ["A", "AAAA"] || text(rule, "server", ISSUE)? != fake_tag {
                return Err(ISSUE);
            }
            client = true;
        } else if rule.contains_key("outbound") && !rule.contains_key("query_type") {
            if outbound
                || strings(rule.get("outbound").ok_or(ISSUE)?, ISSUE)? != ["any"]
                || text(rule, "server", ISSUE)? != local
            {
                return Err(ISSUE);
            }
            outbound = true;
        } else {
            return Err(ISSUE);
        }
    }
    if !client || !outbound {
        return Err(ISSUE);
    }
    Ok(Dns {
        upstream,
        range: range.into(),
        local,
    })
}

fn parse_upstream(address: &str, via_proxy: bool) -> Result<SourceDns, PolicyIssue> {
    if address.len() > 2048 || !address.bytes().all(|b| b.is_ascii_graphic() && b != b'\\') {
        return Err(ISSUE);
    }
    let url = url::Url::parse(&if address.contains("://") {
        address.into()
    } else {
        format!("udp://{address}")
    })
    .map_err(|_| ISSUE)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || (url.scheme() != "https" && !matches!(url.path(), "" | "/"))
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ISSUE);
    }
    let transport = match url.scheme() {
        "udp" => DnsTransport::Udp,
        "tcp" => DnsTransport::Tcp,
        "tls" => DnsTransport::Tls,
        "https" => DnsTransport::Https,
        _ => return Err(ISSUE),
    };
    let server = url.host_str().ok_or(ISSUE)?;
    let (ip_address, host) = match server.parse::<std::net::Ipv4Addr>() {
        Ok(address) => (address, None),
        Err(_) => (
            std::net::Ipv4Addr::UNSPECIFIED,
            Some(nm_tunnel_profile::canonical_domain(server).ok_or(ISSUE)?),
        ),
    };
    let port = url.port().unwrap_or(match transport {
        DnsTransport::Tls => 853,
        DnsTransport::Https => 443,
        _ => 53,
    });
    let http_path = if transport == DnsTransport::Https {
        let raw_path = address
            .split_once("://")
            .and_then(|(_, rest)| rest.find('/').map(|n| &rest[n..]));
        match raw_path {
            None => "/dns-query".to_owned(),
            Some(path) if path == url.path() => path.to_owned(),
            _ => return Err(ISSUE),
        }
    } else {
        String::new()
    };
    SourceDns {
        address: ip_address,
        host,
        port,
        transport,
        via_proxy,
        tls_name: if matches!(transport, DnsTransport::Tls | DnsTransport::Https) {
            server.to_owned()
        } else {
            String::new()
        },
        http_path,
    }
    .validated()
    .map_err(|_| ISSUE)
}
