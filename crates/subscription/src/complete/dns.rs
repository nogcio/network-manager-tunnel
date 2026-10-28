//! Supported DNS roles: client A/AAAA FakeIP, outbound bootstrap local, one real upstream.
use super::{PolicyIssue, outbounds::Outbounds, value::*};
use nm_tunnel_profile::{DnsTransport, SourceDns};
use serde_json::Value;
use std::collections::HashMap;
const ISSUE: PolicyIssue = PolicyIssue::Dns;

pub(super) struct Dns {
    pub upstream: SourceDns,
    pub range: String,
    pub local: String,
}
pub(super) fn parse(value: &Value, outbounds: &Outbounds) -> Result<Dns, PolicyIssue> {
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
        let rule = object(rule, &["query_type", "outbound", "server"], ISSUE)?;
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
    let url = url::Url::parse(&if address.contains("://") {
        address.into()
    } else {
        format!("udp://{address}")
    })
    .map_err(|_| ISSUE)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ISSUE);
    }
    let transport = match url.scheme() {
        "udp" => DnsTransport::Udp,
        "tcp" => DnsTransport::Tcp,
        "tls" => DnsTransport::Tls,
        _ => return Err(ISSUE),
    };
    let server = url.host_str().ok_or(ISSUE)?;
    let (address, host) = match server.parse::<std::net::Ipv4Addr>() {
        Ok(address) => (address, None),
        Err(_) => (
            std::net::Ipv4Addr::UNSPECIFIED,
            Some(nm_tunnel_profile::canonical_domain(server).ok_or(ISSUE)?),
        ),
    };
    let port = url.port().unwrap_or(if transport == DnsTransport::Tls {
        853
    } else {
        53
    });
    Ok(SourceDns {
        address,
        host,
        port,
        transport,
        via_proxy,
        tls_name: if transport == DnsTransport::Tls {
            server.to_owned()
        } else {
            String::new()
        },
    })
}
