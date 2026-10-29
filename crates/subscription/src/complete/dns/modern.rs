//! Translate the bounded sing-box 1.12 typed-server subset into existing DNS roles.
use super::*;
use serde_json::json;

pub(super) fn parse(value: &Value, outbounds: &Outbounds) -> Result<Dns, PolicyIssue> {
    let mut normalized = value.clone();
    let dns = normalized.as_object_mut().ok_or(ISSUE)?;
    // Two competing FakeIP authorities are ambiguous, even if their ranges match.
    if dns.contains_key("fakeip") {
        return Err(PolicyIssue::FakeIp);
    }
    let servers = dns
        .get_mut("servers")
        .and_then(Value::as_array_mut)
        .ok_or(ISSUE)?;
    let mut fake = None;
    let mut tls_names = HashMap::new();
    for value in servers.iter_mut() {
        let server = value.as_object().ok_or(ISSUE)?;
        let kind = text(server, "type", ISSUE)?;
        let tag = text(server, "tag", ISSUE)?;
        let mut legacy = json!({"tag":tag});
        match kind {
            "fakeip" => {
                object(value, &["type", "tag", "inet4_range", "inet6_range"], ISSUE)?;
                if fake.is_some() {
                    return Err(PolicyIssue::FakeIp);
                }
                let mut ranges = json!({"enabled":true,
                    "inet4_range": optional_text(server, "inet4_range", ISSUE)?});
                if ranges["inet4_range"] == "" {
                    ranges["inet4_range"] = json!("198.18.0.0/15");
                }
                if let Some(ipv6) = server.get("inet6_range") {
                    ranges["inet6_range"] = ipv6.clone();
                }
                fake = Some(ranges);
                legacy["address"] = json!("fakeip");
            }
            "local" => {
                object(value, &["type", "tag", "detour"], ISSUE)?;
                let detour = optional_text(server, "detour", ISSUE)?;
                if !detour.is_empty() && detour != outbounds.direct {
                    return Err(ISSUE);
                }
                legacy["address"] = json!("local");
                legacy["detour"] = json!(&outbounds.direct);
            }
            "udp" | "tcp" | "tls" | "https" => {
                object(
                    value,
                    &[
                        "type",
                        "tag",
                        "server",
                        "server_port",
                        "detour",
                        "domain_resolver",
                        "tls",
                        "path",
                        "headers",
                    ],
                    ISSUE,
                )?;
                let host = text(server, "server", ISSUE)?;
                if host.parse::<std::net::Ipv4Addr>().is_err()
                    && nm_tunnel_profile::canonical_domain(host).as_deref() != Some(host)
                {
                    return Err(ISSUE);
                }
                let port = server
                    .get("server_port")
                    .map(|p| p.as_u64().filter(|p| (1..=65535).contains(p)).ok_or(ISSUE))
                    .transpose()?
                    .unwrap_or(match kind {
                        "https" => 443,
                        "tls" => 853,
                        _ => 53,
                    });
                let detour = optional_text(server, "detour", ISSUE)?;
                // Typed servers default to Direct, unlike legacy default-outbound DNS.
                legacy["detour"] = json!(if detour.is_empty() {
                    &outbounds.direct
                } else {
                    detour
                });
                if let Some(resolver) = server.get("domain_resolver") {
                    legacy["address_resolver"] = json!(super::options::resolver(resolver)?);
                }
                let encrypted = matches!(kind, "tls" | "https");
                if let Some(tls) = server.get("tls") {
                    let tls = object(tls, &["enabled", "server_name"], ISSUE)?;
                    if !encrypted || !flag(tls, "enabled", true, ISSUE)? {
                        return Err(ISSUE);
                    }
                    let name = optional_text(tls, "server_name", ISSUE)?;
                    if !name.is_empty() {
                        tls_names.insert(tag.to_owned(), name.to_owned());
                    }
                }
                let path = optional_text(server, "path", ISSUE)?;
                if kind != "https"
                    && (server.contains_key("path") || server.contains_key("headers"))
                {
                    return Err(ISSUE);
                }
                if server
                    .get("headers")
                    .is_some_and(|h| h.as_object().is_none_or(|h| !h.is_empty()))
                {
                    return Err(ISSUE);
                }
                // Validate before URL parsing, which may normalize dot segments/controls.
                let path = if kind == "https" && path.is_empty() {
                    "/dns-query"
                } else {
                    path
                };
                if kind == "https"
                    && (!path.starts_with('/')
                        || path.starts_with("//")
                        || path.len() > 1024
                        || !path
                            .bytes()
                            .all(|b| b.is_ascii_graphic() && !matches!(b, b'?' | b'#' | b'\\'))
                        || path.split('/').any(|s| matches!(s, "." | "..")))
                {
                    return Err(ISSUE);
                }
                legacy["address"] = json!(format!("{kind}://{host}:{port}{path}"));
                let mut upstream =
                    super::parse_upstream(legacy["address"].as_str().ok_or(ISSUE)?, false)?;
                if let Some(name) = tls_names.get(tag) {
                    upstream.tls_name = name.clone();
                }
                upstream.validated().map_err(|_| ISSUE)?;
            }
            _ => return Err(ISSUE),
        }
        *value = legacy;
    }
    dns.insert("fakeip".into(), fake.ok_or(PolicyIssue::FakeIp)?);
    super::parse_legacy(&normalized, outbounds, &tls_names)
}
