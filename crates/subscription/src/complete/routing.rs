//! Admit the supported ordered pipeline, never flatten/reorder arbitrary rules.
use super::{PolicyIssue, outbounds::Outbounds, value::*};
use serde_json::{Value, json};
const ISSUE: PolicyIssue = PolicyIssue::Routing;

pub(super) fn parse(
    value: &Value,
    outbounds: &Outbounds,
    local_dns: &str,
) -> Result<String, PolicyIssue> {
    let route = object(
        value,
        &[
            "rules",
            "final",
            "auto_detect_interface",
            "default_domain_resolver",
            "rule_set",
            "default_interface",
        ],
        ISSUE,
    )?;
    if optional_text(route, "final", ISSUE)? != outbounds.proxy
        || !flag(route, "auto_detect_interface", true, ISSUE)?
        || !optional_text(route, "default_interface", ISSUE)?.is_empty()
        || route
            .get("rule_set")
            .is_some_and(|v| v.as_array().is_none_or(|v| !v.is_empty()))
        || route
            .get("default_domain_resolver")
            .is_some_and(|v| v.as_str() != Some(local_dns))
    {
        return Err(ISSUE);
    }
    let rules = route.get("rules").and_then(Value::as_array).ok_or(ISSUE)?;
    if !(5..=68).contains(&rules.len()) {
        return Err(ISSUE);
    }
    let sniff = object(&rules[0], &["action", "timeout"], ISSUE)?;
    if text(sniff, "action", ISSUE)? != "sniff"
        || !matches!(optional_text(sniff, "timeout", ISSUE)?, "" | "300ms")
    {
        return Err(ISSUE);
    }
    let hijack = object(&rules[1], &["type", "mode", "rules", "action"], ISSUE)?;
    if text(hijack, "type", ISSUE)? != "logical"
        || text(hijack, "mode", ISSUE)? != "or"
        || text(hijack, "action", ISSUE)? != "hijack-dns"
    {
        return Err(ISSUE);
    }
    let dns = hijack.get("rules").and_then(Value::as_array).ok_or(ISSUE)?;
    if dns.len() != 2
        || !dns
            .iter()
            .any(|v| *v == json!({"protocol":"dns"}) || *v == json!({"protocol":["dns"]}))
        || !dns
            .iter()
            .any(|v| *v == json!({"port":53}) || *v == json!({"port":[53]}))
    {
        return Err(ISSUE);
    }
    let block = object(&rules[2], &["protocol", "outbound", "action"], ISSUE)?;
    if strings(block.get("protocol").ok_or(ISSUE)?, ISSUE)? != ["bittorrent"]
        || text(block, "outbound", ISSUE)? != outbounds.block
        || !matches!(optional_text(block, "action", ISSUE)?, "" | "route")
    {
        return Err(ISSUE);
    }
    let last = object(
        rules.last().ok_or(ISSUE)?,
        &["ip_is_private", "outbound", "action"],
        ISSUE,
    )?;
    if !flag(last, "ip_is_private", false, ISSUE)?
        || text(last, "outbound", ISSUE)? != outbounds.direct
        || !matches!(optional_text(last, "action", ISSUE)?, "" | "route")
    {
        return Err(ISSUE);
    }
    let mut native = Vec::new();
    for rule in &rules[3..rules.len() - 1] {
        let rule = object(
            rule,
            &["domain", "domain_suffix", "outbound", "action"],
            ISSUE,
        )?;
        if !matches!(optional_text(rule, "action", ISSUE)?, "" | "route") {
            return Err(ISSUE);
        }
        let action = match text(rule, "outbound", ISSUE)? {
            tag if tag == outbounds.direct => "direct",
            tag if tag == outbounds.proxy => "proxy",
            tag if tag == outbounds.block => "block",
            _ => return Err(ISSUE),
        };
        let domains = rule
            .get("domain")
            .map(|v| strings(v, ISSUE))
            .transpose()?
            .unwrap_or_default();
        let suffixes = rule
            .get("domain_suffix")
            .map(|v| strings(v, ISSUE))
            .transpose()?
            .unwrap_or_default();
        native.push(json!({"domain":domains,"domain_suffix":suffixes,"action":action}));
    }
    let text = serde_json::to_string(&json!({"version":1,"rules":native})).map_err(|_| ISSUE)?;
    nm_tunnel_profile::TcpDomainPolicy::from_json(&text).map_err(|_| ISSUE)?;
    Ok(text)
}
