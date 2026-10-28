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
            .get("default_domain_resolver")
            .map(super::dns::options::resolver)
            .transpose()
            .map_err(|_| ISSUE)?
            .is_some_and(|tag| tag != local_dns)
    {
        return Err(ISSUE);
    }
    let sets = super::rule_sets::InlineSets::parse(route.get("rule_set"))?;
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
    let block = object(
        &rules[2],
        &["protocol", "outbound", "action", "method", "no_drop"],
        ISSUE,
    )?;
    if strings(block.get("protocol").ok_or(ISSUE)?, ISSUE)? != ["bittorrent"]
        || final_action(block, outbounds)? != "block"
    {
        return Err(ISSUE);
    }
    let last = object(
        rules.last().ok_or(ISSUE)?,
        &["ip_is_private", "outbound", "action"],
        ISSUE,
    )?;
    if !flag(last, "ip_is_private", false, ISSUE)? || final_action(last, outbounds)? != "direct" {
        return Err(ISSUE);
    }
    let mut native = Vec::new();
    let mut expanded_names = 0;
    for rule in &rules[3..rules.len() - 1] {
        let rule = object(
            rule,
            &[
                "domain",
                "domain_suffix",
                "rule_set",
                "outbound",
                "action",
                "method",
                "no_drop",
            ],
            ISSUE,
        )?;
        let action = final_action(rule, outbounds)?;
        let (domains, suffixes) = if let Some(references) = rule.get("rule_set") {
            if rule.contains_key("domain") || rule.contains_key("domain_suffix") {
                return Err(ISSUE);
            }
            let names = sets.referenced(references)?;
            (names.domains, names.suffixes)
        } else {
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
            (domains, suffixes)
        };
        expanded_names += domains.len() + suffixes.len();
        if expanded_names > 128 {
            return Err(ISSUE);
        }
        native.push(json!({"domain":domains,"domain_suffix":suffixes,"action":action}));
    }
    let text = serde_json::to_string(&json!({"version":1,"rules":native})).map_err(|_| ISSUE)?;
    nm_tunnel_profile::TcpDomainPolicy::from_json(&text).map_err(|_| ISSUE)?;
    Ok(text)
}

/// Only called after the mandatory sniff/hijack prefix has been checked.
/// sing-box closes these established/post-sniff flows on reject; this is not
/// permission to translate a pre-sniff TUN reject requiring RST/ICMP responses.
fn final_action(
    map: &serde_json::Map<String, Value>,
    outbounds: &Outbounds,
) -> Result<&'static str, PolicyIssue> {
    match optional_text(map, "action", ISSUE)? {
        "reject" => {
            if map.contains_key("outbound")
                || !matches!(
                    optional_text(map, "method", ISSUE)?,
                    "" | "default" | "drop"
                )
                || flag(map, "no_drop", false, ISSUE)?
            {
                return Err(ISSUE);
            }
            Ok("block")
        }
        "" | "route" => {
            if map.contains_key("method") || map.contains_key("no_drop") {
                return Err(ISSUE);
            }
            match text(map, "outbound", ISSUE)? {
                tag if tag == outbounds.direct => Ok("direct"),
                tag if tag == outbounds.proxy => Ok("proxy"),
                tag if outbounds.block.as_deref() == Some(tag) => Ok("block"),
                _ => Err(ISSUE),
            }
        }
        _ => Err(ISSUE),
    }
}
