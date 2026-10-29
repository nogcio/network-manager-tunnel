//! Preserve the client-FakeIP boundary before ordered real-resolution rules.
use super::*;
use serde_json::json;

pub(super) fn parse(
    values: &[Value],
    servers: &HashMap<String, &serde_json::Map<String, Value>>,
    fake: &str,
    local: &str,
    outbounds: &Outbounds,
    tls_names: &HashMap<String, String>,
) -> Result<Option<Value>, PolicyIssue> {
    if values.len() > 66 {
        return Err(ISSUE);
    }
    let mut client = false;
    let mut outbound = false;
    let mut rules = Vec::new();
    let mut resolvers = Vec::new();
    let mut indices = HashMap::new();
    let mut names = 0;
    for value in values {
        let rule = object(
            value,
            &[
                "query_type",
                "outbound",
                "server",
                "action",
                "strategy",
                "disable_cache",
                "rewrite_ttl",
                "client_subnet",
                "domain",
                "domain_suffix",
            ],
            ISSUE,
        )?;
        options::route_options(rule)?;
        if !matches!(optional_text(rule, "action", ISSUE)?, "" | "route") {
            return Err(ISSUE);
        }
        let has_names = rule.contains_key("domain") || rule.contains_key("domain_suffix");
        if rule.contains_key("query_type") && !rule.contains_key("outbound") && !has_names {
            let mut types = strings(rule.get("query_type").ok_or(ISSUE)?, ISSUE)?;
            types.sort();
            if client || types != ["A", "AAAA"] || text(rule, "server", ISSUE)? != fake {
                return Err(ISSUE);
            }
            client = true;
        } else if rule.contains_key("outbound") && !rule.contains_key("query_type") && !has_names {
            if outbound
                || !rules.is_empty()
                || strings(rule.get("outbound").ok_or(ISSUE)?, ISSUE)? != ["any"]
                || text(rule, "server", ISSUE)? != local
            {
                return Err(ISSUE);
            }
            outbound = true;
        } else if has_names && !rule.contains_key("query_type") && !rule.contains_key("outbound") {
            if !client || !outbound {
                return Err(ISSUE);
            }
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
            names += domains.len() + suffixes.len();
            if names > 128 || domains.len() + suffixes.len() == 0 {
                return Err(ISSUE);
            }
            let tag = text(rule, "server", ISSUE)?;
            let index = if let Some(index) = indices.get(tag) {
                *index
            } else {
                let server = servers.get(tag).ok_or(ISSUE)?;
                let target = match text(server, "address", ISSUE)? {
                    "fakeip" => return Err(ISSUE),
                    "local" => json!({"type":"current_network"}),
                    _ => json!({"type":"endpoint","dns":endpoint(tag,server,outbounds,tls_names)?}),
                };
                let index = resolvers.len();
                resolvers.push(target);
                indices.insert(tag.to_owned(), index);
                index
            };
            rules.push(json!({"domain":domains,"domain_suffix":suffixes,"resolver":index}));
        } else {
            return Err(ISSUE);
        }
    }
    if !client || !outbound {
        return Err(ISSUE);
    }
    Ok(if rules.is_empty() {
        None
    } else {
        Some(json!({"version":1,"resolvers":resolvers,"rules":rules}))
    })
}
