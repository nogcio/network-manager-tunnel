//! Representable DNS route/resolver options. Non-default behavior is never erased.
use super::*;

pub(in crate::complete) fn route_options(
    map: &serde_json::Map<String, Value>,
) -> Result<(), PolicyIssue> {
    // All execution is explicitly IPv4-only. Other preferences are not equivalent
    // to an explicit IPv4-only query and cannot silently replace this choice.
    if !matches!(optional_text(map, "strategy", ISSUE)?, "" | "ipv4_only")
        || flag(map, "disable_cache", false, ISSUE)?
        || map.get("rewrite_ttl").is_some_and(|v| !v.is_null())
        || map.get("client_subnet").is_some_and(|v| !v.is_null())
    {
        return Err(ISSUE);
    }
    Ok(())
}

/// String shorthand and checked object form have identical bootstrap authority.
pub(in crate::complete) fn resolver(value: &Value) -> Result<&str, PolicyIssue> {
    let tag = if let Some(tag) = value.as_str() {
        tag
    } else {
        let map = object(
            value,
            &[
                "server",
                "strategy",
                "disable_cache",
                "rewrite_ttl",
                "client_subnet",
            ],
            ISSUE,
        )?;
        route_options(map)?;
        text(map, "server", ISSUE)?
    };
    if !label(tag) {
        return Err(ISSUE);
    }
    Ok(tag)
}
