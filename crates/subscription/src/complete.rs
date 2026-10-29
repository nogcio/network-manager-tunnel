//! Fail-closed full-configuration admission, never node extraction from policies.
use crate::{MAX_BYTES, MAX_ENTRIES, Subscription, SubscriptionError};
use serde::Deserialize;
use serde_json::Value;

mod dns;
#[cfg(test)]
pub(crate) mod fixtures;
mod integration;
mod outbounds;
mod route_rules;
mod routing;
mod rule_sets;
mod value;

/// Static admission categories; no provider text or unsupported field values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyIssue {
    /// The source's required FakeIP semantics cannot be represented by the checked
    /// IPv4 pool/ownership contract. No partial node extraction is permitted.
    #[error(
        "The complete configuration requires FakeIP DNS semantics this importer cannot yet preserve. No profiles were extracted."
    )]
    FakeIp,
    /// A global resolver policy cannot be replaced by the backend's legacy default.
    #[error(
        "The complete configuration has DNS settings this version cannot preserve. No profiles were extracted."
    )]
    Dns,
    /// Full ordered routing has not been translated/admitted by the runtime.
    #[error(
        "The complete configuration has routing settings this version cannot preserve. No profiles were extracted."
    )]
    Routing,
    /// Foreign listeners/controllers/cache paths are not executable instructions.
    #[error(
        "The complete configuration requires unsupported client integration settings. No profiles were extracted."
    )]
    ClientIntegration,
    /// Do not accept an unvalidated remainder merely because known rules are absent.
    #[error(
        "The complete configuration is outside the supported native IPv4 policy contract. No profiles were extracted or policies discarded."
    )]
    Configuration,
}

// Top-level duplicate/unknown fields are errors. Nested fields remain untrusted
// values: none are admitted to the runtime, executed, persisted or printed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteConfiguration {
    outbounds: Vec<Value>,
    #[serde(default)]
    dns: Option<Value>,
    #[serde(default)]
    route: Option<Value>,
    #[serde(default)]
    inbounds: Option<Value>,
    #[serde(default)]
    experimental: Option<Value>,
    #[serde(default)]
    log: Option<Value>,
}

pub(crate) fn admit(bytes: &[u8]) -> Result<Subscription, SubscriptionError> {
    if bytes.len() > MAX_BYTES {
        return Err(SubscriptionError::TooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| SubscriptionError::Format)?;
    let text = text.trim_start_matches('\u{feff}').trim();
    if !text.starts_with('{') {
        return Err(SubscriptionError::FullConfigurationRequired);
    }
    let value: value::Unique = serde_json::from_str(text).map_err(|_| SubscriptionError::Format)?;
    let document: CompleteConfiguration =
        serde_json::from_value(value.0).map_err(|_| SubscriptionError::Format)?;
    if document.outbounds.is_empty()
        || document
            .outbounds
            .iter()
            .any(|value| !value.is_object() || value.get("type").and_then(Value::as_str).is_none())
    {
        return Err(SubscriptionError::Format);
    }
    if document.outbounds.len() > MAX_ENTRIES {
        return Err(SubscriptionError::TooManyEntries);
    }
    // No profile leaves this function until every node and global policy has
    // been translated. A failure never extracts a selectable node-only subset.
    if document.dns.is_some() && document.route.is_some() {
        return translate(&document).map_err(SubscriptionError::UnsupportedPolicy);
    }
    let issue = if let Some(dns) = document.dns {
        let fake_ip = dns.pointer("/fakeip/enabled").and_then(Value::as_bool) == Some(true)
            || dns
                .get("servers")
                .and_then(Value::as_array)
                .is_some_and(|servers| {
                    servers.iter().any(|server| {
                        server.get("address").and_then(Value::as_str) == Some("fakeip")
                            || server.get("type").and_then(Value::as_str) == Some("fakeip")
                    })
                });
        if fake_ip {
            PolicyIssue::FakeIp
        } else {
            PolicyIssue::Dns
        }
    } else if document.route.is_some() {
        PolicyIssue::Routing
    } else if document.inbounds.is_some() || document.experimental.is_some() {
        PolicyIssue::ClientIntegration
    } else {
        // Even a nodes-only JSON object is not a completely admitted client
        // configuration. Log values, controllers, paths and URLs are never acted on.
        drop(document.log);
        PolicyIssue::Configuration
    };
    Err(SubscriptionError::UnsupportedPolicy(issue))
}

fn translate(document: &CompleteConfiguration) -> Result<Subscription, PolicyIssue> {
    let outbounds = outbounds::parse(&document.outbounds)?;
    let mut dns_value = document.dns.as_ref().ok_or(PolicyIssue::Dns)?.clone();
    // Modern configurations replace the deprecated outbound:any DNS rule with an
    // explicit route bootstrap resolver. Preserve only that same checked role;
    // routing::parse independently requires it to name the local DNS server.
    if let Some(resolver) = document
        .route
        .as_ref()
        .and_then(|r| r.get("default_domain_resolver"))
        .map(dns::options::resolver)
        .transpose()?
        && let Some(rules) = dns_value.get_mut("rules").and_then(Value::as_array_mut)
        && !rules.iter().any(|rule| rule.get("outbound").is_some())
    {
        rules.insert(0, serde_json::json!({"outbound":"any", "server":resolver}));
    }
    let dns = dns::parse(&dns_value, &outbounds)?;
    if outbounds.resolvers.iter().any(|tag| tag != &dns.local) {
        return Err(PolicyIssue::Dns);
    }
    let domains = routing::parse(
        document.route.as_ref().ok_or(PolicyIssue::Routing)?,
        &outbounds,
        &dns.local,
    )?;
    let tun = integration::parse(
        document.inbounds.as_ref(),
        document.experimental.as_ref(),
        document.log.as_ref(),
    )?;
    let mut native = serde_json::json!({
        "version":domains.version, "dns":dns.upstream, "fakeip_range":dns.range,
        "tun_address":tun.address, "tun_prefix":tun.prefix, "mtu":tun.mtu,
    });
    native[domains.field] = serde_json::Value::String(domains.encoded);
    if let Some(policy) = dns.policy {
        native["version"] = serde_json::json!(3);
        native["dns_policy"] = policy;
    }
    let encoded = serde_json::to_string(&native).map_err(|_| PolicyIssue::Configuration)?;
    let policy = nm_tunnel_profile::SourcePolicy::from_json(&encoded)
        .map_err(|_| PolicyIssue::Configuration)?;
    let mut profiles = Vec::new();
    for (tag, mut draft) in outbounds.nodes {
        draft.source_policy = Some(policy.clone());
        draft.fake_ip = true;
        draft.dns_interception = true;
        let profile = draft.validate().map_err(|_| PolicyIssue::Configuration)?;
        profiles.push((tag, profile));
    }
    if profiles.is_empty() {
        return Err(PolicyIssue::Configuration);
    }
    Ok(Subscription::from_complete(profiles))
}

#[cfg(test)]
mod action_tests;
#[cfg(test)]
mod dns_tests;
#[cfg(test)]
mod tests;
