//! Compile destination predicates into the native v2 source contract, not a
//! foreign JSON passthrough. The fixed sniff/DNS/BitTorrent/private-IP order stays.
use super::{PolicyIssue, outbounds::Outbounds, routing, rule_sets::InlineSets, value::*};
use serde_json::{Value, json};

const ISSUE: PolicyIssue = PolicyIssue::Routing;
pub(super) const MAX_DEPTH: usize = 8;

pub(super) fn compile(
    rules: &[Value],
    outbounds: &Outbounds,
    sets: &InlineSets,
) -> Result<routing::Compiled, PolicyIssue> {
    let mut budget = Budget::default();
    let mut native = Vec::new();
    for value in rules {
        let mut map = value.as_object().ok_or(ISSUE)?.clone();
        let action = routing::final_action(&map, outbounds)?;
        for key in ["action", "outbound", "method", "no_drop"] {
            map.remove(key);
        }
        let condition = budget.condition(&Value::Object(map), Some(sets), 1)?;
        native.push(json!({"condition":condition,"action":action}));
        // Repeated references consume the actual expanded model budget, not
        // merely one source node. Reject before building the next terminal rule.
        checked_policy(&native)?;
    }
    let checked = checked_policy(&native)?;
    Ok(routing::Compiled {
        version: 2,
        field: "route_policy",
        encoded: checked.as_json().into(),
    })
}

#[derive(Default)]
pub(super) struct Budget {
    nodes: usize,
    values: usize,
    pub names: usize,
}

impl Budget {
    pub fn condition(
        &mut self,
        value: &Value,
        sets: Option<&InlineSets>,
        depth: usize,
    ) -> Result<Value, PolicyIssue> {
        self.nodes += 1;
        if depth > MAX_DEPTH || self.nodes > 128 {
            return Err(ISSUE);
        }
        let map = value.as_object().ok_or(ISSUE)?;
        let invert = flag(map, "invert", false, ISSUE)?;
        match optional_text(map, "type", ISSUE)? {
            "logical" => {
                object(value, &["type", "mode", "rules", "invert"], ISSUE)?;
                let mode = text(map, "mode", ISSUE)?;
                if !matches!(mode, "and" | "or") {
                    return Err(ISSUE);
                }
                let rules = map.get("rules").and_then(Value::as_array).ok_or(ISSUE)?;
                if rules.is_empty() || rules.len() > 128 {
                    return Err(ISSUE);
                }
                let rules = rules
                    .iter()
                    .map(|rule| self.condition(rule, sets, depth + 1))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(json!({"type":"logical","mode":mode,"rules":rules,"invert":invert}))
            }
            "" | "default" => {
                object(
                    value,
                    &[
                        "type",
                        "domain",
                        "domain_suffix",
                        "ip_cidr",
                        "port",
                        "port_range",
                        "rule_set",
                        "invert",
                    ],
                    ISSUE,
                )?;
                let domains = self.strings(map.get("domain"))?;
                let suffixes = self.strings(map.get("domain_suffix"))?;
                let networks = self.strings(map.get("ip_cidr"))?;
                let mut ports = Vec::<[u16; 2]>::new();
                if let Some(value) = map.get("port") {
                    let values = list(value)?;
                    for value in values {
                        let port = value
                            .as_u64()
                            .and_then(|v| u16::try_from(v).ok())
                            .filter(|p| *p != 0)
                            .ok_or(ISSUE)?;
                        ports.push([port, port]);
                    }
                }
                if let Some(value) = map.get("port_range") {
                    for range in self.strings(Some(value))? {
                        let (low, high) = range.split_once(':').ok_or(ISSUE)?;
                        let number = |text: &str, default| {
                            if text.is_empty() {
                                return Ok(default);
                            }
                            if !text.bytes().all(|b| b.is_ascii_digit()) {
                                return Err(ISSUE);
                            }
                            text.parse::<u16>().ok().filter(|v| *v != 0).ok_or(ISSUE)
                        };
                        let low = number(low, 1)?;
                        let high = number(high, u16::MAX)?;
                        if low > high {
                            return Err(ISSUE);
                        }
                        ports.push([low, high]);
                    }
                }
                let count = domains.len() + suffixes.len() + networks.len() + ports.len();
                self.values += count;
                self.names += domains.len() + suffixes.len();
                let references = map.get("rule_set");
                if (count == 0 && references.is_none()) || self.values > 256 {
                    return Err(ISSUE);
                }
                let mut condition = json!({"type":"match","domain":domains,"domain_suffix":suffixes,"ip_cidr":networks,"ports":ports,"invert":false});
                if let Some(references) = references {
                    condition = sets
                        .ok_or(ISSUE)?
                        .compose(references, condition, count == 0)?;
                }
                if invert {
                    let current = condition
                        .get("invert")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    condition["invert"] = json!(!current);
                }
                Ok(condition)
            }
            _ => Err(ISSUE),
        }
    }

    fn strings(&self, value: Option<&Value>) -> Result<Vec<String>, PolicyIssue> {
        let Some(value) = value else {
            return Ok(Vec::new());
        };
        let result = strings(value, ISSUE)?;
        if result.len() > 256 {
            return Err(ISSUE);
        }
        Ok(result)
    }
}

fn checked_policy(rules: &[Value]) -> Result<nm_tunnel_profile::RoutePolicy, PolicyIssue> {
    let text = serde_json::to_string(&json!({"version":1,"rules":rules})).map_err(|_| ISSUE)?;
    nm_tunnel_profile::RoutePolicy::from_json(&text).map_err(|_| ISSUE)
}

/// The shared model validates and normalizes declarations even when unused.
/// The temporary action does not survive expansion or grant any authority.
pub(super) fn checked_condition(condition: Value) -> Result<Value, PolicyIssue> {
    let policy = checked_policy(&[json!({"condition":condition,"action":"proxy"})])?;
    let mut document: Value = serde_json::from_str(policy.as_json()).map_err(|_| ISSUE)?;
    Ok(document["rules"][0]["condition"].take())
}

fn list(value: &Value) -> Result<Vec<&Value>, PolicyIssue> {
    let values = value
        .as_array()
        .map_or_else(|| vec![value], |values| values.iter().collect());
    if values.len() > 256 {
        return Err(ISSUE);
    }
    Ok(values)
}

#[cfg(test)]
#[path = "route_rules_tests.rs"]
mod tests;
