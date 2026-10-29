//! Bounded inline destination predicates, compiled away without file/network I/O.
use super::{PolicyIssue, route_rules, value::*};
use serde_json::{Value, json};
use std::collections::HashMap;

const ISSUE: PolicyIssue = PolicyIssue::Routing;
const MAX_SETS: usize = 32;
const MAX_NODES: usize = 128;
const MAX_NAMES: usize = 128;

#[derive(Clone, Default)]
pub(super) struct Names {
    pub domains: Vec<String>,
    pub suffixes: Vec<String>,
}

impl Names {
    fn extend(&mut self, other: &Self) -> Result<(), PolicyIssue> {
        if self.domains.len() + self.suffixes.len() + other.domains.len() + other.suffixes.len()
            > MAX_NAMES
        {
            return Err(ISSUE);
        }
        self.domains.extend(other.domains.iter().cloned());
        self.suffixes.extend(other.suffixes.iter().cloned());
        Ok(())
    }
}

struct InlineSet {
    rules: Vec<Value>,
    names: Option<Names>,
}

pub(super) struct InlineSets(HashMap<String, InlineSet>);

impl InlineSets {
    pub fn parse(value: Option<&Value>) -> Result<Self, PolicyIssue> {
        let Some(value) = value else {
            return Ok(Self(HashMap::new()));
        };
        let sets = value.as_array().ok_or(ISSUE)?;
        if sets.len() > MAX_SETS
            || serde_json::to_vec(value).map_err(|_| ISSUE)?.len()
                > nm_tunnel_profile::MAX_POLICY_BYTES
        {
            return Err(ISSUE);
        }
        let mut result = HashMap::new();
        let mut budget = route_rules::Budget::default();
        for set in sets {
            let set = object(set, &["type", "tag", "rules"], ISSUE)?;
            if !matches!(optional_text(set, "type", ISSUE)?, "" | "inline") {
                return Err(ISSUE);
            }
            let tag = text(set, "tag", ISSUE)?;
            if !label(tag) || result.contains_key(tag) {
                return Err(ISSUE);
            }
            let rules = set.get("rules").and_then(Value::as_array).ok_or(ISSUE)?;
            if rules.is_empty() || rules.len() > MAX_NODES {
                return Err(ISSUE);
            }
            let mut predicates = Vec::new();
            for rule in rules {
                let condition = budget.condition(rule, None, 1)?;
                if budget.names > MAX_NAMES {
                    return Err(ISSUE);
                }
                predicates.push(route_rules::checked_condition(condition)?);
            }
            let mut names = Some(Names::default());
            for rule in &predicates {
                match (&mut names, flat_names(rule)?) {
                    (Some(names), Some(other)) => names.extend(&other)?,
                    _ => names = None,
                }
            }
            result.insert(
                tag.to_owned(),
                InlineSet {
                    rules: predicates,
                    names,
                },
            );
        }
        Ok(Self(result))
    }

    /// Legacy domain-only OR sets keep their original source-v1 representation.
    pub fn referenced(&self, value: &Value) -> Result<Names, PolicyIssue> {
        let mut result = Names::default();
        for set in self.references(value)? {
            result.extend(set.names.as_ref().ok_or(ISSUE)?)?;
        }
        Ok(result)
    }

    pub fn requires_v2(&self, references: &Value) -> Result<bool, PolicyIssue> {
        Ok(self
            .references(references)?
            .iter()
            .any(|set| set.names.is_none()))
    }

    fn references(&self, value: &Value) -> Result<Vec<&InlineSet>, PolicyIssue> {
        let count = value.as_array().map_or(1, Vec::len);
        if count == 0 || count > MAX_SETS {
            return Err(ISSUE);
        }
        strings(value, ISSUE)?
            .into_iter()
            .map(|tag| self.0.get(&tag).ok_or(ISSUE))
            .collect()
    }

    /// Single non-inverted default entries merge like groups (address OR and
    /// port OR). Other shapes stay self-contained and AND the outer condition.
    /// Each tag is a separate OR branch: never union groups across different tags.
    pub fn compose(&self, value: &Value, outer: Value, empty: bool) -> Result<Value, PolicyIssue> {
        let mut branches = Vec::new();
        for set in self.references(value)? {
            let single = &set.rules[0];
            let branch =
                if set.rules.len() == 1 && single["type"] == "match" && single["invert"] == false {
                    let mut merged = outer.clone();
                    for key in ["domain", "domain_suffix", "ip_cidr", "ports"] {
                        merged[key]
                            .as_array_mut()
                            .ok_or(ISSUE)?
                            .extend(single[key].as_array().ok_or(ISSUE)?.iter().cloned());
                    }
                    merged
                } else {
                    let own = group("or", set.rules.clone());
                    if empty {
                        own
                    } else {
                        group("and", vec![outer.clone(), own])
                    }
                };
            branches.push(branch);
            // Bound expansion incrementally before another tag is cloned.
            route_rules::checked_condition(group("or", branches.clone()))?;
        }
        Ok(group("or", branches))
    }
}

fn group(mode: &str, mut rules: Vec<Value>) -> Value {
    if rules.len() == 1 {
        rules.remove(0)
    } else {
        json!({"type":"logical","mode":mode,"rules":rules,"invert":false})
    }
}

fn flat_names(condition: &Value) -> Result<Option<Names>, PolicyIssue> {
    if condition["invert"] == true {
        return Ok(None);
    }
    if condition["type"] == "match" {
        if !condition["ip_cidr"].as_array().ok_or(ISSUE)?.is_empty()
            || !condition["ports"].as_array().ok_or(ISSUE)?.is_empty()
        {
            return Ok(None);
        }
        return Ok(Some(Names {
            domains: strings(&condition["domain"], ISSUE)?,
            suffixes: strings(&condition["domain_suffix"], ISSUE)?,
        }));
    }
    if condition["mode"] != "or" {
        return Ok(None);
    }
    let mut names = Names::default();
    for rule in condition["rules"].as_array().ok_or(ISSUE)? {
        let Some(other) = flat_names(rule)? else {
            return Ok(None);
        };
        names.extend(&other)?;
    }
    Ok(Some(names))
}

#[cfg(test)]
#[path = "rule_sets_tests.rs"]
mod tests;
