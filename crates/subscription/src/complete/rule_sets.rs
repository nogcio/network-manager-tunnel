//! Bounded domain-only inline sets, compiled away before native policy admission.
use super::{PolicyIssue, value::*};
use serde_json::Value;
use std::collections::HashMap;

const ISSUE: PolicyIssue = PolicyIssue::Routing;
const MAX_SETS: usize = 32;
const MAX_NODES: usize = 128;
const MAX_NAMES: usize = 128;
const MAX_DEPTH: usize = 8;

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

pub(super) struct InlineSets(HashMap<String, Names>);

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
        let mut budget = Budget { nodes: 0, names: 0 };
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
            let mut names = Names::default();
            for rule in rules {
                names.extend(&budget.rule(rule, 1)?)?;
            }
            result.insert(tag.to_owned(), names);
        }
        Ok(Self(result))
    }

    /// Multiple tags are ORed. A route combining these with another match group
    /// must be rejected by the caller: concatenation would erase an AND condition.
    pub fn referenced(&self, value: &Value) -> Result<Names, PolicyIssue> {
        let count = value.as_array().map_or(1, Vec::len);
        if count == 0 || count > MAX_SETS {
            return Err(ISSUE);
        }
        let tags = strings(value, ISSUE)?;
        let mut result = Names::default();
        for tag in tags {
            result.extend(self.0.get(&tag).ok_or(ISSUE)?)?;
        }
        Ok(result)
    }
}

struct Budget {
    nodes: usize,
    names: usize,
}

impl Budget {
    fn rule(&mut self, value: &Value, depth: usize) -> Result<Names, PolicyIssue> {
        self.nodes += 1;
        if depth > MAX_DEPTH || self.nodes > MAX_NODES {
            return Err(ISSUE);
        }
        let map = value.as_object().ok_or(ISSUE)?;
        if flag(map, "invert", false, ISSUE)? {
            return Err(ISSUE);
        }
        match optional_text(map, "type", ISSUE)? {
            "logical" => {
                object(value, &["type", "mode", "rules", "invert"], ISSUE)?;
                if text(map, "mode", ISSUE)? != "or" {
                    return Err(ISSUE);
                }
                let rules = map.get("rules").and_then(Value::as_array).ok_or(ISSUE)?;
                if rules.is_empty() || rules.len() > MAX_NODES {
                    return Err(ISSUE);
                }
                let mut result = Names::default();
                for rule in rules {
                    result.extend(&self.rule(rule, depth + 1)?)?;
                }
                Ok(result)
            }
            "" | "default" => {
                object(value, &["type", "domain", "domain_suffix", "invert"], ISSUE)?;
                let domains = self.names(map.get("domain"), false)?;
                let suffixes = self.names(map.get("domain_suffix"), true)?;
                if domains.is_empty() && suffixes.is_empty() {
                    return Err(ISSUE);
                }
                Ok(Names { domains, suffixes })
            }
            _ => Err(ISSUE),
        }
    }

    fn names(&mut self, value: Option<&Value>, suffix: bool) -> Result<Vec<String>, PolicyIssue> {
        let Some(value) = value else {
            return Ok(Vec::new());
        };
        let count = value.as_array().map_or(1, Vec::len);
        if count > MAX_NAMES - self.names {
            return Err(ISSUE);
        }
        self.names += count;
        strings(value, ISSUE)?
            .into_iter()
            .map(|name| {
                let subdomains_only = suffix && name.starts_with('.');
                let name = nm_tunnel_profile::canonical_domain(if subdomains_only {
                    &name[1..]
                } else {
                    &name
                })
                .ok_or(ISSUE)?;
                Ok(if subdomains_only {
                    format!(".{name}")
                } else {
                    name
                })
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "rule_sets_tests.rs"]
mod tests;
