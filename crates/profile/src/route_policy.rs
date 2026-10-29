//! Bounded complete-policy predicates. Matching is never socket authority.
use crate::{DomainAction, PolicyError, canonical_domain};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Clone, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
struct Network(Ipv4Net);

impl TryFrom<String> for Network {
    type Error = PolicyError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let net = if value.contains('/') {
            value.parse::<Ipv4Net>().map_err(|_| PolicyError)?
        } else {
            Ipv4Net::new(value.parse().map_err(|_| PolicyError)?, 32).map_err(|_| PolicyError)?
        };
        Ok(Self(net.trunc()))
    }
}

impl From<Network> for String {
    fn from(value: Network) -> Self {
        value.0.to_string()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Condition {
    Match {
        #[serde(default)]
        domain: Vec<String>,
        #[serde(default)]
        domain_suffix: Vec<String>,
        #[serde(default)]
        ip_cidr: Vec<Network>,
        #[serde(default)]
        ports: Vec<[u16; 2]>,
        #[serde(default)]
        invert: bool,
    },
    Logical {
        mode: Mode,
        rules: Vec<Condition>,
        #[serde(default)]
        invert: bool,
    },
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    And,
    Or,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    condition: Condition,
    action: DomainAction,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    rules: Vec<Rule>,
}

#[derive(Clone)]
/// Bounded ordered destination predicates for complete source-policy v2.
/// Native predicate schema v1 supports exact/suffix names, IPv4 CIDRs, destination
/// port intervals and logical AND/OR/inversion. Address alternatives are ORed;
/// the port group is ANDed. First match wins, without implicit DNS or socket I/O.
pub struct RoutePolicy {
    document: Document,
    encoded: String,
}

impl std::fmt::Debug for RoutePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RoutePolicy([redacted])")
    }
}

impl RoutePolicy {
    /// Atomically parse/canonicalize native schema v1. At most 64 terminal rules,
    /// 128 condition nodes, depth 8 and 256 match values; no empty conditions.
    /// Names/CIDRs are normalized; input is never mutated or retained verbatim.
    ///
    /// # Errors
    /// Returns a redacted [`PolicyError`] for unknown fields/versions, invalid
    /// names or IPv4 CIDRs, zero/reversed port intervals or exceeded budgets.
    pub fn from_json(input: &str) -> Result<Self, PolicyError> {
        if input.len() > crate::MAX_POLICY_BYTES {
            return Err(PolicyError);
        }
        let mut document: Document = serde_json::from_str(input).map_err(|_| PolicyError)?;
        if document.version != 1 || document.rules.is_empty() || document.rules.len() > 64 {
            return Err(PolicyError);
        }
        let mut budget = Budget::default();
        for rule in &mut document.rules {
            rule.condition.validate(1, &mut budget)?;
        }
        let encoded = serde_json::to_string(&document).map_err(|_| PolicyError)?;
        if encoded.len() > crate::MAX_POLICY_BYTES {
            return Err(PolicyError);
        }
        Ok(Self { document, encoded })
    }

    /// Canonical native representation. Contains identifying names/addresses;
    /// never include it in logs. Serialization grants no runtime authority.
    pub fn as_json(&self) -> &str {
        &self.encoded
    }

    /// First explicit decision, not a default or Direct authorization. An
    /// unresolved FQDN has no IP: CIDR alternatives do not match it. No DNS is
    /// performed just to satisfy an IP rule. Inversion applies to the whole node,
    /// including a false missing-name/IP match. Invalid names/zero ports yield None.
    pub fn matched_action(
        &self,
        name: Option<&str>,
        ip: Option<Ipv4Addr>,
        port: u16,
    ) -> Option<DomainAction> {
        let canonical = name.and_then(canonical_domain);
        if port == 0 || (name.is_some() && canonical.is_none()) {
            return None;
        }
        self.document.rules.iter().find_map(|rule| {
            rule.condition
                .matches(canonical.as_deref(), ip, port)
                .then_some(rule.action)
        })
    }
}

#[derive(Default)]
struct Budget {
    nodes: usize,
    values: usize,
}

impl Condition {
    fn validate(&mut self, depth: usize, budget: &mut Budget) -> Result<(), PolicyError> {
        budget.nodes += 1;
        if depth > 8 || budget.nodes > 128 {
            return Err(PolicyError);
        }
        match self {
            Self::Match {
                domain,
                domain_suffix,
                ip_cidr,
                ports,
                ..
            } => {
                let count = domain.len() + domain_suffix.len() + ip_cidr.len() + ports.len();
                budget.values += count;
                if count == 0 || budget.values > 256 || ports.iter().any(|[a, b]| *a == 0 || a > b)
                {
                    return Err(PolicyError);
                }
                for name in domain {
                    *name = canonical_domain(name).ok_or(PolicyError)?;
                }
                for name in domain_suffix {
                    let children = name.starts_with('.');
                    let value = canonical_domain(name.strip_prefix('.').unwrap_or(name))
                        .ok_or(PolicyError)?;
                    *name = if children { format!(".{value}") } else { value };
                }
            }
            Self::Logical { rules, .. } => {
                if rules.is_empty() || rules.len() > 128 {
                    return Err(PolicyError);
                }
                for rule in rules {
                    rule.validate(depth + 1, budget)?;
                }
            }
        }
        Ok(())
    }

    fn matches(&self, name: Option<&str>, ip: Option<Ipv4Addr>, port: u16) -> bool {
        let (matched, invert) = match self {
            Self::Match {
                domain,
                domain_suffix,
                ip_cidr,
                ports,
                invert,
            } => {
                let has_address =
                    !domain.is_empty() || !domain_suffix.is_empty() || !ip_cidr.is_empty();
                let address = !has_address
                    || name.is_some_and(|name| {
                        domain.iter().any(|value| value == name)
                            || domain_suffix.iter().any(|suffix| {
                                if suffix.starts_with('.') {
                                    name.ends_with(suffix)
                                } else {
                                    name == suffix
                                        || name
                                            .strip_suffix(suffix)
                                            .is_some_and(|prefix| prefix.ends_with('.'))
                                }
                            })
                    })
                    || ip.is_some_and(|ip| ip_cidr.iter().any(|net| net.0.contains(&ip)));
                (
                    address
                        && (ports.is_empty()
                            || ports.iter().any(|[a, b]| (*a..=*b).contains(&port))),
                    *invert,
                )
            }
            Self::Logical {
                mode,
                rules,
                invert,
            } => (
                match mode {
                    Mode::And => rules.iter().all(|rule| rule.matches(name, ip, port)),
                    Mode::Or => rules.iter().any(|rule| rule.matches(name, ip, port)),
                },
                *invert,
            ),
        };
        matched != invert
    }
}
