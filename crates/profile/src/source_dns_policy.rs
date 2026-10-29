//! Bounded real-resolution selection, independent of FakeIP and bootstrap.
use crate::{PolicyError, SourceDns, canonical_domain};
use serde::{Deserialize, Serialize};

/// Checked DNS route selected from an immutable source policy. Selection grants
/// no socket authority. CurrentNetwork uses the activation's NM uplink snapshot,
/// not host resolver discovery; endpoint detours never imply fallback.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceDnsSelection {
    /// Explicit Direct DNS using the current NM uplink DNS and interface.
    CurrentNetwork {},
    /// Explicit endpoint with its own checked Direct/Proxy detour.
    Endpoint {
        /// Checked real resolver; not a worker-supplied destination.
        dns: SourceDns,
    },
}

impl std::fmt::Debug for SourceDnsSelection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SourceDnsSelection([redacted])")
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DnsPolicy {
    version: u32,
    resolvers: Vec<SourceDnsSelection>,
    rules: Vec<Rule>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    #[serde(default)]
    domain: Vec<String>,
    #[serde(default)]
    domain_suffix: Vec<String>,
    resolver: usize,
}

impl DnsPolicy {
    pub fn validated(mut self) -> Result<Self, PolicyError> {
        if self.version != 1
            || self.resolvers.is_empty()
            || self.resolvers.len() > 8
            || self.rules.is_empty()
            || self.rules.len() > 64
        {
            return Err(PolicyError);
        }
        for resolver in &mut self.resolvers {
            if let SourceDnsSelection::Endpoint { dns } = resolver {
                *dns = dns.clone().validated()?;
            }
        }
        let mut names = 0;
        for rule in &mut self.rules {
            names += rule.domain.len() + rule.domain_suffix.len();
            if rule.resolver >= self.resolvers.len()
                || names > 128
                || rule.domain.len() + rule.domain_suffix.len() == 0
            {
                return Err(PolicyError);
            }
            for name in &mut rule.domain {
                *name = canonical_domain(name).ok_or(PolicyError)?;
            }
            for name in &mut rule.domain_suffix {
                let subdomains = name.starts_with('.');
                let canonical = canonical_domain(if subdomains { &name[1..] } else { name })
                    .ok_or(PolicyError)?;
                *name = if subdomains {
                    format!(".{canonical}")
                } else {
                    canonical
                };
            }
        }
        Ok(self)
    }

    pub fn select(&self, name: &str) -> Option<SourceDnsSelection> {
        self.rules
            .iter()
            .find(|rule| {
                rule.domain.iter().any(|value| value == name)
                    || rule.domain_suffix.iter().any(|suffix| {
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
            .map(|rule| self.resolvers[rule.resolver].clone())
    }
}
