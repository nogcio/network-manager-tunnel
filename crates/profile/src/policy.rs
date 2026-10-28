//! Bounded, versioned TCP hostname rules; not an opaque foreign-engine config.
use serde::{Deserialize, Serialize};

/// Maximum encoded TCP policy size, including all rule names.
pub const MAX_POLICY_BYTES: usize = 16 * 1024;

/// Terminal action for a TCP hostname. No match always stays in the VPN.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainAction {
    /// Forward through the selected VPN, without a direct fallback.
    Proxy,
    /// Request an explicitly authorized, uplink-bound socket from the supervisor.
    Direct,
    /// Close the flow without requesting any upstream socket.
    Block,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    #[serde(default)]
    domain: Vec<String>,
    #[serde(default)]
    domain_suffix: Vec<String>,
    action: DomainAction,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    rules: Vec<Rule>,
}

/// Validated ordered rules for HTTP Host/TLS SNI obtained by the protocol library.
/// Exact and suffix alternatives within a rule are ORed; the first match wins.
/// A suffix without a leading dot matches its apex and subdomains; a leading dot
/// matches subdomains only. No IP-to-domain inference or suffix substring match.
/// This is explicitly TCP-only, not sing-box/FakeIP/UDP policy compatibility.
#[derive(Clone)]
pub struct TcpDomainPolicy {
    document: Document,
    encoded: String,
}

impl std::fmt::Debug for TcpDomainPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TcpDomainPolicy([redacted])")
    }
}

/// Sanitized admission error, never containing policy text, domains or JSON errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("Unsupported or invalid TCP domain policy.")]
pub struct PolicyError;

/// Canonical ASCII DNS name, without an optional terminal root dot. IP literals,
/// wildcards, empty/oversized labels, URL syntax and implicit IDNA are rejected.
pub fn canonical_domain(input: &str) -> Option<String> {
    let name = input.strip_suffix('.').unwrap_or(input);
    if name.is_empty() || name.len() > 253 || name.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    if !name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) {
        return None;
    }
    Some(name.to_ascii_lowercase())
}

impl TcpDomainPolicy {
    pub(crate) fn has_direct(&self) -> bool {
        self.document
            .rules
            .iter()
            .any(|rule| rule.action == DomainAction::Direct)
    }
    /// Parse schema version 1 atomically, before any networking. At most 64 rules
    /// and 128 names total; unknown fields, actions and versions are errors.
    /// Domains are normalized explicitly. The original JSON is not retained.
    pub fn from_json(input: &str) -> Result<Self, PolicyError> {
        if input.len() > MAX_POLICY_BYTES {
            return Err(PolicyError);
        }
        let mut document: Document = serde_json::from_str(input).map_err(|_| PolicyError)?;
        if document.version != 1 || document.rules.is_empty() || document.rules.len() > 64 {
            return Err(PolicyError);
        }
        let mut count = 0;
        for rule in &mut document.rules {
            if rule.domain.is_empty() && rule.domain_suffix.is_empty() {
                return Err(PolicyError);
            }
            count += rule.domain.len() + rule.domain_suffix.len();
            if count > 128 {
                return Err(PolicyError);
            }
            for name in &mut rule.domain {
                *name = canonical_domain(name).ok_or(PolicyError)?;
            }
            for name in &mut rule.domain_suffix {
                let subdomains_only = name.starts_with('.');
                let normalized =
                    canonical_domain(name.strip_prefix('.').unwrap_or(name)).ok_or(PolicyError)?;
                *name = if subdomains_only {
                    format!(".{normalized}")
                } else {
                    normalized
                };
            }
        }
        let encoded = serde_json::to_string(&document).map_err(|_| PolicyError)?;
        if encoded.len() > MAX_POLICY_BYTES {
            return Err(PolicyError);
        }
        Ok(Self { document, encoded })
    }

    /// Canonical versioned NM representation; contains no authentication material.
    /// Hostnames may be identifying: never include this in diagnostics.
    pub fn as_json(&self) -> &str {
        &self.encoded
    }

    /// Evaluate an observed or owned hostname. Invalid/absent names never grant
    /// direct access. Unknown names use Proxy, including encrypted/unsniffable names.
    pub fn action(&self, domain: Option<&str>) -> DomainAction {
        self.matched_action(domain).unwrap_or(DomainAction::Proxy)
    }

    /// First explicit decision, distinguishing Proxy from the default when a
    /// FakeIP domain rule precedes local-IP fallback. Invalid names yield None.
    pub fn matched_action(&self, domain: Option<&str>) -> Option<DomainAction> {
        let domain = domain.and_then(canonical_domain)?;
        for rule in &self.document.rules {
            if rule.domain.contains(&domain)
                || rule.domain_suffix.iter().any(|suffix| {
                    if suffix.starts_with('.') {
                        domain.ends_with(suffix)
                    } else {
                        domain == *suffix
                            || domain
                                .strip_suffix(suffix)
                                .is_some_and(|prefix| prefix.ends_with('.'))
                    }
                })
            {
                return Some(rule.action);
            }
        }
        None
    }
}
