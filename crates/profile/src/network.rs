//! Execution-facing policy views. Import drafts and persisted schemas stay at the boundary.
use crate::{DnsOverride, DomainAction, Draft, Profile, SourcePolicy, TcpDomainPolicy};
use std::net::SocketAddr;

/// Mutually exclusive LAN behavior; no live interface or prefix authority is stored.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LanBypass {
    /// Normal full-tunnel capture.
    #[default]
    None,
    /// Only selected-uplink connected RFC1918 networks bypass the proxy.
    Connected,
    /// All RFC1918 destinations follow existing physical routes.
    Private,
}

/// Mutually exclusive handling of captured IPv4 DNS. FakeIP always intercepts DNS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsHandling {
    /// No explicit port-53 interception (CurrentNetwork's internal relay still applies).
    Passthrough,
    /// Intercept captured IPv4 UDP/TCP port 53 using the selected resolver.
    Intercept,
    /// Interception with persistent IPv4 synthetic identity ownership.
    FakeIp,
}

#[derive(Clone)]
enum Routing {
    Legacy {
        domains: Option<TcpDomainPolicy>,
        lan: LanBypass,
        dns: DnsHandling,
    },
    Complete(Box<SourcePolicy>),
}

/// Immutable checked network settings. Complete policy cannot carry competing
/// legacy overlays or disable its required interception/FakeIP protection.
#[derive(Clone)]
pub struct NetworkPolicy {
    dns_override: DnsOverride,
    routing: Routing,
}

impl std::fmt::Debug for NetworkPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NetworkPolicy([redacted])")
    }
}

impl NetworkPolicy {
    /// Validate only network settings from a boundary draft, without credentials or I/O.
    /// Errors are static and reject contradictions without mutating the draft.
    pub fn from_draft(draft: &Draft) -> Result<Self, Vec<crate::ValidationError>> {
        draft.validate_policy()?;
        Ok(Self::from_validated(draft))
    }
    /// Resolver selection; CurrentNetwork stores no live DHCP address.
    pub fn dns_override(&self) -> DnsOverride {
        self.dns_override
    }
    /// Checked DNS behavior without independent contradictory booleans.
    pub fn dns_handling(&self) -> DnsHandling {
        match &self.routing {
            Routing::Legacy { dns, .. } => *dns,
            Routing::Complete(_) => DnsHandling::FakeIp,
        }
    }
    /// Whether explicit IPv4 port-53 interception is required.
    pub fn intercepts_dns(&self) -> bool {
        self.dns_handling() != DnsHandling::Passthrough
    }
    /// Whether durable IPv4 synthetic identity ownership is required.
    pub fn fake_ip(&self) -> bool {
        self.dns_handling() == DnsHandling::FakeIp
    }
    /// Mutually exclusive LAN behavior. Complete routing owns its own IP actions.
    pub fn lan_bypass(&self) -> LanBypass {
        match &self.routing {
            Routing::Legacy { lan, .. } => *lan,
            Routing::Complete(_) => LanBypass::None,
        }
    }
    /// Optional legacy hostname overlay, never a competing complete policy.
    pub fn tcp_domains(&self) -> Option<&TcpDomainPolicy> {
        match &self.routing {
            Routing::Legacy { domains, .. } => domains.as_ref(),
            Routing::Complete(_) => None,
        }
    }
    /// Optional checked complete policy for resolver/TUN settings and root authority.
    pub fn source(&self) -> Option<&SourcePolicy> {
        match &self.routing {
            Routing::Complete(policy) => Some(policy),
            Routing::Legacy { .. } => None,
        }
    }
    /// Borrow pure routing semantics; this grants no socket authority.
    pub fn routing(&self) -> RoutingPolicy<'_> {
        match &self.routing {
            Routing::Legacy { domains, .. } => RoutingPolicy::Legacy(domains.as_ref()),
            Routing::Complete(policy) => RoutingPolicy::Complete(policy),
        }
    }
    pub(crate) fn from_validated(draft: &Draft) -> Self {
        let routing = if let Some(source) = &draft.source_policy {
            Routing::Complete(Box::new(source.clone()))
        } else {
            Routing::Legacy {
                domains: draft.tcp_domain_policy.clone(),
                lan: if draft.private_lan_bypass {
                    LanBypass::Private
                } else if draft.lan_bypass {
                    LanBypass::Connected
                } else {
                    LanBypass::None
                },
                dns: if draft.fake_ip {
                    DnsHandling::FakeIp
                } else if draft.dns_interception {
                    DnsHandling::Intercept
                } else {
                    DnsHandling::Passthrough
                },
            }
        };
        Self {
            dns_override: draft.dns_override,
            routing,
        }
    }
    /// Replace only network settings in an editable boundary copy. This does not
    /// validate or change its node/credential, persist anything, or affect a session.
    pub fn apply_to(&self, draft: &mut Draft) {
        draft.dns_override = self.dns_override;
        draft.tcp_domain_policy = self.tcp_domains().cloned();
        draft.lan_bypass = self.lan_bypass() == LanBypass::Connected;
        draft.private_lan_bypass = self.lan_bypass() == LanBypass::Private;
        draft.dns_interception = self.intercepts_dns();
        draft.fake_ip = self.fake_ip();
        draft.source_policy = self.source().cloned();
    }
}

/// Checked routing semantics, independent of URI, subscription or NM schema versions.
#[derive(Clone, Copy)]
pub enum RoutingPolicy<'a> {
    /// Legacy full-tunnel behavior with optional ordered hostname actions.
    Legacy(Option<&'a TcpDomainPolicy>),
    /// Complete native IPv4 policy with ordered domain and private-IP actions.
    Complete(&'a SourcePolicy),
}

impl RoutingPolicy<'_> {
    /// Explicit name action, distinct from a default proxy or private-IP action.
    pub fn domain_action(self, name: Option<&str>) -> Option<DomainAction> {
        match self {
            Self::Legacy(policy) => policy.and_then(|policy| policy.matched_action(name)),
            Self::Complete(policy) => policy.domain_action(name),
        }
    }

    /// Terminal action after DNS/classification and any legacy LAN dispatch.
    /// This pure decision grants no socket authority; supervisors revalidate requests.
    pub fn action(self, name: Option<&str>, destination: SocketAddr) -> DomainAction {
        match self {
            Self::Legacy(policy) => {
                policy.map_or(DomainAction::Proxy, |policy| policy.action(name))
            }
            Self::Complete(policy) => policy.action(name, destination, false),
        }
    }
}

impl Profile {
    /// Borrow execution semantics without exposing a foreign configuration format.
    pub fn routing(&self) -> RoutingPolicy<'_> {
        self.network().routing()
    }

    /// One checked LAN mode. Invalid combinations cannot construct a Profile.
    pub fn lan_bypass(&self) -> LanBypass {
        self.network().lan_bypass()
    }
}
