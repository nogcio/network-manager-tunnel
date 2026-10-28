//! Pure outbound selection shared by TCP and UDP, without broker or socket access.
use crate::LanScope;
use nm_tunnel_profile::{DomainAction, NetworkPolicy, RoutingPolicy};
use std::{io, net::SocketAddr};

/// An intended route, never authority. Root independently verifies all Direct/LAN grants.
/// Legacy Direct requires a name; complete policy may authorize a private IP without one.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Decision<'a> {
    /// Reject without opening an outbound.
    Block,
    /// Use the fixed proxy endpoint.
    Proxy,
    /// Request independently checked LAN access.
    Lan,
    /// Request legacy domain-bound Direct access.
    LegacyDirect(&'a str),
    /// Request complete-policy Direct access; private-IP actions need no name.
    PolicyDirect(Option<&'a str>),
}

impl std::fmt::Debug for Decision<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Block => "Block",
            Self::Proxy => "Proxy",
            Self::Lan => "Lan",
            Self::LegacyDirect(_) => "LegacyDirect([redacted])",
            Self::PolicyDirect(_) => "PolicyDirect([redacted])",
        })
    }
}

/// Run only after DNS handling/classification and owned FakeIP destination resolution.
/// For legacy TCP, an early call with the resolved name determines LAN bypass before
/// sniffing; otherwise a second call uses the observed hostname. Complete policy's
/// domain/private-IP order is independent of legacy physical-LAN exceptions.
pub fn decide<'a>(
    policy: &NetworkPolicy,
    lan: &(impl LanScope + ?Sized),
    destination: SocketAddr,
    name: Option<&'a str>,
) -> io::Result<Decision<'a>> {
    let routing = policy.routing();
    match routing {
        RoutingPolicy::Complete(_) => Ok(match routing.action(name, destination) {
            DomainAction::Block => Decision::Block,
            DomainAction::Proxy => Decision::Proxy,
            DomainAction::Direct => Decision::PolicyDirect(name),
        }),
        RoutingPolicy::Legacy(policy) => {
            let explicit = policy.and_then(|policy| policy.matched_action(name));
            if explicit == Some(DomainAction::Block) {
                return Ok(Decision::Block);
            }
            if lan.is_local(destination) && explicit != Some(DomainAction::Proxy) {
                if !lan.authorizes(destination) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "LAN flow refused.",
                    ));
                }
                return Ok(Decision::Lan);
            }
            match explicit {
                Some(DomainAction::Direct) => {
                    Ok(Decision::LegacyDirect(name.ok_or_else(|| {
                        io::Error::other("Missing authorized hostname.")
                    })?))
                }
                _ => Ok(Decision::Proxy),
            }
        }
    }
}
