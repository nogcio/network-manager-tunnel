//! FakeIP ownership is resolved before outbound admission, never guessed from IP.
use super::resolver;
use crate::{Host, LanScope, dns, fakeip};
use std::{
    io,
    net::{IpAddr, SocketAddr},
};

/// An owned real destination and optional durable synthetic-name identity.
pub struct Destination {
    /// Real IPv4 socket destination, not permission to dial it directly.
    pub address: SocketAddr,
    /// Canonical name supplied by the identity owner, not by traffic sniffing.
    pub domain: Option<String>,
}

/// Resolve owned FakeIP before route admission, within ten seconds. Unknown or
/// blocked identities error without requesting an outbound; cancellation retains
/// host semantics. No guessed reverse mapping or physical DNS fallback is allowed.
pub async fn resolve(
    profile: &nm_tunnel_profile::Profile,
    broker: &(impl Host + ?Sized),
    endpoint: SocketAddr,
    destination: SocketAddr,
    lan: &(impl LanScope + ?Sized),
) -> io::Result<Destination> {
    resolve_with_sniffed_name(profile, broker, endpoint, destination, lan, None).await
}

/// Keep the FakeIP identity as the destination while complete-policy rules prefer
/// the separately observed name. Legacy identity precedence remains unchanged.
/// A sniffed name is never authority: Host independently authorizes Direct grants.
pub(crate) async fn resolve_with_sniffed_name(
    profile: &nm_tunnel_profile::Profile,
    broker: &(impl Host + ?Sized),
    endpoint: SocketAddr,
    destination: SocketAddr,
    lan: &(impl LanScope + ?Sized),
    observed: Option<&str>,
) -> io::Result<Destination> {
    if profile.network().source().is_some()
        && observed
            .is_some_and(|name| nm_tunnel_profile::canonical_domain(name).as_deref() != Some(name))
    {
        return Err(io::Error::other("Invalid observed source-policy name."));
    }
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        resolve_inner(profile, broker, endpoint, destination, lan, observed),
    )
    .await
    .map_err(|_| io::Error::other("FakeIP destination deadline."))?
}

async fn resolve_inner(
    profile: &nm_tunnel_profile::Profile,
    broker: &(impl Host + ?Sized),
    endpoint: SocketAddr,
    destination: SocketAddr,
    lan: &(impl LanScope + ?Sized),
    observed: Option<&str>,
) -> io::Result<Destination> {
    let IpAddr::V4(ip) = destination.ip() else {
        return Err(io::Error::other("IPv6 flow is unsupported."));
    };
    let source = profile.network().source();
    if !fakeip::in_range(ip) && !source.is_some_and(|policy| policy.synthetic(ip)) {
        return Ok(Destination {
            address: destination,
            domain: None,
        });
    }
    if !profile.network().fake_ip() {
        return Err(io::Error::other("Unowned synthetic destination refused."));
    }
    let name = broker.fake_reverse(ip).await?;
    if profile
        .routing()
        .domain_action(routing_name(profile, Some(&name), observed))
        == Some(nm_tunnel_profile::DomainAction::Block)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Blocked FakeIP identity.",
        ));
    }
    resolve_name(profile, broker, endpoint, destination, lan, name).await
}

async fn resolve_name(
    profile: &nm_tunnel_profile::Profile,
    broker: &(impl Host + ?Sized),
    endpoint: SocketAddr,
    destination: SocketAddr,
    lan: &(impl LanScope + ?Sized),
    name: String,
) -> io::Result<Destination> {
    let source = profile.network().source();
    let (id, query) = dns::query(&name)?;
    let response = resolver::relay_query(profile, broker, endpoint, &query, false).await?;
    let addresses = dns::dns_answer(id, &response)?;
    let ip = addresses
        .into_iter()
        .find(|ip| {
            let permitted = source.is_some_and(|policy| !policy.synthetic(*ip))
                || nm_tunnel_profile::DnsOverride::ProxyIpv4(*ip)
                    .validate()
                    .is_ok()
                || (source.is_some() && nm_tunnel_profile::non_public_ipv4(*ip))
                || lan.authorizes(SocketAddr::from((*ip, destination.port())));
            permitted
                && dns::direct_dns_answer(id, &name, IpAddr::V4(*ip), &response).unwrap_or(false)
        })
        .ok_or_else(|| io::Error::other("No permitted DNS address for FakeIP identity."))?;
    Ok(Destination {
        address: SocketAddr::from((ip, destination.port())),
        domain: Some(name),
    })
}

pub(crate) enum TcpDestination {
    /// An owned original name routed through Proxy, never a Direct capability.
    ProxyDomain {
        name: String,
        port: u16,
    },
    Resolved(Destination),
}

/// Resolve only ownership before routing a complete FakeIP TCP destination.
/// Unresolved FQDNs do not match IP-only rules. Direct resolves the original name
/// through the selected DNS and still requires independent Host authorization.
/// Explicit DNS overrides retain pre-resolution rather than moving DNS remotely.
pub(crate) async fn prepare_tcp(
    profile: &nm_tunnel_profile::Profile,
    broker: &(impl Host + ?Sized),
    endpoint: SocketAddr,
    destination: SocketAddr,
    lan: &(impl LanScope + ?Sized),
    observed: Option<&str>,
) -> io::Result<TcpDestination> {
    let synthetic = match destination.ip() {
        IpAddr::V4(ip) => profile.network().source().is_some_and(|s| s.synthetic(ip)),
        _ => false,
    };
    if !synthetic || profile.network().dns_override() != nm_tunnel_profile::DnsOverride::Inherit {
        return resolve_with_sniffed_name(profile, broker, endpoint, destination, lan, observed)
            .await
            .map(TcpDestination::Resolved);
    }
    if destination.port() == 0
        || !profile.network().fake_ip()
        || observed.is_some_and(|n| nm_tunnel_profile::canonical_domain(n).as_deref() != Some(n))
    {
        return Err(io::Error::other("Invalid complete TCP destination."));
    }
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let IpAddr::V4(ip) = destination.ip() else {
            return Err(io::Error::other("IPv6 flow is unsupported."));
        };
        let name = broker.fake_reverse(ip).await?;
        if nm_tunnel_profile::canonical_domain(&name).as_deref() != Some(name.as_str()) {
            return Err(io::Error::other("Invalid owned destination identity."));
        }
        match profile
            .routing()
            .domain_action(routing_name(profile, Some(&name), observed))
        {
            Some(nm_tunnel_profile::DomainAction::Block) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Blocked FakeIP identity.",
            )),
            Some(nm_tunnel_profile::DomainAction::Direct) => {
                resolve_name(profile, broker, endpoint, destination, lan, name)
                    .await
                    .map(TcpDestination::Resolved)
            }
            _ => Ok(TcpDestination::ProxyDomain {
                name,
                port: destination.port(),
            }),
        }
    })
    .await
    .map_err(|_| io::Error::other("FakeIP destination deadline."))?
}

/// Complete rules use sniffed metadata before the original FQDN, as sing-box does.
/// This never replaces the original destination or grants socket authority.
pub(crate) fn routing_name<'a>(
    profile: &nm_tunnel_profile::Profile,
    identity: Option<&'a str>,
    observed: Option<&'a str>,
) -> Option<&'a str> {
    if profile.network().source().is_some() {
        observed.or(identity)
    } else {
        identity.or(observed)
    }
}
