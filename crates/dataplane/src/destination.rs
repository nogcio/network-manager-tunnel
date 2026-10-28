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
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        resolve_inner(profile, broker, endpoint, destination, lan),
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
    if profile.routing().domain_action(Some(&name)) == Some(nm_tunnel_profile::DomainAction::Block)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Blocked FakeIP identity.",
        ));
    }
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
