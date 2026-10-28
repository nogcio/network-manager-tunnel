//! Activation-local selected-resolver cache and independent Direct authorization.
use crate::dns;
use nm_tunnel_profile::Profile;
use std::{collections::HashMap, io, net::SocketAddr, time::Duration};
use tokio::time::{Instant, timeout};

/// Selected DNS transport authority. Implementations derive upstreams from the
/// checked profile, never caller-supplied resolvers, and own endpoint bypass and
/// bootstrap. Errors/cancellation must not retry on a different route/resolver.
#[async_trait::async_trait]
pub trait Exchange: Send + Sync {
    /// Perform one selected exchange. Responses are validated by the shared owner.
    async fn exchange(&self, profile: &Profile, bytes: &[u8], tcp: bool) -> io::Result<Vec<u8>>;
}

/// One activation's independent DNS authority. Never share the cache with an
/// untrusted worker or across profile/uplink changes. Drop forgets only this cache.
pub struct Resolver<T> {
    profile: Profile,
    transport: T,
    cache: HashMap<Vec<u8>, (Instant, hickory_proto::op::Message, u32)>,
}

impl<T: Exchange> Resolver<T> {
    /// Create an empty activation-local cache over the platform DNS transport.
    pub fn new(profile: Profile, transport: T) -> Self {
        Self {
            profile,
            transport,
            cache: HashMap::new(),
        }
    }

    /// Validate before I/O, age cached TTLs and bind cache entries to question and
    /// transport. One ten-second exchange budget; failure does not mutate the cache
    /// or fall back. Cancellation retains transport semantics and publishes no entry.
    pub async fn query(&mut self, bytes: &[u8], tcp: bool) -> io::Result<Vec<u8>> {
        let query = dns::parse_query(bytes)?;
        let mut keyed = query.clone();
        keyed.metadata.id = 0;
        let mut key = keyed.to_vec().map_err(|_| failed())?;
        key.push(u8::from(tcp));
        if let Some((created, message, ttl)) = self.cache.get(&key) {
            let age = created.elapsed().as_secs();
            if age < u64::from(*ttl) {
                let mut message = message.clone();
                message.metadata.id = query.id;
                for record in message
                    .answers
                    .iter_mut()
                    .chain(message.authorities.iter_mut())
                    .chain(message.additionals.iter_mut())
                {
                    record.ttl = record.ttl.saturating_sub(age as u32);
                }
                return message.to_vec().map_err(|_| failed());
            }
        }
        let response = timeout(
            Duration::from_secs(10),
            self.transport.exchange(&self.profile, bytes, tcp),
        )
        .await
        .map_err(|_| failed())??;
        dns::validate_response(&query, &response)?;
        let message = hickory_proto::op::Message::from_vec(&response).map_err(|_| failed())?;
        if !message.truncation && message.signature.is_none() && !message.answers.is_empty() {
            let ttl = message
                .answers
                .iter()
                .chain(message.authorities.iter())
                .chain(message.additionals.iter())
                .map(|record| record.ttl)
                .min()
                .unwrap_or(0);
            self.cache
                .retain(|_, (created, _, ttl)| created.elapsed().as_secs() < u64::from(*ttl));
            if self.cache.len() >= 256
                && let Some(old) = self.cache.keys().next().cloned()
            {
                self.cache.remove(&old);
            }
            if ttl > 0 {
                self.cache.insert(key, (Instant::now(), message, ttl));
            }
        }
        Ok(response)
    }

    /// Independently authorize a complete-policy Direct destination before any
    /// application socket exists. Public named destinations require selected-resolver
    /// membership; private-IP actions remain distinct. No worker decision is trusted.
    /// Refusal is final and redacted; cancellation never grants an application socket.
    pub async fn authorize_direct(
        &mut self,
        domain: Option<&str>,
        destination: SocketAddr,
    ) -> io::Result<()> {
        let policy = self.profile.network().source().ok_or_else(failed)?;
        let std::net::IpAddr::V4(ip) = destination.ip() else {
            return Err(failed());
        };
        if matches!(destination.port(), 0 | 53)
            || policy.synthetic(ip)
            || policy.action(domain, destination, false) != nm_tunnel_profile::DomainAction::Direct
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Source Direct destination refused.",
            ));
        }
        if let Some(name) = domain {
            if nm_tunnel_profile::canonical_domain(name).as_deref() != Some(name) {
                return Err(failed());
            }
            if !nm_tunnel_profile::non_public_ipv4(ip) {
                let (id, query) = dns::query(name)?;
                let answer = self.query(&query, false).await?;
                if !dns::direct_dns_answer(id, name, destination.ip(), &answer)? {
                    return Err(failed());
                }
            }
        } else if !nm_tunnel_profile::non_public_ipv4(ip) {
            return Err(failed());
        }
        Ok(())
    }
}

/// Redacted selected DNS/authorization failure; never a signal to fall back.
pub fn failed() -> io::Error {
    io::Error::other("Source DNS or Direct authorization failed; no fallback is allowed.")
}

#[cfg(test)]
#[path = "source_dns_tests.rs"]
mod tests;
