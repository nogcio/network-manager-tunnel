//! Pure DNS message policy and legacy defaults. No sockets, processes or host changes.
#[cfg(test)]
#[path = "dns_tests.rs"]
mod tests;
use hickory_proto::{
    op::{Message, Query},
    rr::{Name, RData, RecordType},
};
use std::{io, net::Ipv4Addr};

/// Resolver used by legacy inherited policy.
pub const LEGACY_VPN_DNS: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
/// Virtual resolver for current-network forwarding.
pub const INTERNAL_DNS: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
/// Reserved local FakeIP ownership check. Never query an upstream resolver for it.
pub const PROBE_HOST: &str = "readiness.nm-tunnel.invalid";
/// Maximum accepted DNS message, independently of its transport.
pub const MAX_DNS_BYTES: usize = 4096;

/// Admit one bounded IN query; malformed/unsupported messages error before I/O.
pub fn parse_query(bytes: &[u8]) -> io::Result<Message> {
    use hickory_proto::{
        op::{MessageType, OpCode},
        rr::DNSClass,
    };
    if bytes.is_empty() || bytes.len() > MAX_DNS_BYTES {
        return Err(invalid());
    }
    let query = Message::from_vec(bytes).map_err(|_| invalid())?;
    if query.message_type != MessageType::Query
        || query.op_code != OpCode::Query
        || query.queries.len() != 1
        || query.queries[0].query_class() != DNSClass::IN
        || !query.answers.is_empty()
        || !query.authorities.is_empty()
        || query.signature.is_some()
    {
        return Err(invalid());
    }
    Ok(query)
}

/// Bind a bounded response to its question and ID, without resolver fallback.
pub fn validate_response(query: &Message, bytes: &[u8]) -> io::Result<()> {
    use hickory_proto::op::{MessageType, OpCode};
    if bytes.is_empty() || bytes.len() > MAX_DNS_BYTES {
        return Err(invalid());
    }
    let response = Message::from_vec(bytes).map_err(|_| invalid())?;
    if response.message_type != MessageType::Response
        || response.op_code != OpCode::Query
        || response.id != query.id
        || response.queries != query.queries
    {
        return Err(invalid());
    }
    // Negative and truncated answers never trigger an implicit transport/resolver fallback.
    Ok(())
}

/// Redacted DNS rejection shared by transports.
pub fn invalid() -> io::Error {
    io::Error::other("Invalid or unsupported DNS exchange.")
}

/// Check that a selected uplink resolver is unicast and outside synthetic space.
pub fn valid_uplink_server(server: Ipv4Addr) -> bool {
    let [a, b, _, _] = server.octets();
    a != 0 && a < 224 && !server.is_loopback() && !(a == 198 && matches!(b, 18 | 19))
}

/// Frame DNS over an owned stream, rejecting frames above the message limit.
pub fn framed<S: tokio::io::AsyncRead + tokio::io::AsyncWrite>(
    stream: S,
) -> tokio_util::codec::Framed<S, tokio_util::codec::LengthDelimitedCodec> {
    tokio_util::codec::LengthDelimitedCodec::builder()
        .length_field_length(2)
        .max_frame_length(MAX_DNS_BYTES)
        .new_framed(stream)
}

/// Project the checked legacy resolver selection to its TUN-visible address.
pub fn profile_dns(mode: nm_tunnel_profile::DnsOverride) -> Ipv4Addr {
    match mode {
        nm_tunnel_profile::DnsOverride::Inherit => LEGACY_VPN_DNS,
        nm_tunnel_profile::DnsOverride::ProxyIpv4(ip) => ip,
        nm_tunnel_profile::DnsOverride::CurrentNetwork => INTERNAL_DNS,
    }
}

/// Build the local FakeIP check, with a fresh ID or a redacted encoding error.
/// This name has no external readiness or Internet reachability meaning.
pub fn dns_query() -> io::Result<(u16, Vec<u8>)> {
    query(PROBE_HOST)
}

/// Build an A query without resolving or opening sockets. Errors redact the name.
pub fn query(host: &str) -> io::Result<(u16, Vec<u8>)> {
    let id = u16::from_ne_bytes(
        uuid::Uuid::new_v4().as_bytes()[..2]
            .try_into()
            .map_err(|_| io::Error::other("DNS ID failed."))?,
    );
    let mut message = Message::new(
        id,
        hickory_proto::op::MessageType::Query,
        hickory_proto::op::OpCode::Query,
    );
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(
        Name::from_utf8(host).map_err(|_| io::Error::other("Invalid endpoint name."))?,
        RecordType::A,
    ));
    Ok((
        id,
        message
            .to_vec()
            .map_err(|_| io::Error::other("DNS query failed."))?,
    ))
}

/// Extract IPv4 answers, rejecting negative, truncated, empty or mismatched replies.
pub fn dns_answer(id: u16, bytes: &[u8]) -> io::Result<Vec<Ipv4Addr>> {
    let response =
        Message::from_vec(bytes).map_err(|_| io::Error::other("Invalid DNS response."))?;
    if response.id != id
        || response.truncation
        || response.response_code != hickory_proto::op::ResponseCode::NoError
        || response.message_type != hickory_proto::op::MessageType::Response
    {
        return Err(io::Error::other("DNS response refused."));
    }
    let ips: Vec<_> = response
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .collect();
    if ips.is_empty() {
        return Err(io::Error::other("No IPv4 endpoint."));
    }
    Ok(ips)
}

/// Bind the question and A/CNAME answer chain to the authorized domain and IP.
pub fn direct_dns_answer(
    id: u16,
    domain: &str,
    destination: std::net::IpAddr,
    bytes: &[u8],
) -> io::Result<bool> {
    dns_answer(id, bytes)?;
    let response =
        Message::from_vec(bytes).map_err(|_| io::Error::other("Invalid direct DNS response."))?;
    let mut name =
        Name::from_utf8(domain).map_err(|_| io::Error::other("Invalid direct DNS name."))?;
    name.set_fqdn(true);
    if response.op_code != hickory_proto::op::OpCode::Query
        || response.queries.len() != 1
        || response.queries[0] != Query::query(name.clone(), RecordType::A)
    {
        return Ok(false);
    }
    let mut current = name;
    for _ in 0..8 {
        if response.answers.iter().any(|record| {
            record.name == current
                && record.dns_class == hickory_proto::rr::DNSClass::IN
                && matches!(&record.data, RData::A(ip) if std::net::IpAddr::V4(ip.0) == destination)
        }) {
            return Ok(true);
        }
        let Some(next) = response.answers.iter().find_map(|record| {
            if record.name != current || record.dns_class != hickory_proto::rr::DNSClass::IN {
                return None;
            }
            match &record.data {
                RData::CNAME(name) => Some(name.0.clone()),
                _ => None,
            }
        }) else {
            return Ok(false);
        };
        current = next;
    }
    Ok(false)
}
