//! Append-only FakeIP identities, independent of storage paths and OS permissions.
use meow_dns::fakeip::{MemoryStore, Pool};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

const PREFIX: &str = "198.18.0.0/16";
/// Existing journal version/range; platforms must never silently reset an epoch.
pub const HEADER: &[u8] = b"{\"version\":1,\"range\":\"198.18.0.0/16\"}\n";
/// Admission bound below allocator eviction/wrap, not a reusable cache capacity.
pub const MAX_NAMES: usize = 16384;
/// Maximum restored journal size.
pub const MAX_BYTES: u64 = 5 * 1024 * 1024;

/// Redacted identity/storage error. An invalid journal must never trigger reset.
pub fn failure() -> io::Error {
    io::Error::other(
        "FakeIP identity journal is unavailable or invalid; no automatic reset is allowed.",
    )
}

/// Recognize the owned synthetic range, independently of current allocation.
pub fn in_range(ip: Ipv4Addr) -> bool {
    ip.octets()[..2] == [198, 18]
}

/// One identity epoch. No address reuse, expiration or storage authority.
/// Dropping this value does not delete its journal or reset its namespace.
pub struct Identities {
    pool: Pool,
    names: HashMap<String, Ipv4Addr>,
    reverse: HashMap<Ipv4Addr, String>,
    poisoned: bool,
}

impl Identities {
    /// Restore a bounded complete journal without mutation. Invalid/truncated,
    /// duplicate or noncanonical records reject the whole epoch, never repair it.
    pub fn restore(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() as u64 > MAX_BYTES || !bytes.starts_with(HEADER) || !bytes.ends_with(b"\n") {
            return Err(failure());
        }
        let pool = Pool::new(
            PREFIX.parse().map_err(|_| failure())?,
            Arc::new(MemoryStore::new(MAX_NAMES + 1)),
        )
        .map_err(|_| failure())?;
        let mut state = Self {
            pool,
            names: HashMap::new(),
            reverse: HashMap::new(),
            poisoned: false,
        };
        let body = &bytes[HEADER.len()..];
        if !body.is_empty() {
            for line in body[..body.len() - 1].split(|byte| *byte == b'\n') {
                let name: String = serde_json::from_slice(line).map_err(|_| failure())?;
                if state.names.len() >= MAX_NAMES
                    || nm_tunnel_profile::canonical_domain(&name).as_deref() != Some(name.as_str())
                    || state.names.contains_key(&name)
                {
                    return Err(failure());
                }
                let ip = state.allocate()?;
                state.reverse.insert(ip, name.clone());
                state.names.insert(name, ip);
            }
        }
        Ok(state)
    }

    fn allocate(&self) -> io::Result<Ipv4Addr> {
        // Only opaque lease IDs reach allocator tracing, never DNS names.
        let IpAddr::V4(ip) = self.pool.lookup(&format!("lease-{}", self.names.len())) else {
            return Err(failure());
        };
        if !in_range(ip) || self.reverse.contains_key(&ip) {
            return Err(failure());
        }
        Ok(ip)
    }

    /// Publish only after `persist` appends the whole supplied record and confirms
    /// durable storage under exclusive ownership. It must not report success for
    /// buffered-only writes. Any write error poisons ALL reads/writes until reopen;
    /// no address is published or reused after an ambiguous append. This synchronous
    /// transaction must run to completion (platforms may use a blocking worker).
    pub fn lookup(
        &mut self,
        name: &str,
        persist: impl FnOnce(&[u8]) -> io::Result<()>,
    ) -> io::Result<Ipv4Addr> {
        if self.poisoned {
            return Err(failure());
        }
        let name = nm_tunnel_profile::canonical_domain(name).ok_or_else(failure)?;
        if let Some(ip) = self.names.get(&name) {
            return Ok(*ip);
        }
        if self.names.len() >= MAX_NAMES {
            return Err(io::Error::other(
                "FakeIP identity capacity exhausted; addresses are never reused.",
            ));
        }
        let ip = self.allocate()?;
        let mut record = serde_json::to_vec(&name).map_err(|_| failure())?;
        record.push(b'\n');
        if persist(&record).is_err() {
            self.poisoned = true;
            return Err(failure());
        }
        self.reverse.insert(ip, name.clone());
        self.names.insert(name, ip);
        Ok(ip)
    }

    /// Return only a published identity. Unknown addresses or a poisoned epoch error.
    pub fn reverse(&self, ip: Ipv4Addr) -> io::Result<String> {
        if self.poisoned {
            return Err(failure());
        }
        self.reverse
            .get(&ip)
            .cloned()
            .ok_or_else(|| io::Error::other("Unknown or unowned FakeIP destination."))
    }
}

/// Generate the existing IPv4 FakeIP DNS answer using a storage-owner callback.
/// AAAA returns an empty answer and never allocates; unsupported queries reject.
/// The callback must publish only durable identities. No socket or filesystem I/O.
pub fn answer(
    request: &[u8],
    lookup: impl FnOnce(&str) -> io::Result<Ipv4Addr>,
) -> io::Result<Vec<u8>> {
    use hickory_proto::{
        op::{Message, MessageType, OpCode},
        rr::{RData, Record, RecordType, rdata::A},
    };
    let query = crate::dns::parse_query(request)?;
    let question = &query.queries[0];
    let kind = question.query_type();
    if !matches!(kind, RecordType::A | RecordType::AAAA) {
        return Err(failure());
    }
    let ip = if kind == RecordType::A {
        Some(lookup(&question.name().to_utf8())?)
    } else {
        None
    };
    let mut response = Message::new(query.id, MessageType::Response, OpCode::Query);
    response.metadata.recursion_desired = query.recursion_desired;
    response.metadata.recursion_available = true;
    response.queries = query.queries.clone();
    if let Some(ip) = ip {
        response.add_answer(Record::from_rdata(
            question.name().clone(),
            60,
            RData::A(A(ip)),
        ));
    }
    response.to_vec().map_err(|_| failure())
}
