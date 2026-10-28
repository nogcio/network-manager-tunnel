//! Synthetic Host that observes intended routes and never opens an application socket.
use nm_tunnel_dataplane::{Datagram, Host, LanScope, PayloadStream, dns, routing::Decision};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Mutex,
};

pub struct NoLan;
impl LanScope for NoLan {
    fn is_local(&self, _: SocketAddr) -> bool {
        false
    }
    fn authorizes(&self, _: SocketAddr) -> bool {
        false
    }
}

pub struct Observe {
    pub original: String,
    pub route: Mutex<Option<&'static str>>,
    pub queries: Mutex<usize>,
}

impl Observe {
    fn refuse<T>(&self, route: &'static str) -> io::Result<T> {
        let mut current = self
            .route
            .lock()
            .map_err(|_| io::Error::other("Probe lock failed."))?;
        if current.is_some() {
            *current = Some("unexpected-second-outbound");
            return Err(io::Error::other("Unexpected second outbound."));
        }
        *current = Some(route);
        Err(io::Error::other("Synthetic outbound refusal."))
    }
}

#[async_trait::async_trait]
impl Host for Observe {
    async fn open_endpoint(&self, _: SocketAddr) -> io::Result<nm_tunnel_engine::EndpointStream> {
        self.refuse("proxy")
    }
    async fn open_tcp(
        &self,
        _: SocketAddr,
        decision: Decision<'_>,
    ) -> io::Result<Box<dyn PayloadStream>> {
        if !matches!(decision, Decision::PolicyDirect(_)) {
            return Err(io::Error::other("Unexpected TCP grant."));
        }
        self.refuse("direct")
    }
    async fn open_udp(
        &self,
        _: SocketAddr,
        decision: Decision<'_>,
    ) -> io::Result<Box<dyn Datagram>> {
        if !matches!(decision, Decision::PolicyDirect(_)) {
            return Err(io::Error::other("Unexpected UDP grant."));
        }
        self.refuse("direct")
    }
    async fn query_dns(&self, bytes: &[u8], _: bool) -> io::Result<Vec<u8>> {
        let query = dns::parse_query(bytes)?;
        if query.queries[0].name().to_utf8() != format!("{}.", self.original) {
            return Err(io::Error::other("Unexpected DNS identity."));
        }
        *self
            .queries
            .lock()
            .map_err(|_| io::Error::other("Probe lock failed."))? += 1;
        let mut response = query;
        response.metadata.message_type = hickory_proto::op::MessageType::Response;
        response.add_answer(hickory_proto::rr::Record::from_rdata(
            response.queries[0].name().clone(),
            60,
            hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(203, 0, 113, 1))),
        ));
        response.to_vec().map_err(io::Error::other)
    }
    async fn fake_dns(&self, _: &[u8]) -> io::Result<Vec<u8>> {
        Err(io::Error::other("Unexpected DNS interception."))
    }
    async fn fake_reverse(&self, _: Ipv4Addr) -> io::Result<String> {
        Ok(self.original.clone())
    }
}
