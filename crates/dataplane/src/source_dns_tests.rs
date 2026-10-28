use super::*;
use std::net::Ipv4Addr;

struct Refuse;
#[async_trait::async_trait]
impl Exchange for Refuse {
    async fn exchange(&self, _: &Profile, _: &[u8], _: bool) -> io::Result<Vec<u8>> {
        Err(io::Error::other("Unexpected DNS exchange."))
    }
}

fn source_profile() -> io::Result<Profile> {
    let domains = r#"{"version":1,"rules":[{"domain_suffix":["direct.example"],"action":"direct"},{"domain":["blocked.example"],"action":"block"},{"domain":["proxied.example"],"action":"proxy"}]}"#;
    let policy = serde_json::json!({"version":1,
        "dns":{"address":"1.1.1.1","port":853,"transport":"tls","via_proxy":true,"tls_name":"1.1.1.1"},
        "domain_policy":domains,"fakeip_range":"198.18.0.0/15","tun_address":"172.19.0.1","tun_prefix":30,"mtu":1400});
    let mut draft = nm_tunnel_profile::import_vless("vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example").map_err(io::Error::other)?;
    draft.source_policy = Some(
        nm_tunnel_profile::SourcePolicy::from_json(&policy.to_string())
            .map_err(io::Error::other)?,
    );
    draft.fake_ip = true;
    draft.dns_interception = true;
    draft
        .validate()
        .map_err(|_| io::Error::other("Invalid source fixture."))
}

#[tokio::test]
async fn source_direct_rejections_precede_all_dns_and_socket_work() -> io::Result<()> {
    let mut resolver = Resolver::new(source_profile()?, Refuse);
    for (domain, destination) in [
        (None, "1.1.1.1:443"),
        (Some("blocked.example"), "10.1.2.3:443"),
        (Some("proxied.example"), "10.1.2.3:443"),
        (Some("https://private-token.example"), "10.1.2.3:443"),
        (Some("direct.example"), "198.18.0.4:443"),
        (Some("direct.example"), "198.19.0.4:443"),
        (None, "[fd00::1]:443"),
        (None, "10.1.2.3:0"),
        (None, "10.1.2.3:53"),
        (Some("direct.example"), "1.1.1.1:53"),
    ] {
        let error = resolver
            .authorize_direct(domain, destination.parse().map_err(io::Error::other)?)
            .await
            .err()
            .ok_or_else(|| io::Error::other("Forbidden grant admitted."))?;
        assert!(!error.to_string().contains("private-token"));
        assert!(matches!(
            error.to_string().as_str(),
            "Source Direct destination refused."
                | "Source DNS or Direct authorization failed; no fallback is allowed."
        ));
        assert!(resolver.cache.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn a_sniffed_direct_rule_still_requires_independent_destination_dns_membership()
-> io::Result<()> {
    use hickory_proto::rr::{RData, Record, rdata::A};
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct SelectedDns(AtomicUsize);
    #[async_trait::async_trait]
    impl Exchange for SelectedDns {
        async fn exchange(&self, _: &Profile, bytes: &[u8], _: bool) -> io::Result<Vec<u8>> {
            let mut message = dns::parse_query(bytes)?;
            assert_eq!(message.queries[0].name().to_utf8(), "direct.example.");
            self.0.fetch_add(1, Ordering::SeqCst);
            message.metadata.message_type = hickory_proto::op::MessageType::Response;
            message.add_answer(Record::from_rdata(
                message.queries[0].name().clone(),
                60,
                RData::A(A(Ipv4Addr::new(203, 0, 113, 2))),
            ));
            message.to_vec().map_err(io::Error::other)
        }
    }
    let mut resolver = Resolver::new(source_profile()?, SelectedDns(AtomicUsize::new(0)));
    assert!(
        resolver
            .authorize_direct(
                Some("direct.example"),
                SocketAddr::from(([203, 0, 113, 1], 443))
            )
            .await
            .is_err()
    );
    resolver
        .authorize_direct(
            Some("direct.example"),
            SocketAddr::from(([203, 0, 113, 2], 443)),
        )
        .await?;
    assert_eq!(resolver.transport.0.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn cached_answers_are_question_transport_and_activation_bound_and_age_ttls() -> io::Result<()>
{
    use hickory_proto::{
        op::{Message, MessageType, OpCode},
        rr::{RData, Record, rdata::A},
    };
    let profile = source_profile()?;
    let mut resolver = Resolver::new(profile.clone(), Refuse);
    let (_, bytes) = dns::query("owned.example")?;
    let mut query = dns::parse_query(&bytes)?;
    let mut response = Message::new(query.id, MessageType::Response, OpCode::Query);
    response.queries = query.queries.clone();
    response.add_answer(Record::from_rdata(
        query.queries[0].name().clone(),
        30,
        RData::A(A(Ipv4Addr::new(1, 1, 1, 1))),
    ));
    let mut keyed = query.clone();
    keyed.metadata.id = 0;
    let mut key = keyed.to_vec().map_err(io::Error::other)?;
    key.push(0);
    resolver
        .cache
        .insert(key.clone(), (Instant::now(), response, 30));
    tokio::time::advance(Duration::from_secs(7)).await;
    query.metadata.id = query.id.wrapping_add(1);
    let request = query.to_vec().map_err(io::Error::other)?;
    let answer = resolver.query(&request, false).await?;
    dns::validate_response(&query, &answer)?;
    let answer = Message::from_vec(&answer).map_err(io::Error::other)?;
    assert_eq!(answer.answers[0].ttl, 23);
    assert_eq!(resolver.cache.len(), 1);
    let other = Resolver::new(profile, Refuse);
    assert!(other.cache.is_empty());
    let mut tcp_key = key;
    *tcp_key.last_mut().ok_or_else(failed)? = 1;
    assert!(!resolver.cache.contains_key(&tcp_key));
    Ok(())
}
