use super::*;
use std::net::Ipv4Addr;

struct Refuse;

fn split_profile() -> io::Result<Profile> {
    let mut draft = source_profile()?.to_draft();
    let mut value: serde_json::Value =
        serde_json::from_str(draft.source_policy.as_ref().ok_or_else(failed)?.as_json())
            .map_err(io::Error::other)?;
    value["version"] = serde_json::json!(3);
    value["dns_policy"] = serde_json::json!({"version":1,
        "resolvers":[{"type":"current_network"},{"type":"endpoint","dns":{"address":"8.8.8.8","port":53,"transport":"tcp","via_proxy":false,"tls_name":""}}],
        "rules":[{"domain":["direct.example"],"resolver":1},{"domain_suffix":["work.example"],"resolver":0}]
    });
    draft.source_policy = Some(
        nm_tunnel_profile::SourcePolicy::from_json(&value.to_string()).map_err(io::Error::other)?,
    );
    draft.validate().map_err(|_| failed())
}

#[tokio::test]
async fn split_selection_cache_and_direct_membership_use_the_question_not_worker_metadata()
-> io::Result<()> {
    use hickory_proto::rr::{RData, Record, rdata::A};
    use nm_tunnel_profile::{DnsOverride, DnsTransport, SourceDnsSelection};
    use std::sync::Mutex;
    struct Answers(Mutex<Vec<String>>);
    #[async_trait::async_trait]
    impl Exchange for Answers {
        async fn exchange(
            &self,
            profile: &Profile,
            bytes: &[u8],
            tcp: bool,
        ) -> io::Result<Vec<u8>> {
            let mut query = dns::parse_query(bytes)?;
            let (route, ip) = match selected_upstream(profile, bytes, tcp)? {
                SourceDnsSelection::CurrentNetwork {} => ("network", [192, 0, 2, 1]),
                SourceDnsSelection::Endpoint { dns } if !dns.via_proxy => {
                    assert_eq!(dns.transport, DnsTransport::Tcp);
                    ("direct", [203, 0, 113, 2])
                }
                SourceDnsSelection::Endpoint { .. } => ("proxy", [203, 0, 113, 3]),
            };
            self.0.lock().map_err(|_| failed())?.push(route.into());
            query.metadata.message_type = hickory_proto::op::MessageType::Response;
            query.add_answer(Record::from_rdata(
                query.queries[0].name().clone(),
                60,
                RData::A(A(ip.into())),
            ));
            query.to_vec().map_err(io::Error::other)
        }
    }
    let profile = split_profile()?;
    let mut resolver = Resolver::new(profile.clone(), Answers(Mutex::new(Vec::new())));
    for (name, ip) in [
        ("work.example", [192, 0, 2, 1]),
        ("other.example", [203, 0, 113, 3]),
        ("direct.example", [203, 0, 113, 2]),
    ] {
        let (id, bytes) = dns::query(name)?;
        for _ in 0..2 {
            let answer = resolver.query(&bytes, false).await?;
            assert!(dns::direct_dns_answer(
                id,
                name,
                std::net::IpAddr::V4(ip.into()),
                &answer
            )?);
        }
    }
    assert!(
        resolver
            .authorize_direct(Some("direct.example"), ([203, 0, 113, 3], 443).into())
            .await
            .is_err()
    );
    resolver
        .authorize_direct(Some("direct.example"), ([203, 0, 113, 2], 443).into())
        .await?;
    assert_eq!(
        *resolver.transport.0.lock().map_err(|_| failed())?,
        ["network", "proxy", "direct"]
    );
    assert_eq!(resolver.cache.len(), 3);
    assert!(selected_upstream(&profile, b"invalid", false).is_err());
    for override_dns in [
        DnsOverride::CurrentNetwork,
        DnsOverride::ProxyIpv4([9, 9, 9, 9].into()),
    ] {
        let mut draft = profile.to_draft();
        draft.dns_override = override_dns;
        let overridden = draft.validate().map_err(|_| failed())?;
        for name in ["work.example", "direct.example", "other.example"] {
            let (_, bytes) = dns::query(name)?;
            match selected_upstream(&overridden, &bytes, true)? {
                SourceDnsSelection::CurrentNetwork {} => {
                    assert_eq!(override_dns, DnsOverride::CurrentNetwork)
                }
                SourceDnsSelection::Endpoint { dns } => {
                    assert_eq!(dns.address, Ipv4Addr::new(9, 9, 9, 9));
                    assert!(dns.via_proxy);
                    assert_eq!(dns.transport, DnsTransport::Tcp);
                }
            }
        }
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn selected_split_failure_timeout_and_cancellation_never_try_default_or_publish_cache()
-> io::Result<()> {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct DropLease(Arc<AtomicUsize>);
    impl Drop for DropLease {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    struct Pending {
        calls: AtomicUsize,
        live: Arc<AtomicUsize>,
        refuse: bool,
    }
    #[async_trait::async_trait]
    impl Exchange for Pending {
        async fn exchange(
            &self,
            profile: &Profile,
            bytes: &[u8],
            tcp: bool,
        ) -> io::Result<Vec<u8>> {
            assert!(matches!(
                selected_upstream(profile, bytes, tcp)?,
                nm_tunnel_profile::SourceDnsSelection::CurrentNetwork {}
            ));
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.live.fetch_add(1, Ordering::SeqCst);
            let _lease = DropLease(self.live.clone());
            if self.refuse {
                return Err(failed());
            }
            std::future::pending().await
        }
    }
    let (_, bytes) = dns::query("work.example")?;
    for refuse in [true, false] {
        let mut resolver = Resolver::new(
            split_profile()?,
            Pending {
                calls: AtomicUsize::new(0),
                live: Arc::new(AtomicUsize::new(0)),
                refuse,
            },
        );
        assert!(resolver.query(&bytes, false).await.is_err());
        assert_eq!(resolver.transport.calls.load(Ordering::SeqCst), 1);
        assert_eq!(resolver.transport.live.load(Ordering::SeqCst), 0);
        assert!(resolver.cache.is_empty());
    }
    let mut resolver = Resolver::new(
        split_profile()?,
        Pending {
            calls: AtomicUsize::new(0),
            live: Arc::new(AtomicUsize::new(0)),
            refuse: false,
        },
    );
    {
        let query = resolver.query(&bytes, false);
        tokio::pin!(query);
        assert!(futures_util::poll!(&mut query).is_pending());
        // Dropping the caller's future cancels the selected exchange and its lease.
    }
    assert_eq!(resolver.transport.calls.load(Ordering::SeqCst), 1);
    assert_eq!(resolver.transport.live.load(Ordering::SeqCst), 0);
    assert!(resolver.cache.is_empty());
    Ok(())
}

#[tokio::test]
async fn selected_doh_failure_or_unrelated_response_never_publishes_cache_or_retries()
-> io::Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Fail(AtomicUsize, bool);
    #[async_trait::async_trait]
    impl Exchange for Fail {
        async fn exchange(&self, profile: &Profile, bytes: &[u8], _: bool) -> io::Result<Vec<u8>> {
            assert_eq!(
                profile
                    .network()
                    .source()
                    .ok_or_else(failed)?
                    .dns()
                    .transport,
                nm_tunnel_profile::DnsTransport::Https
            );
            self.0.fetch_add(1, Ordering::SeqCst);
            if self.1 {
                return Err(failed());
            }
            let mut reply = dns::parse_query(bytes)?;
            reply.metadata.message_type = hickory_proto::op::MessageType::Response;
            reply.metadata.id = reply.metadata.id.wrapping_add(1);
            reply.to_vec().map_err(io::Error::other)
        }
    }
    let mut draft = source_profile()?.to_draft();
    let encoded = draft
        .source_policy
        .as_ref()
        .ok_or_else(failed)?
        .as_json()
        .replace("\"transport\":\"tls\"", "\"transport\":\"https\"");
    draft.source_policy =
        Some(nm_tunnel_profile::SourcePolicy::from_json(&encoded).map_err(io::Error::other)?);
    let profile = draft.validate().map_err(|_| failed())?;
    let (_, query) = dns::query("direct.example")?;
    for refuse in [false, true] {
        let mut resolver = Resolver::new(profile.clone(), Fail(AtomicUsize::new(0), refuse));
        assert!(resolver.query(&query, false).await.is_err());
        assert!(resolver.cache.is_empty());
        assert_eq!(resolver.transport.0.load(Ordering::SeqCst), 1);
    }
    Ok(())
}
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
    for extended in [false, true] {
        let mut profile = source_profile()?;
        if extended {
            let mut draft = profile.to_draft();
            let mut policy: serde_json::Value =
                serde_json::from_str(draft.source_policy.as_ref().ok_or_else(failed)?.as_json())
                    .map_err(io::Error::other)?;
            policy["version"] = serde_json::json!(2);
            policy
                .as_object_mut()
                .ok_or_else(failed)?
                .remove("domain_policy");
            policy["route_policy"] = serde_json::json!({"version":1,"rules":[
                {"condition":{"type":"logical","mode":"and","rules":[
                    {"type":"match","domain":["direct.example"],"ip_cidr":["203.0.113.0/24"]},
                    {"type":"match","ports":[[443,443]]}
                ]},"action":"direct"}
            ]})
            .to_string()
            .into();
            draft.source_policy = Some(
                nm_tunnel_profile::SourcePolicy::from_json(&policy.to_string())
                    .map_err(io::Error::other)?,
            );
            profile = draft.validate().map_err(|_| failed())?;
        }
        let mut resolver = Resolver::new(profile, SelectedDns(AtomicUsize::new(0)));
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
        if extended {
            // CIDR matches do not grant unnamed public Direct, bypass port
            // constraints, or replace independent selected-resolver membership.
            assert!(
                resolver
                    .authorize_direct(None, SocketAddr::from(([203, 0, 113, 2], 443)))
                    .await
                    .is_err()
            );
            assert!(
                resolver
                    .authorize_direct(
                        Some("direct.example"),
                        SocketAddr::from(([203, 0, 113, 2], 80))
                    )
                    .await
                    .is_err()
            );
        }
        assert_eq!(resolver.transport.0.load(Ordering::SeqCst), 1);
    }
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
