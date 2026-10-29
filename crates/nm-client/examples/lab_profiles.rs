//! Fixed synthetic profile fixtures for the explicitly authorized offline VM suite.
//! Uses the public model/client contract; never constructs NM dictionaries itself.
use nm_tunnel_profile::{DnsOverride, Draft, Security, SourcePolicy, TcpDomainPolicy, Transport};
use std::time::Duration;

#[path = "support/agent.rs"]
mod agent;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !std::path::Path::new("/run/nmt-lab-authorized").is_file() {
        return Err("Explicit disposable VM authorization required.".into());
    }
    let virt = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::process::Command::new("systemd-detect-virt")
            .arg("--vm")
            .output(),
    )
    .await??;
    if !virt.status.success() {
        return Err("Disposable VM required.".into());
    }
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [mode] = args.as_slice() else {
        return Err("Expected one fixed fixture mode.".into());
    };
    if mode == "serve-secret-agent" {
        return agent::serve().await;
    }
    if matches!(
        mode.as_str(),
        "observe-traffic" | "observe-running" | "observe-drained"
    ) {
        tokio::time::timeout(
            Duration::from_secs(if mode == "observe-running" || mode == "observe-drained" {
                75
            } else {
                8
            }),
            async {
                loop {
                    let sample = nm_tunnel_client::usage_snapshot()
                        .await?
                        .ok_or(nm_tunnel_client::UsageError::Unavailable)?;
                    if sample.available
                        && sample.live
                        && sample.state == "running"
                        && (mode == "observe-running"
                            || (mode == "observe-drained"
                                && sample.counters.tcp_active == 0
                                && sample.counters.udp_active == 0
                                && sample.counters.tcp_opened >= 2
                                && sample.counters.udp_opened > 0)
                            || (mode == "observe-traffic"
                                && sample.counters.upload_bytes >= 65_549
                                && sample.counters.download_bytes >= 65_549
                                && sample.counters.tcp_opened > 0
                                && sample.counters.udp_opened > 0
                                && !sample.history.is_empty()))
                    {
                        return Ok::<(), nm_tunnel_client::UsageError>(());
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            },
        )
        .await??;
        println!(
            "PASS: selected nonactivating public telemetry readiness/drain condition observed."
        );
        return Ok(());
    }
    if mode == "edit-manual-dns" {
        let observed = nm_tunnel_client::snapshot().await?;
        let target = observed
            .profiles
            .iter()
            .find(|p| p.name() == "NMT VM manual-dns")
            .ok_or("Fixed edit fixture missing.")?;
        nm_tunnel_client::edit_profile(
            target,
            nm_tunnel_client::ProfileChanges {
                name: "NMT VM manual-dns".into(),
                dns: DnsOverride::ProxyIpv4("1.1.1.1".parse()?),
                lan: nm_tunnel_client::LanBypass::None,
                intercept: true,
                fake_ip: false,
            },
        )
        .await?;
        println!("PASS: fixed NM profile edit accepted once; no activation or reapply.");
        return Ok(());
    }
    let mut draft = Draft {
        name: format!("NMT VM {mode}"),
        server: "192.0.2.2".into(),
        port: "24444".into(),
        credential: "12345678-1234-4234-8234-123456789abc".to_owned().into(),
        security: Security::Reality,
        server_name: "peer.example".into(),
        public_key: std::env::var("NM_TUNNEL_LAB_PUBLIC_KEY")?,
        short_id: "abababababababab".into(),
        vision: false,
        ..Default::default()
    };
    match mode.as_str() {
        "roaming" => {
            draft.server = "endpoint.fixture.invalid".into();
            draft.dns_override = DnsOverride::CurrentNetwork;
            draft.fake_ip = true;
            draft.dns_interception = true;
        }
        "agent-secret" | "ask-secret" => {}
        "vision" => {
            draft.vision = true;
            draft.port = "24449".into();
        }
        "tls-untrusted" => {
            draft.security = Security::Tls;
            draft.port = "24447".into();
        }
        "ws-untrusted" => {
            draft.security = Security::Tls;
            draft.port = "24448".into();
            draft.transport = Transport::WebSocket {
                path: "/fixture".into(),
                host: Some("peer.example".into()),
            };
        }
        "invalid-auth" => {
            draft.credential = "12345678-1234-4234-8234-123456789abd".to_owned().into();
        }
        "manual-dns" => {
            draft.dns_override = DnsOverride::ProxyIpv4("9.9.9.9".parse()?);
        }
        "network-dns" => {
            draft.dns_override = DnsOverride::CurrentNetwork;
        }
        "intercept" => {
            draft.dns_interception = true;
        }
        "connected-lan" => {
            draft.lan_bypass = true;
        }
        "private-lan" => {
            draft.private_lan_bypass = true;
        }
        "combined-lan" => {
            draft.lan_bypass = true;
            draft.dns_interception = true;
        }
        "fakeip" => {
            draft.fake_ip = true;
            draft.dns_interception = true;
        }
        "domain-rules" => {
            draft.tcp_domain_policy = Some(TcpDomainPolicy::from_json(
                r#"{"version":1,"rules":[
                {"domain":["block.fixture.invalid"],"action":"block"},
                {"domain":["direct.fixture.invalid"],"action":"direct"}] }"#,
            )?);
        }
        "source-udp-proxy"
        | "source-udp-direct"
        | "source-tcp-proxy"
        | "source-tcp-direct"
        | "source-dot-untrusted"
        | "source-doh-untrusted"
        | "roaming-source" => {
            if mode == "roaming-source" {
                draft.server = "endpoint.fixture.invalid".into();
            }
            let transport = if mode.contains("dot") {
                "tls"
            } else if mode.contains("doh") {
                "https"
            } else if mode.contains("tcp") {
                "tcp"
            } else {
                "udp"
            };
            let port = match transport {
                "tls" => 853,
                "https" => 443,
                _ => 53,
            };
            let tls = if matches!(transport, "tls" | "https") {
                "resolver.fixture.invalid"
            } else {
                ""
            };
            let path = if transport == "https" {
                ",\"http_path\":\"/dns-query\""
            } else {
                ""
            };
            let proxy = !mode.ends_with("direct");
            let policy = format!(
                r#"{{"version":1,"dns":{{"address":"1.1.1.1","port":{port},"transport":"{transport}","via_proxy":{proxy},"tls_name":"{tls}"{path}}},
                "domain_policy":"{{\"version\":1,\"rules\":[{{\"domain\":[\"block.fixture.invalid\"],\"action\":\"block\"}},{{\"domain\":[\"direct.fixture.invalid\"],\"action\":\"direct\"}}]}}",
                "fakeip_range":"198.18.0.0/15","tun_address":"172.19.0.1","tun_prefix":30,"mtu":1400}}"#
            );
            draft.source_policy = Some(SourcePolicy::from_json(&policy)?);
            draft.fake_ip = true;
            draft.dns_interception = true;
        }
        _ => return Err("Unknown fixed fixture mode.".into()),
    }
    if draft.security == Security::Tls {
        draft.public_key.clear();
        draft.short_id.clear();
    }
    let observed = nm_tunnel_client::snapshot().await?;
    if observed.profiles.iter().any(|p| p.name() == draft.name) || !observed.active.is_empty() {
        return Err("Fixture name occupied or VPN still active; refusing mutation.".into());
    }
    let profile = draft.validate().map_err(|_| "Invalid synthetic profile.")?;
    let options = nm_tunnel_client::ProfileOptions {
        persistent: mode.starts_with("roaming"),
        credentials: match mode.as_str() {
            "agent-secret" => nm_tunnel_client::CredentialStorage::Agent,
            "ask-secret" => nm_tunnel_client::CredentialStorage::Ask,
            _ => nm_tunnel_client::CredentialStorage::System,
        },
    };
    nm_tunnel_client::save_profile_with_options(profile, options).await?;
    println!("PASS: fixed synthetic profile saved once; no activation or secret retrieval.");
    Ok(())
}
