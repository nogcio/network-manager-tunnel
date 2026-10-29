//! Complete-policy name precedence observed against pinned sing-box v1.12.0.
#[path = "../support/source_policy.rs"]
mod fixture;
#[path = "../support/route_observer.rs"]
mod observation;

use nm_tunnel_dataplane::{datagram::Route, stream};
use observation::{NoLan, Observe};
use std::{io, net::SocketAddr, sync::Mutex, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn with_dns_rules(profile: nm_tunnel_profile::Profile) -> io::Result<nm_tunnel_profile::Profile> {
    let mut draft = profile.to_draft();
    let mut policy: serde_json::Value = serde_json::from_str(
        draft
            .source_policy
            .as_ref()
            .ok_or_else(|| io::Error::other("Missing source"))?
            .as_json(),
    )
    .map_err(io::Error::other)?;
    policy["version"] = serde_json::json!(3);
    policy["dns_policy"] = serde_json::json!({"version":1,"resolvers":[{"type":"current_network"}],"rules":[{"domain_suffix":["example"],"resolver":0}]});
    draft.source_policy = Some(
        nm_tunnel_profile::SourcePolicy::from_json(&policy.to_string())
            .map_err(io::Error::other)?,
    );
    draft
        .validate()
        .map_err(|_| io::Error::other("Invalid DNS fixture"))
}

#[tokio::test]
async fn split_dns_refusal_closes_tcp_and_udp_without_remote_name_or_other_outbound()
-> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let profile = with_dns_rules(fixture::profile()?)?;
        for original in ["proxy.example", "direct.example", "block.example"] {
            for tcp in [true, false] {
                let host = Observe {
                    original: original.into(),
                    route: Mutex::new(None),
                    queries: Mutex::new(0),
                    refuse_dns: true,
                };
                let endpoint = SocketAddr::from(([192, 0, 2, 1], 443));
                let destination = SocketAddr::from(([198, 18, 0, 4], 8443));
                let error = if tcp {
                    let (mut application, inbound) = tokio::io::duplex(8192);
                    application
                        .write_all(format!("GET / HTTP/1.1\r\nHost: {original}\r\n\r\n").as_bytes())
                        .await?;
                    application.shutdown().await?;
                    let error =
                        stream::route_tcp(inbound, &profile, &host, endpoint, destination, &NoLan)
                            .await
                            .err()
                            .ok_or_else(|| io::Error::other("DNS failure admitted TCP"))?;
                    assert_eq!(application.read(&mut [0]).await?, 0);
                    error
                } else {
                    Route::connect_named(&profile, &host, endpoint, destination, &NoLan, None)
                        .await
                        .err()
                        .ok_or_else(|| io::Error::other("DNS failure admitted UDP"))?
                };
                assert_eq!(
                    *host
                        .route
                        .lock()
                        .map_err(|_| io::Error::other("Test lock"))?,
                    None
                );
                assert_eq!(
                    *host
                        .queries
                        .lock()
                        .map_err(|_| io::Error::other("Test lock"))?,
                    usize::from(original != "block.example")
                );
                assert_eq!(
                    error.kind(),
                    if original == "block.example" {
                        io::ErrorKind::PermissionDenied
                    } else {
                        io::ErrorKind::Other
                    }
                );
            }
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("DNS refusal dispatch deadline"))?
}

#[tokio::test]
async fn v2_port_rules_drive_tcp_and_udp_without_treating_fakeip_as_real_cidr() -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut draft = fixture::profile()?.to_draft();
        let mut policy: serde_json::Value = serde_json::from_str(
            draft
                .source_policy
                .as_ref()
                .ok_or_else(|| io::Error::other("No source fixture"))?
                .as_json(),
        )
        .map_err(io::Error::other)?;
        policy["version"] = serde_json::json!(2);
        policy
            .as_object_mut()
            .ok_or_else(|| io::Error::other("Invalid fixture"))?
            .remove("domain_policy");
        policy["route_policy"] = serde_json::json!({"version":1,"rules":[
            {"condition":{"type":"match","ip_cidr":["198.18.0.0/15"]},"action":"block"},
            {"condition":{"type":"match","ip_cidr":["203.0.113.0/24"],"ports":[[10443,10443]]},"action":"proxy"},
            {"condition":{"type":"match","ports":[[8443,8443]]},"action":"block"},
            {"condition":{"type":"match","ports":[[9443,9443],[10443,10443]]},"action":"direct"}
        ]})
        .to_string()
        .into();
        draft.source_policy = Some(
            nm_tunnel_profile::SourcePolicy::from_json(&policy.to_string())
                .map_err(io::Error::other)?,
        );
        let profile = draft
            .validate()
            .map_err(|_| io::Error::other("Invalid v2 fixture"))?;
        for (port, expected, queries) in [
            (10443, None, 1),
            (8443, None, 0),
            (9443, Some("direct"), 1),
            (443, Some("proxy"), 0),
        ] {
            for tcp in [true, false] {
                let host = Observe {
                    refuse_dns: false,
                    original: "proxy.example".into(),
                    route: Mutex::new(None),
                    queries: Mutex::new(0),
                };
                let endpoint = SocketAddr::from(([192, 0, 2, 1], 443));
                let destination = SocketAddr::from(([198, 18, 0, 4], port));
                if tcp {
                    let (mut application, inbound) = tokio::io::duplex(8192);
                    application
                        .write_all(b"GET / HTTP/1.1\r\nHost: proxy.example\r\n\r\n")
                        .await?;
                    application.shutdown().await?;
                    assert!(
                        stream::route_tcp(inbound, &profile, &host, endpoint, destination, &NoLan)
                            .await
                            .is_err()
                    );
                    assert_eq!(application.read(&mut [0]).await?, 0);
                } else {
                    assert!(
                        Route::connect_named(&profile, &host, endpoint, destination, &NoLan, None)
                            .await
                            .is_err()
                    );
                }
                assert_eq!(
                    *host
                        .route
                        .lock()
                        .map_err(|_| io::Error::other("Test lock"))?,
                    expected
                );
                assert_eq!(
                    *host
                        .queries
                        .lock()
                        .map_err(|_| io::Error::other("Test lock"))?,
                    queries
                );
            }
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("V2 dispatch contract deadline"))?
}

#[tokio::test]
async fn complete_rules_use_observed_name_but_dns_keeps_the_original_identity() -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        for split_dns in [false, true] {
            for original in ["block.example", "direct.example", "proxy.example"] {
                for observed in [
                    Some("block.example"),
                    Some("direct.example"),
                    Some("proxy.example"),
                    None,
                ] {
                    for tcp in [true, false] {
                        let host = Observe {
                            refuse_dns: false,
                            original: original.into(),
                            route: Mutex::new(None),
                            queries: Mutex::new(0),
                        };
                        let profile = if split_dns {
                            with_dns_rules(fixture::profile()?)?
                        } else {
                            fixture::profile()?
                        };
                        let destination = SocketAddr::from(([198, 18, 0, 4], 8443));
                        let endpoint = SocketAddr::from(([192, 0, 2, 1], 443));
                        if tcp {
                            let (mut application, inbound) = tokio::io::duplex(8192);
                            if let Some(name) = observed {
                                application
                                    .write_all(
                                        format!("GET / HTTP/1.1\r\nHost: {name}\r\n\r\n")
                                            .as_bytes(),
                                    )
                                    .await?;
                            }
                            application.shutdown().await?;
                            let _ = stream::route_tcp(
                                inbound,
                                &profile,
                                &host,
                                endpoint,
                                destination,
                                &NoLan,
                            )
                            .await;
                            assert_eq!(application.read(&mut [0]).await?, 0);
                        } else {
                            assert!(
                                Route::connect_named(
                                    &profile,
                                    &host,
                                    endpoint,
                                    destination,
                                    &NoLan,
                                    observed
                                )
                                .await
                                .is_err()
                            );
                        }
                        let expected = match observed.unwrap_or(original) {
                            "block.example" => None,
                            "direct.example" => Some("direct"),
                            _ => Some("proxy"),
                        };
                        assert_eq!(
                            *host
                                .route
                                .lock()
                                .map_err(|_| io::Error::other("Test lock failed."))?,
                            expected,
                            "original={original}, observed={observed:?}, tcp={tcp}"
                        );
                        assert_eq!(
                            *host
                                .queries
                                .lock()
                                .map_err(|_| io::Error::other("Test lock failed."))?,
                            usize::from(
                                expected == Some("direct")
                                    || (split_dns && expected == Some("proxy"))
                            )
                        );
                    }
                }
            }
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Source-name contract deadline."))?
}

#[tokio::test]
async fn sniffed_names_cannot_bypass_fakeip_ownership_or_accept_invalid_metadata() -> io::Result<()>
{
    use super::support::Refuse;
    use std::sync::atomic::Ordering;
    for (name, expected_calls) in [
        ("proxy.example", 1),
        ("direct.example", 1),
        ("https://invalid.example", 0),
    ] {
        let host = Refuse::default();
        assert!(
            Route::connect_named(
                &fixture::profile()?,
                &host,
                SocketAddr::from(([192, 0, 2, 1], 443)),
                SocketAddr::from(([198, 18, 0, 4], 8443)),
                &NoLan,
                Some(name),
            )
            .await
            .is_err()
        );
        assert_eq!(host.calls.load(Ordering::SeqCst), expected_calls);
        assert_eq!(host.endpoint_calls.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[tokio::test]
async fn explicit_dns_overrides_keep_destination_resolution_for_tcp_proxy() -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        for override_mode in [
            nm_tunnel_profile::DnsOverride::CurrentNetwork,
            nm_tunnel_profile::DnsOverride::ProxyIpv4(std::net::Ipv4Addr::new(9, 9, 9, 9)),
        ] {
            let mut draft = fixture::profile()?.to_draft();
            draft.dns_override = override_mode;
            let profile = draft
                .validate()
                .map_err(|_| io::Error::other("Invalid override fixture."))?;
            let host = Observe {
                refuse_dns: false,
                original: "proxy.example".into(),
                route: Mutex::new(None),
                queries: Mutex::new(0),
            };
            let (mut application, inbound) = tokio::io::duplex(8192);
            application
                .write_all(b"GET / HTTP/1.1\r\nHost: proxy.example\r\n\r\n")
                .await?;
            application.shutdown().await?;
            assert!(
                stream::route_tcp(
                    inbound,
                    &profile,
                    &host,
                    SocketAddr::from(([192, 0, 2, 1], 443)),
                    SocketAddr::from(([198, 18, 0, 4], 8443)),
                    &NoLan
                )
                .await
                .is_err()
            );
            assert_eq!(
                *host
                    .route
                    .lock()
                    .map_err(|_| io::Error::other("Test lock failed."))?,
                Some("proxy")
            );
            assert_eq!(
                *host
                    .queries
                    .lock()
                    .map_err(|_| io::Error::other("Test lock failed."))?,
                1
            );
            assert_eq!(application.read(&mut [0]).await?, 0);
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Override contract deadline."))?
}

#[tokio::test]
async fn explicit_dns_overrides_keep_xudp_resolution_and_refusal_never_falls_back() -> io::Result<()>
{
    tokio::time::timeout(Duration::from_secs(5), async {
        for override_mode in [
            nm_tunnel_profile::DnsOverride::CurrentNetwork,
            nm_tunnel_profile::DnsOverride::ProxyIpv4(std::net::Ipv4Addr::new(9, 9, 9, 9)),
        ] {
            let mut draft = fixture::profile()?.to_draft();
            draft.dns_override = override_mode;
            let profile = draft
                .validate()
                .map_err(|_| io::Error::other("Invalid override fixture."))?;
            let host = Observe {
                refuse_dns: false,
                original: "proxy.example".into(),
                route: Mutex::new(None),
                queries: Mutex::new(0),
            };
            assert!(
                Route::connect_named(
                    &profile,
                    &host,
                    SocketAddr::from(([192, 0, 2, 1], 443)),
                    SocketAddr::from(([198, 18, 0, 4], 8443)),
                    &NoLan,
                    Some("proxy.example")
                )
                .await
                .is_err()
            );
            assert_eq!(
                *host
                    .route
                    .lock()
                    .map_err(|_| io::Error::other("Test lock failed."))?,
                Some("proxy")
            );
            assert_eq!(
                *host
                    .queries
                    .lock()
                    .map_err(|_| io::Error::other("Test lock failed."))?,
                1
            );
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("XUDP override contract deadline."))?
}

#[tokio::test]
async fn unresolved_tcp_proxy_names_still_require_fakeip_ownership() -> io::Result<()> {
    use super::support::Refuse;
    use std::sync::atomic::Ordering;
    tokio::time::timeout(Duration::from_secs(5), async {
        for name in ["proxy.example", "direct.example", "block.example"] {
            let host = Refuse::default();
            let (mut application, inbound) = tokio::io::duplex(8192);
            application
                .write_all(format!("GET / HTTP/1.1\r\nHost: {name}\r\n\r\n").as_bytes())
                .await?;
            application.shutdown().await?;
            assert!(
                stream::route_tcp(
                    inbound,
                    &fixture::profile()?,
                    &host,
                    SocketAddr::from(([192, 0, 2, 1], 443)),
                    SocketAddr::from(([198, 18, 0, 4], 8443)),
                    &NoLan
                )
                .await
                .is_err()
            );
            assert_eq!(host.calls.load(Ordering::SeqCst), 1);
            assert_eq!(host.endpoint_calls.load(Ordering::SeqCst), 0);
            assert_eq!(application.read(&mut [0]).await?, 0);
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Ownership contract deadline."))?
}
