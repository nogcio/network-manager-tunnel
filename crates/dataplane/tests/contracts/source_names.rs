//! Complete-policy name precedence observed against pinned sing-box v1.12.0.
#[path = "../support/source_policy.rs"]
mod fixture;
#[path = "../support/route_observer.rs"]
mod observation;

use nm_tunnel_dataplane::{datagram::Route, stream};
use observation::{NoLan, Observe};
use std::{io, net::SocketAddr, sync::Mutex, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn complete_rules_use_observed_name_but_dns_keeps_the_original_identity() -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        for original in ["block.example", "direct.example", "proxy.example"] {
            for observed in [
                Some("block.example"),
                Some("direct.example"),
                Some("proxy.example"),
                None,
            ] {
                for tcp in [true, false] {
                    let host = Observe {
                        original: original.into(),
                        route: Mutex::new(None),
                        queries: Mutex::new(0),
                    };
                    let profile = fixture::profile()?;
                    let destination = SocketAddr::from(([198, 18, 0, 4], 8443));
                    let endpoint = SocketAddr::from(([192, 0, 2, 1], 443));
                    if tcp {
                        let (mut application, inbound) = tokio::io::duplex(8192);
                        if let Some(name) = observed {
                            application
                                .write_all(
                                    format!("GET / HTTP/1.1\r\nHost: {name}\r\n\r\n").as_bytes(),
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
                        usize::from(expected == Some("direct"))
                    );
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
