use super::support::*;
use nm_tunnel_dataplane::{datagram::Route, resolver, stream::route_tcp};
use std::{io, sync::atomic::Ordering, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn portable_tcp_blocks_before_host_io_and_refusal_closes_without_fallback() -> io::Result<()>
{
    tokio::time::timeout(Duration::from_secs(3), async {
        for (name, calls) in [("blocked.example", 0), ("direct.example", 1)] {
            let host = Refuse::default();
            let profile = profile()?;
            let (mut application, inbound) = tokio::io::duplex(8192);
            application
                .write_all(format!("GET / HTTP/1.1\r\nHost: {name}\r\n\r\n").as_bytes())
                .await?;
            application.shutdown().await?;
            let result =
                route_tcp(inbound, &profile, &host, endpoint(), destination(), &NoLan).await;
            assert_eq!(result.is_err(), calls == 1);
            assert_eq!(host.calls.load(Ordering::SeqCst), calls);
            assert_eq!(application.read(&mut [0]).await?, 0);
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Capability contract deadline."))?
}

#[tokio::test]
async fn portable_dns_rejects_before_io_and_udp_refusal_is_one_request() -> io::Result<()> {
    let host = Refuse::default();
    let profile = profile()?;
    assert!(
        resolver::answer_query(&profile, &host, endpoint(), b"not DNS", false)
            .await
            .is_err()
    );
    assert_eq!(host.calls.load(Ordering::SeqCst), 0);
    // Legacy UDP must not turn a TCP-only sniffed name into a Direct request.
    assert!(
        Route::connect_named(
            &profile,
            &host,
            endpoint(),
            destination(),
            &NoLan,
            Some("direct.example")
        )
        .await
        .is_err()
    );
    assert_eq!(host.calls.load(Ordering::SeqCst), 1);
    assert_eq!(host.endpoint_calls.load(Ordering::SeqCst), 1);
    Ok(())
}
