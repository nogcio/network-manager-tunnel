//! Synthetic route observation and explicit loopback-only peer DNS allocation.
//! No NM, TUN, host configuration or external resolver access.
use nm_tunnel_dataplane::{datagram::Route, dns, stream};
use std::{io, net::SocketAddr, sync::Mutex, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[path = "../tests/support/source_policy.rs"]
mod fixture;
#[path = "../tests/support/route_observer.rs"]
mod observation;
use observation::{NoLan, Observe};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 4
        || !["tcp", "udp", "allocate"].contains(&args[0].as_str())
        || !["block.example", "direct.example", "proxy.example"].contains(&args[1].as_str())
        || !["block.example", "direct.example", "proxy.example", "none"].contains(&args[2].as_str())
    {
        return Err(
            "Expected synthetic transport, original name, observed name and JSON byte array."
                .into(),
        );
    }
    if args[3].len() > 32768 {
        return Err("Oversized synthetic byte array.".into());
    }
    let bytes: Vec<u8> = serde_json::from_str(&args[3])?;
    if bytes.len() > 8192 {
        return Err("Oversized synthetic prefix.".into());
    }
    if args[0] == "allocate" {
        if std::env::var("NMTUN_ISOLATED_SEMANTICS").as_deref() != Ok("1") {
            return Err("Peer allocation requires the explicit isolated harness.".into());
        }
        let (_, query) = dns::query(&args[1])?;
        let parsed = dns::parse_query(&query)?;
        let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        socket.set_write_timeout(Some(Duration::from_secs(2)))?;
        socket.connect("127.0.0.1:15354")?;
        socket.send(&query)?;
        let mut buffer = [0; dns::MAX_DNS_BYTES];
        let size = socket.recv(&mut buffer)?;
        dns::validate_response(&parsed, &buffer[..size])?;
        let addresses = dns::dns_answer(parsed.id, &buffer[..size])?;
        let address = addresses.first().ok_or("Missing peer FakeIP")?;
        if address.octets()[..2] != [198, 18] {
            return Err("Unexpected peer FakeIP range.".into());
        }
        println!("{address}");
        return Ok(());
    }
    let host = Observe {
        refuse_dns: false,
        original: args[1].clone(),
        route: Mutex::new(None),
        queries: Mutex::new(0),
    };
    let profile = fixture::profile()?;
    let destination = SocketAddr::from(([198, 18, 0, 4], 8443));
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        if args[0] == "udp" {
            Route::connect_named(
                &profile,
                &host,
                SocketAddr::from(([192, 0, 2, 1], 443)),
                destination,
                &NoLan,
                (args[2] != "none").then_some(args[2].as_str()),
            )
            .await
            .map(|_| ())
        } else {
            let (mut application, inbound) = tokio::io::duplex(16384);
            application.write_all(&bytes).await?;
            application.shutdown().await?;
            let result = stream::route_tcp(
                inbound,
                &profile,
                &host,
                SocketAddr::from(([192, 0, 2, 1], 443)),
                destination,
                &NoLan,
            )
            .await;
            if application.read(&mut [0]).await? != 0 {
                return Err(io::Error::other("Inbound ownership retained."));
            }
            result
        }
    })
    .await?;
    let route = host
        .route
        .lock()
        .map_err(|_| "Probe lock failed")?
        .unwrap_or("block");
    // Selected outbounds deliberately refuse, while Block may close or return refusal.
    if route != "block" && result.is_ok() {
        return Err("Probe claimed a successful refused outbound.".into());
    }
    println!(
        "{}",
        serde_json::json!({"route":route, "dns_queries":*host.queries.lock().map_err(|_| "Probe lock failed")?})
    );
    Ok(())
}
