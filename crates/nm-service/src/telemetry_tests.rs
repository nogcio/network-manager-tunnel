use super::*;
use std::time::Duration;

#[test]
fn counters_and_flow_ownership_cover_success_failure_and_drop() {
    let meter = Arc::new(Meter::default());
    meter.packet(true, 80);
    meter.packet(true, 40);
    meter.packet(false, 160);
    meter.dropped();
    let tcp = meter.flow(true);
    let udp = meter.flow(false);
    tcp.failed();
    assert_eq!(
        meter.snapshot(),
        Counters {
            upload_bytes: 120,
            download_bytes: 160,
            upload_packets: 2,
            download_packets: 1,
            tcp_active: 1,
            udp_active: 1,
            tcp_opened: 1,
            udp_opened: 1,
            tcp_failed: 1,
            dropped_packets: 1,
            ..Counters::default()
        }
    );
    drop(tcp);
    drop(udp);
    assert_eq!(meter.snapshot().tcp_active, 0);
    assert_eq!(meter.snapshot().udp_active, 0);
}

#[tokio::test(start_paused = true)]
async fn rates_history_freshness_and_generation_have_explicit_lifetimes() {
    let telemetry = Telemetry::default();
    assert!(!telemetry.snapshot().available);
    telemetry.begin();
    telemetry.observe(Report {
        stage: 7,
        counters: Counters::default(),
    });
    for second in 1..=70 {
        tokio::time::advance(Duration::from_secs(1)).await;
        telemetry.observe(Report {
            stage: 7,
            counters: Counters {
                upload_bytes: second * 100,
                download_bytes: second * 250,
                ..Counters::default()
            },
        });
    }
    let snapshot = telemetry.snapshot();
    assert_eq!(snapshot.history.len(), 61);
    assert_eq!(snapshot.history[0].elapsed_ms, 10_000);
    assert_eq!(snapshot.upload_bytes_per_second, 100);
    assert_eq!(snapshot.download_bytes_per_second, 250);
    assert!(snapshot.live);
    tokio::time::advance(Duration::from_secs(4)).await;
    let stale = telemetry.snapshot();
    assert!(stale.available);
    assert!(!stale.live);
    assert_eq!(stale.age_ms, 4000);
    assert_eq!(stale.upload_bytes_per_second, 0);
    assert_eq!(stale.counters.upload_bytes, 7000);
    telemetry.state("failed");
    telemetry.observe(Report {
        stage: 1,
        counters: Counters::default(),
    });
    assert_eq!(telemetry.snapshot().counters.upload_bytes, 7000);
    tokio::time::advance(Duration::from_secs(61)).await;
    assert!(telemetry.snapshot().history.is_empty());
    assert_eq!(telemetry.snapshot().counters.download_bytes, 17500);
    telemetry.begin();
    let reset = telemetry.snapshot();
    assert_eq!(reset.generation, 2);
    assert!(!reset.available);
    assert_eq!(reset.counters, Counters::default());
    assert_eq!(reset.elapsed_ms, 0);
    assert!(reset.history.is_empty());
}

#[tokio::test]
async fn cancelled_flow_releases_active_count_without_claiming_protocol_failure() -> io::Result<()>
{
    tokio::time::timeout(Duration::from_secs(3), async {
        let meter = Arc::new(Meter::default());
        let flow = meter.flow(true);
        let (ready, started) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _flow = flow;
            let _ = ready.send(());
            std::future::pending::<()>().await;
        });
        started.await.map_err(io::Error::other)?;
        task.abort();
        assert!(task.await.is_err());
        assert_eq!(meter.snapshot().tcp_active, 0);
        assert_eq!(meter.snapshot().tcp_failed, 0);
        Ok(())
    })
    .await
    .map_err(io::Error::other)?
}

#[tokio::test]
async fn malformed_and_backpressured_datagrams_do_not_block_the_data_plane() -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let telemetry = Telemetry::default();
        telemetry.begin();
        let (sender, receiver) = UnixDatagram::pair()?;
        sender.send(b"invalid").await?;
        sender.send(&[b'x'; 3000]).await?;
        let health = crate::health::Report {
            health: true,
            failures: 1,
            stage: 12,
            elapsed_ms: 15_000,
            failure: Some(crate::health::Failure::Deadline),
            fatal: false,
        };
        sender.send(&serde_json::to_vec(&health).map_err(io::Error::other)?).await?;
        // A diagnostic must not become a traffic sample or alter lifecycle state.
        let report = Report {
            stage: 7,
            counters: Counters {
                upload_bytes: 123,
                ..Counters::default()
            },
        };
        sender
            .send(&serde_json::to_vec(&report).map_err(io::Error::other)?)
            .await?;
        // FIFO datagrams plus a bounded readiness notification, no polling sleeps.
        let received = telemetry.clone();
        let task =
            crate::task::AbortTask(tokio::spawn(
                async move { received.receive(receiver).await },
            ));
        loop {
            if telemetry.snapshot().available {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(telemetry.snapshot().counters.upload_bytes, 123);
        assert_eq!(telemetry.snapshot().history.len(), 1);
        assert_eq!(telemetry.snapshot().state, "connecting");
        drop(task);
        // A full telemetry socket is a dropped observation, not an async wait.
        let (sender, _unread) = UnixDatagram::pair()?;
        while sender.try_send(b"full").is_ok() {}
        assert!(matches!(sender.try_send(b"full"), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        let publisher = tokio::spawn(publish(Arc::new(sender), Arc::new(Meter::default())));
        tokio::task::yield_now().await;
        publisher.abort();
        assert!(publisher.await.is_err());
        Ok(())
    })
    .await
    .map_err(io::Error::other)?
}

#[tokio::test]
async fn deployed_bus_policy_allows_only_the_observation_method_for_nonroot_clients()
-> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    tokio::time::timeout(Duration::from_secs(10), async {
        let policy = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../packaging/dbus/org.freedesktop.NetworkManager.tunnel.conf")
            .canonicalize()?;
        let path = std::env::temp_dir().join(format!("nm-tunnel-bus-{}.conf", uuid::Uuid::new_v4()));
        let config = format!(r#"<busconfig>
          <type>session</type><listen>unix:tmpdir=/tmp</listen><auth>EXTERNAL</auth>
          <policy context="default"><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy>
          <include>{}</include>
          <policy user="{}"><allow own="org.freedesktop.NetworkManager.tunnel"/></policy>
        </busconfig>"#, policy.display(), rustix::process::getuid().as_raw());
        std::fs::write(&path, config)?;
        let spawned = tokio::process::Command::new("dbus-daemon")
            .arg("--nofork").arg("--print-address=1").arg(format!("--config-file={}", path.display()))
            .stdout(std::process::Stdio::piped()).kill_on_drop(true).spawn();
        let mut daemon = spawned?;
        let mut output = BufReader::new(daemon.stdout.take().ok_or("Missing bus stdout")?);
        let mut address = String::new();
        let ready = output.read_line(&mut address).await;
        std::fs::remove_file(path)?;
        ready?;
        let service = zbus::connection::Builder::address(address.trim())?.build().await?;
        let observer = zbus::connection::Builder::address(address.trim())?.build().await?;
        let telemetry = Telemetry::default();
        service.object_server().at(crate::plugin::PATH, telemetry.clone()).await?;
        service.request_name(nm_tunnel_profile::SERVICE_TYPE).await?;
        let proxy = zbus::Proxy::new(&observer, nm_tunnel_profile::SERVICE_TYPE, crate::plugin::PATH, INTERFACE).await?;
        let snapshot: Snapshot = proxy.call("GetSnapshot", &()).await?;
        assert_eq!(snapshot.generation, 0);
        if !rustix::process::geteuid().is_root() {
            for (path, interface, member) in [
                (crate::plugin::PATH, INTERFACE, "Disconnect"),
                (crate::plugin::PATH, "org.freedesktop.NetworkManager.VPN.Plugin", "Disconnect"),
                ("/wrong", INTERFACE, "GetSnapshot"),
            ] {
                let rejected = zbus::Proxy::new(&observer, nm_tunnel_profile::SERVICE_TYPE, path, interface).await?;
                let result: zbus::Result<()> = rejected.call(member, &()).await;
                assert!(matches!(result, Err(zbus::Error::MethodError(ref name, _, _))
                    if name.as_str() == "org.freedesktop.DBus.Error.AccessDenied"));
            }
        }
        assert_eq!(telemetry.snapshot().generation, 0);
        daemon.kill().await?;
        daemon.wait().await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    }).await?
}
