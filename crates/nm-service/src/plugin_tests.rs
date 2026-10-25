//! Caller authorization belongs to the plugin, exercised on a private real bus.
use super::*;
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::test]
async fn only_current_nm_owner_can_control_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut daemon = tokio::process::Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let mut output = BufReader::new(daemon.stdout.take().ok_or("Missing bus output")?);
        let mut address = String::new();
        output.read_line(&mut address).await?;
        let service = zbus::connection::Builder::address(address.trim())?
            .build()
            .await?;
        let owner = zbus::connection::Builder::address(address.trim())?
            .build()
            .await?;
        let stranger = zbus::connection::Builder::address(address.trim())?
            .build()
            .await?;
        owner.request_name(NM).await?;
        let state = Arc::new(AtomicU32::new(1));
        let (tx, mut rx) = mpsc::channel(8);
        service
            .object_server()
            .at(
                PATH,
                Plugin {
                    bus: service.clone(),
                    state: Arc::clone(&state),
                    requests: tx,
                },
            )
            .await?;
        let destination = service.unique_name().ok_or("Missing unique name")?;
        let telemetry = Telemetry::default();
        service.object_server().at(PATH, telemetry.clone()).await?;
        let observation =
            zbus::Proxy::new(&stranger, destination, PATH, crate::telemetry::INTERFACE).await?;
        let snapshot: crate::telemetry::Snapshot = observation.call("GetSnapshot", &()).await?;
        assert_eq!(snapshot.state, "idle");
        assert!(!snapshot.available);
        assert_eq!(snapshot.generation, 0);
        assert_eq!(telemetry.snapshot().generation, 0);
        let proxy = zbus::Proxy::new(
            &stranger,
            destination,
            PATH,
            "org.freedesktop.NetworkManager.VPN.Plugin",
        )
        .await?;
        let result: zbus::Result<()> = proxy.call("Disconnect", &()).await;
        assert!(
            matches!(result, Err(zbus::Error::MethodError(ref name, _, _))
            if name.as_str() == "org.freedesktop.DBus.Error.AccessDenied")
        );
        assert_eq!(state.load(Ordering::SeqCst), 1);
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        let valid = zbus::Proxy::new(
            &owner,
            destination,
            PATH,
            "org.freedesktop.NetworkManager.VPN.Plugin",
        )
        .await?;
        let required: String = valid
            .call("NeedSecrets", &(crate::test_support::settings()?,))
            .await?;
        assert_eq!(required, "vpn");
        // Connect must not reserve state while an older Stop is still queued.
        let _: () = valid.call("Disconnect", &()).await?;
        let connecting_owner = owner.clone();
        let destination = destination.to_string();
        let connecting = tokio::spawn(async move {
            let proxy = zbus::Proxy::new(
                &connecting_owner,
                destination.as_str(),
                PATH,
                "org.freedesktop.NetworkManager.VPN.Plugin",
            )
            .await?;
            let mut settings = crate::test_support::settings()
                .map_err(|_| zbus::Error::Failure("Synthetic settings failed.".into()))?;
            let secrets = crate::schema::Strings::from([(
                "uuid".into(),
                "12345678-1234-4234-8234-123456789abc".into(),
            )]);
            settings
                .get_mut("vpn")
                .ok_or_else(|| zbus::Error::Failure("Missing synthetic VPN.".into()))?
                .insert(
                    "secrets".into(),
                    OwnedValue::try_from(zbus::zvariant::Value::from(secrets))?,
                );
            proxy.call::<_, _, ()>("Connect", &(settings,)).await
        });
        assert!(matches!(rx.recv().await, Some(Request::Stop)));
        let Some(Request::Start(_, reply)) = rx.recv().await else {
            return Err("Missing queued Connect".into());
        };
        assert_eq!(state.load(Ordering::SeqCst), 1);
        assert!(!connecting.is_finished());
        // Rejection must reach the caller without changing lifecycle state.
        reply
            .send(Err("Synthetic admission rejection."))
            .map_err(|_| "Lost Connect reply")?;
        assert!(connecting.await?.is_err());
        assert_eq!(state.load(Ordering::SeqCst), 1);
        let _: () = valid.call("Disconnect", &()).await?;
        assert!(matches!(rx.recv().await, Some(Request::Stop)));
        owner.release_name(NM).await?;
        stranger.request_name(NM).await?;
        let result: zbus::Result<()> = valid.call("Disconnect", &()).await;
        assert!(
            matches!(result, Err(zbus::Error::MethodError(ref name, _, _))
            if name.as_str() == "org.freedesktop.DBus.Error.AccessDenied")
        );
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        let _: () = proxy.call("Disconnect", &()).await?;
        assert!(matches!(rx.recv().await, Some(Request::Stop)));
        assert_eq!(state.load(Ordering::SeqCst), 1);
        daemon.kill().await?;
        daemon.wait().await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await?
}

#[test]
fn admission_checks_ownership_even_when_reported_state_is_stopped() {
    let state = AtomicU32::new(6);
    assert!(admit_start(&state, true, false).is_err());
    assert!(admit_start(&state, false, true).is_err());
    assert_eq!(state.load(Ordering::SeqCst), 6);
    assert!(admit_start(&state, false, false).is_ok());
    assert_eq!(state.load(Ordering::SeqCst), 3);
    assert!(admit_start(&state, false, false).is_err());
    assert_eq!(state.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn cancelling_preparation_awaits_owned_task_resource_release() -> io::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let (owned, mut receiver) = mpsc::channel::<()>(1);
        let (ready, started) = oneshot::channel();
        let mut pending = Some(AbortTask(tokio::spawn(async move {
            let _owned = owned;
            let _ = ready.send(());
            std::future::pending::<io::Result<Session>>().await
        })));
        started.await.map_err(io::Error::other)?;
        cancel_preparation(&mut pending).await;
        assert!(pending.is_none());
        assert_eq!(receiver.recv().await, None);
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("Preparation cancellation deadline."))?
}
