use super::*;
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::test]
async fn orphan_cleanup_is_gated_by_current_backend_ownership_and_never_activates_it()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut daemon = tokio::process::Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null())
            .kill_on_drop(true).spawn()?;
        let mut output = BufReader::new(daemon.stdout.take().ok_or("Missing bus output")?);
        let mut address = String::new();
        output.read_line(&mut address).await?;
        let service = zbus::connection::Builder::address(address.trim())?.build().await?;
        let backend = zbus::connection::Builder::address(address.trim())?.build().await?;
        let stranger = zbus::connection::Builder::address(address.trim())?.build().await?;
        let gate = Arc::new(Mutex::new(State::default()));
        let status = Status::default();
        service.object_server().at(PATH, Recovery { bus: service.clone(), gate: Arc::clone(&gate), status: status.clone() }).await?;
        service.request_name(NAME).await?;
        let cleaned = std::cell::Cell::new(0);
        assert!(clean_if_orphaned(&service, &gate, &status, async { cleaned.set(cleaned.get()+1); Ok(()) }).await?);
        backend.request_name(SERVICE_TYPE).await?;
        assert!(!clean_if_orphaned(&service, &gate, &status, async { cleaned.set(cleaned.get()+1); Ok(()) }).await?);
        assert_eq!(cleaned.get(), 1);
        let invalid = zbus::Proxy::new(&stranger, NAME, PATH, INTERFACE).await?;
        let rejected: zbus::Result<()> = invalid.call("Arm", &()).await;
        assert!(matches!(rejected, Err(zbus::Error::MethodError(ref name,_,_)) if name.as_str() == "org.freedesktop.DBus.Error.AccessDenied"));
        let rejected: zbus::Result<()> = invalid.call("Renew", &(false,)).await;
        assert!(matches!(rejected, Err(zbus::Error::MethodError(ref name,_,_)) if name.as_str() == "org.freedesktop.DBus.Error.AccessDenied"));
        let valid = zbus::Proxy::new(&backend, NAME, PATH, INTERFACE).await?;
        valid.call::<_,_,()>("Arm", &()).await?;
        valid.call::<_,_,()>("Renew", &(true,)).await?;
        let progress: (u32, String) = invalid.call("GetStatus", &()).await?;
        assert_eq!(progress, (1, "backend-cleanup".into()));
        assert_eq!(cleaned.get(), 1);
        // Simulate helper restart: the bus-pinned FD is dropped, never signalled.
        // Process termination/cleanup ordering is exercised on owned children in
        // watchdog's tests, not on this test process hosting both bus peers.
        gate.lock().await.lease = None;
        backend.release_name(SERVICE_TYPE).await?;
        let refused = clean_if_orphaned(&service, &gate, &status, async { Err(io::Error::other("Synthetic transaction refusal.")) }).await;
        assert!(refused.is_err());
        assert!(clean_if_orphaned(&service, &gate, &status, async { cleaned.set(cleaned.get()+1); Ok(()) }).await?);
        assert_eq!(cleaned.get(), 2);
        gate.lock().await.shutting_down = true;
        backend.request_name(SERVICE_TYPE).await?;
        assert!(valid.call::<_,_,()>("Arm", &()).await.is_err(), "final Arm must not succeed after helper shutdown admission closes");
        assert!(gate.lock().await.lease.is_none());
        backend.release_name(SERVICE_TYPE).await?;
        daemon.kill().await?;
        daemon.wait().await?;
        assert!(clean_if_orphaned(&service, &gate, &status, async { cleaned.set(cleaned.get()+1); Ok(()) }).await.is_err());
        assert_eq!(cleaned.get(), 2, "unknown ownership must not run cleanup");
        Ok::<_,Box<dyn std::error::Error>>(())
    }).await?
}

#[tokio::test]
async fn deployed_recovery_policy_exposes_status_without_granting_control()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let policy = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../packaging/dbus/org.freedesktop.NetworkManager.tunnel.Recovery.conf").canonicalize()?;
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/private-bus");
        std::fs::create_dir_all(&directory)?;
        let path = directory.join(format!("recovery-{}.conf", uuid::Uuid::new_v4()));
        let config = format!(r#"<busconfig>
          <type>session</type><listen>unix:tmpdir=/tmp</listen><auth>EXTERNAL</auth>
          <policy context="default"><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy>
          <include>{}</include>
          <policy user="{}"><allow own="org.freedesktop.NetworkManager.tunnel.Recovery"/></policy>
        </busconfig>"#, policy.display(), rustix::process::getuid().as_raw());
        std::fs::write(&path, config)?;
        let mut daemon = tokio::process::Command::new("dbus-daemon")
            .arg("--nofork").arg("--print-address=1").arg(format!("--config-file={}", path.display()))
            .stdout(std::process::Stdio::piped()).kill_on_drop(true).spawn()?;
        let mut output = BufReader::new(daemon.stdout.take().ok_or("Missing bus output")?);
        let mut address = String::new();
        let ready = output.read_line(&mut address).await;
        std::fs::remove_file(path)?;
        ready?;
        let service = zbus::connection::Builder::address(address.trim())?.build().await?;
        let observer = zbus::connection::Builder::address(address.trim())?.build().await?;
        let gate = Arc::new(Mutex::new(State::default()));
        service.object_server().at(PATH, Recovery { bus: service.clone(), gate: Arc::clone(&gate), status: Status::default() }).await?;
        service.request_name(NAME).await?;
        let proxy = zbus::Proxy::new(&observer, NAME, PATH, INTERFACE).await?;
        let status: (u32, String) = proxy.call("GetStatus", &()).await?;
        assert_eq!(status, (1, "starting".into()));
        if !rustix::process::geteuid().is_root() {
            let arm: zbus::Result<()> = proxy.call("Arm", &()).await;
            let renew: zbus::Result<()> = proxy.call("Renew", &(false,)).await;
            let wrong = zbus::Proxy::new(&observer, NAME, "/wrong", INTERFACE).await?;
            let status: zbus::Result<(u32, String)> = wrong.call("GetStatus", &()).await;
            for denied in [arm.err(), renew.err(), status.err()] {
                assert!(matches!(denied, Some(zbus::Error::MethodError(ref name, _, _)) if name.as_str() == "org.freedesktop.DBus.Error.AccessDenied"));
            }
        }
        assert!(gate.lock().await.lease.is_none());
        daemon.kill().await?;
        daemon.wait().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    }).await?
}
