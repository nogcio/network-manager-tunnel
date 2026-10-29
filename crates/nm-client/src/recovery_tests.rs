use super::*;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, BufReader};

struct Feed {
    data: Arc<Mutex<(u32, String)>>,
    handover: Option<(zbus::Connection, zbus::Connection)>,
}

#[zbus::interface(name = "org.freedesktop.NetworkManager.tunnel.Recovery")]
impl Feed {
    async fn get_status(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> zbus::fdo::Result<(u32, String)> {
        if !header
            .primary()
            .flags()
            .contains(zbus::message::Flags::NoAutoStart)
        {
            return Err(zbus::fdo::Error::AccessDenied(
                "Observation must not activate recovery.".into(),
            ));
        }
        if let Some((old, new)) = &self.handover {
            old.release_name(NAME).await?;
            new.request_name(NAME).await?;
        }
        self.data
            .lock()
            .map(|data| data.clone())
            .map_err(|_| zbus::fdo::Error::Failed("Synthetic feed lock failed.".into()))
    }
}

#[tokio::test]
async fn recovery_observation_never_activates_or_controls_and_rejects_owner_or_contract_changes()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(10), async {
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
        let observer = zbus::connection::Builder::address(address.trim())?
            .build()
            .await?;
        let replacement = zbus::connection::Builder::address(address.trim())?
            .build()
            .await?;
        assert_eq!(read(&observer).await?, None);
        let data = Arc::new(Mutex::new((1, "starting".into())));
        service
            .object_server()
            .at(
                PATH,
                Feed {
                    data: Arc::clone(&data),
                    handover: None,
                },
            )
            .await?;
        service.request_name(NAME).await?;
        for (name, expected) in [
            ("starting", RecoveryStatus::Starting),
            ("watching", RecoveryStatus::Watching),
            ("terminating", RecoveryStatus::Terminating),
            ("cleaning", RecoveryStatus::Cleaning),
            ("retrying", RecoveryStatus::Retrying),
            ("cleaned", RecoveryStatus::Cleaned),
            ("backend-cleanup", RecoveryStatus::BackendCleanup),
        ] {
            *data.lock().map_err(|_| "Feed lock failed")? = (1, name.into());
            assert_eq!(read(&observer).await?, Some(expected));
        }
        for invalid in [(99, "cleaned".into()), (1, "unknown".into())] {
            *data.lock().map_err(|_| "Feed lock failed")? = invalid.clone();
            assert_eq!(read(&observer).await, Err(RecoveryError::Invalid));
            assert_eq!(*data.lock().map_err(|_| "Feed lock failed")?, invalid);
        }
        *data.lock().map_err(|_| "Feed lock failed")? = (2, "blocked".into());
        assert_eq!(read(&observer).await?, Some(RecoveryStatus::Blocked));
        *data.lock().map_err(|_| "Feed lock failed")? = (1, "blocked".into());
        assert_eq!(read(&observer).await, Err(RecoveryError::Invalid));
        *data.lock().map_err(|_| "Feed lock failed")? = (1, "cleaned".into());
        service.object_server().remove::<Feed, _>(PATH).await?;
        service
            .object_server()
            .at(
                PATH,
                Feed {
                    data,
                    handover: Some((service.clone(), replacement.clone())),
                },
            )
            .await?;
        assert_eq!(read(&observer).await, Err(RecoveryError::Unavailable));
        daemon.kill().await?;
        daemon.wait().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await?
}
