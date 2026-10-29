use super::*;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncBufReadExt, BufReader};

struct Feed {
    generation: Arc<Mutex<String>>,
    calls: Arc<AtomicUsize>,
    lose_reply: bool,
}

#[zbus::interface(name = "org.freedesktop.NetworkManager.tunnel.Recovery")]
impl Feed {
    fn get_status(&self) -> (u32, String) {
        (2, "blocked".into())
    }
    fn get_release_token(&self) -> zbus::fdo::Result<(u32, String, bool)> {
        Ok((
            2,
            self.generation
                .lock()
                .map_err(|_| zbus::fdo::Error::Failed("Test lock".into()))?
                .clone(),
            true,
        ))
    }
    fn disconnect(
        &self,
        generation: String,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> zbus::fdo::Result<()> {
        assert!(
            header
                .primary()
                .flags()
                .contains(zbus::message::Flags::NoAutoStart)
        );
        assert!(
            header
                .primary()
                .flags()
                .contains(zbus::message::Flags::AllowInteractiveAuth)
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
        if generation
            != *self
                .generation
                .lock()
                .map_err(|_| zbus::fdo::Error::Failed("Test lock".into()))?
        {
            return Err(zbus::fdo::Error::Failed("Stale generation".into()));
        }
        if self.lose_reply {
            return Err(zbus::fdo::Error::NoReply("Synthetic lost reply".into()));
        }
        Ok(())
    }
}

#[tokio::test]
async fn explicit_release_is_pinned_nonactivating_generation_checked_and_never_retried()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut daemon = tokio::process::Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let mut reader = BufReader::new(daemon.stdout.take().ok_or("Missing bus")?);
        let mut address = String::new();
        reader.read_line(&mut address).await?;
        let service = zbus::connection::Builder::address(address.trim())?
            .build()
            .await?;
        let client = zbus::connection::Builder::address(address.trim())?
            .build()
            .await?;
        let replacement = zbus::connection::Builder::address(address.trim())?
            .build()
            .await?;
        assert!(token(&client).await?.is_none());
        let generation = Arc::new(Mutex::new(uuid::Uuid::new_v4().to_string()));
        let calls = Arc::new(AtomicUsize::new(0));
        service
            .object_server()
            .at(
                PATH,
                Feed {
                    generation: Arc::clone(&generation),
                    calls: Arc::clone(&calls),
                    lose_reply: false,
                },
            )
            .await?;
        service.request_name(NAME).await?;
        let stale = token(&client).await?.ok_or("Missing release")?;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "observation must not release"
        );
        *generation.lock().map_err(|_| "Lock")? = uuid::Uuid::new_v4().to_string();
        assert_eq!(stale.release().await, Err(ClientError::Control));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        token(&client)
            .await?
            .ok_or("Missing release")?
            .release()
            .await?;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let old_owner = token(&client).await?.ok_or("Missing release")?;
        service.release_name(NAME).await?;
        replacement.request_name(NAME).await?;
        assert_eq!(old_owner.release().await, Err(ClientError::Control));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "owner change must not dispatch release"
        );
        replacement.release_name(NAME).await?;
        service.request_name(NAME).await?;
        service.object_server().remove::<Feed, _>(PATH).await?;
        service
            .object_server()
            .at(
                PATH,
                Feed {
                    generation,
                    calls: Arc::clone(&calls),
                    lose_reply: true,
                },
            )
            .await?;
        assert_eq!(
            token(&client)
                .await?
                .ok_or("Missing release")?
                .release()
                .await,
            Err(ClientError::ControlTimeout)
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "unknown outcome must not retry"
        );
        daemon.kill().await?;
        daemon.wait().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await?
}
