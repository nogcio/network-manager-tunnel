use super::*;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, BufReader};

fn sample() -> UsageSnapshot {
    UsageSnapshot {
        version: 1,
        generation: 7,
        state: "running".into(),
        setup_stage: "ready".into(),
        worker_stage: 7,
        elapsed_ms: 2000,
        available: true,
        live: true,
        age_ms: 0,
        counters: TrafficCounters {
            download_bytes: 8192,
            ..TrafficCounters::default()
        },
        upload_bytes_per_second: 1024,
        download_bytes_per_second: 4096,
        history: vec![TrafficSample {
            elapsed_ms: 2000,
            counters: TrafficCounters::default(),
            upload_bytes_per_second: 1024,
            download_bytes_per_second: 4096,
        }],
    }
}

struct Feed {
    data: Arc<Mutex<UsageSnapshot>>,
    handover: Option<(zbus::Connection, zbus::Connection)>,
}

struct WrongSignatureFeed {
    data: Arc<Mutex<String>>,
}

#[zbus::interface(name = "org.freedesktop.NetworkManager.tunnel.Telemetry")]
impl WrongSignatureFeed {
    fn get_snapshot(&self) -> zbus::fdo::Result<String> {
        self.data
            .lock()
            .map(|s| s.clone())
            .map_err(|_| zbus::fdo::Error::Failed("Synthetic feed lock failed.".into()))
    }
}

#[zbus::interface(name = "org.freedesktop.NetworkManager.tunnel.Telemetry")]
impl Feed {
    async fn get_snapshot(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> zbus::fdo::Result<UsageSnapshot> {
        if !header
            .primary()
            .flags()
            .contains(zbus::message::Flags::NoAutoStart)
        {
            return Err(zbus::fdo::Error::AccessDenied(
                "Observer must disable auto-start.".into(),
            ));
        }
        if let Some((old, new)) = &self.handover {
            old.release_name(SERVICE_TYPE).await?;
            new.request_name(SERVICE_TYPE).await?;
        }
        self.data
            .lock()
            .map(|s| s.clone())
            .map_err(|_| zbus::fdo::Error::Failed("Synthetic feed lock failed.".into()))
    }
}

#[tokio::test]
async fn usage_is_read_only_nonactivating_bounded_and_pinned_to_the_current_owner()
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
        assert!(
            read(&observer).await?.is_none(),
            "Absent backend is not started"
        );
        let data = Arc::new(Mutex::new(sample()));
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
        service.request_name(SERVICE_TYPE).await?;
        let received = read(&observer).await?.ok_or("Missing sample")?;
        assert_eq!(received.generation, 7);
        assert_eq!(received.counters.download_bytes, 8192);
        data.lock().map_err(|_| "Feed lock failed")?.version = 99;
        assert_eq!(read(&observer).await.err(), Some(UsageError::Invalid));
        assert_eq!(data.lock().map_err(|_| "Feed lock failed")?.version, 99);
        {
            let mut source = data.lock().map_err(|_| "Feed lock failed")?;
            source.version = 1;
            source.worker_stage = 255;
        }
        let before = format!("{:?}", data.lock().map_err(|_| "Feed lock failed")?);
        assert_eq!(read(&observer).await.err(), Some(UsageError::Invalid));
        assert_eq!(
            format!("{:?}", data.lock().map_err(|_| "Feed lock failed")?),
            before,
            "Rejecting an unknown worker stage leaves source data unchanged"
        );
        service.object_server().remove::<Feed, _>(PATH).await?;
        let malformed = Arc::new(Mutex::new("wrong-signature synthetic response".to_owned()));
        service
            .object_server()
            .at(
                PATH,
                WrongSignatureFeed {
                    data: Arc::clone(&malformed),
                },
            )
            .await?;
        assert_eq!(
            read(&observer).await.err(),
            Some(UsageError::Invalid),
            "A malformed reply is not transport unavailability"
        );
        assert_eq!(
            *malformed.lock().map_err(|_| "Feed lock failed")?,
            "wrong-signature synthetic response",
            "Rejecting a malformed reply leaves source data unchanged"
        );
        service
            .object_server()
            .remove::<WrongSignatureFeed, _>(PATH)
            .await?;
        service
            .object_server()
            .at(
                PATH,
                Feed {
                    data: Arc::new(Mutex::new(sample())),
                    handover: Some((service.clone(), replacement.clone())),
                },
            )
            .await?;
        assert_eq!(
            read(&observer).await.err(),
            Some(UsageError::Unavailable),
            "Former owner cannot publish after replacement"
        );
        assert!(
            zbus::fdo::DBusProxy::new(&observer)
                .await?
                .get_name_owner(SERVICE_TYPE.try_into()?)
                .await?
                .as_str()
                == replacement
                    .unique_name()
                    .ok_or("Missing replacement name")?
                    .as_str()
        );
        daemon.kill().await?;
        daemon.wait().await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await?
}

#[test]
fn worker_stages_accept_only_documented_codes_without_mutating_source_data() {
    let mut data = sample();
    for stage in u8::MIN..=u8::MAX {
        data.worker_stage = stage;
        let before = format!("{data:?}");
        let expected = if matches!(stage, 0..=4 | 7 | 10..=14) {
            Ok(())
        } else {
            Err(UsageError::Invalid)
        };
        assert_eq!(data.validate(), expected, "Worker stage {stage}");
        assert_eq!(format!("{data:?}"), before);
    }
}

#[test]
fn unsupported_or_unbounded_history_is_rejected_without_mutating_it() {
    let mut data = sample();
    data.history = vec![data.history[0].clone(); 62];
    assert_eq!(data.validate(), Err(UsageError::Invalid));
    assert_eq!(data.history.len(), 62);
    data.history.truncate(1);
    data.history[0].elapsed_ms = 2001;
    assert_eq!(data.validate(), Err(UsageError::Invalid));
    data.history[0].elapsed_ms = 0;
    data.elapsed_ms = 60_001;
    assert_eq!(data.validate(), Err(UsageError::Invalid));
}
