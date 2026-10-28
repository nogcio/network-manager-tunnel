use super::*;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, BufReader};

struct State {
    environment: Vec<String>,
    loads: usize,
}
struct Manager(Arc<Mutex<State>>);
struct Service(Arc<Mutex<State>>);

#[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
impl Manager {
    fn load_unit(&self, name: &str) -> zbus::fdo::Result<OwnedObjectPath> {
        if name != UNIT {
            return Err(zbus::fdo::Error::InvalidArgs("Unexpected unit".into()));
        }
        self.0
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("State lock failed".into()))?
            .loads += 1;
        OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/fakeip")
            .map_err(|_| zbus::fdo::Error::Failed("Path failed".into()))
    }
}

#[zbus::interface(name = "org.freedesktop.systemd1.Service")]
impl Service {
    #[zbus(property)]
    fn environment(&self) -> zbus::fdo::Result<Vec<String>> {
        Ok(self
            .0
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("State lock failed".into()))?
            .environment
            .clone())
    }
}

#[tokio::test]
async fn disabled_boot_guard_needs_no_nm_dependency_and_namespace_rejection_creates_no_state()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut daemon = tokio::process::Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let mut output = BufReader::new(daemon.stdout.take().ok_or("Missing private bus output")?);
        let mut address = String::new();
        output.read_line(&mut address).await?;
        let server = zbus::connection::Builder::address(address.trim())?
            .build()
            .await?;
        let client = zbus::connection::Builder::address(address.trim())?
            .build()
            .await?;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(format!("../../target/fakeip-boot-{}", uuid::Uuid::new_v4()));
        let pin = format!("XDG_STATE_HOME={}", path.display());
        let state = Arc::new(Mutex::new(State {
            environment: vec![pin.clone()],
            loads: 0,
        }));
        server
            .object_server()
            .at("/org/freedesktop/systemd1", Manager(Arc::clone(&state)))
            .await?;
        server
            .object_server()
            .at(
                "/org/freedesktop/systemd1/unit/fakeip",
                Service(Arc::clone(&state)),
            )
            .await?;
        server.request_name("org.freedesktop.systemd1").await?;
        // No enable/start/status APIs or Unit.RequiredBy interface exist on this
        // bus: namespace discovery must work without querying any of them.
        assert_eq!(state_base(&client).await?, path);
        assert_eq!(state.lock().map_err(|_| "State poisoned")?.loads, 1);
        assert!(!path.exists());
        for environment in [
            vec![],
            vec!["XDG_STATE_HOME=relative-private-token".into()],
            vec![pin.clone(), pin.clone()],
        ] {
            state.lock().map_err(|_| "State poisoned")?.environment = environment;
            let error = state_base(&client)
                .await
                .err()
                .ok_or("Malformed namespace admitted")?;
            assert!(!error.to_string().contains("private-token"));
            assert!(!path.exists());
        }
        daemon.kill().await?;
        daemon.wait().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await?
}
