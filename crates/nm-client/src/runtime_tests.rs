//! Private bus contracts: no host NM, credentials retrieval, routes or activation.
use super::*;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, BufReader};

const PROFILE: &str = "/org/freedesktop/NetworkManager/Settings/1";
const ACTIVE: &str = "/org/freedesktop/NetworkManager/ActiveConnection/1";

#[derive(Default)]
struct State {
    settings: Settings,
    flags: Vec<u32>,
    activations: usize,
    deactivations: usize,
    active: bool,
    unreadable: bool,
    hidden: bool,
    reply_lost: bool,
    release_on_read: bool,
}
type Shared = Arc<Mutex<State>>;
struct FakeSettings(Shared);
struct FakeProfile(Shared);
struct FakeManager(Shared);
struct FakeActive(Shared);

fn object(path: &str) -> zbus::fdo::Result<OwnedObjectPath> {
    OwnedObjectPath::try_from(path)
        .map_err(|_| zbus::fdo::Error::Failed("Invalid fixture path".into()))
}
fn lock(state: &Shared) -> zbus::fdo::Result<std::sync::MutexGuard<'_, State>> {
    state
        .lock()
        .map_err(|_| zbus::fdo::Error::Failed("Fixture lock failed".into()))
}

#[zbus::interface(name = "org.freedesktop.NetworkManager.Settings")]
impl FakeSettings {
    fn list_connections(&self) -> zbus::fdo::Result<Vec<OwnedObjectPath>> {
        let state = lock(&self.0)?;
        Ok(if state.settings.is_empty() || state.hidden {
            vec![]
        } else {
            vec![object(PROFILE)?]
        })
    }
    fn add_connection2(
        &self,
        settings: Settings,
        flags: u32,
        _args: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<(OwnedObjectPath, HashMap<String, OwnedValue>)> {
        let mut state = lock(&self.0)?;
        state.settings = settings;
        state.flags.push(flags);
        if state.reply_lost {
            return Err(zbus::fdo::Error::NoReply(
                "Synthetic indeterminate save".into(),
            ));
        }
        Ok((object(PROFILE)?, HashMap::new()))
    }
}
#[zbus::interface(name = "org.freedesktop.NetworkManager.Settings.Connection")]
impl FakeProfile {
    async fn get_settings(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<Settings> {
        let release = {
            let mut state = lock(&self.0)?;
            std::mem::take(&mut state.release_on_read)
        };
        if release {
            connection
                .release_name(NM)
                .await
                .map_err(|_| zbus::fdo::Error::Failed("Fixture release failed".into()))?;
        }
        if lock(&self.0)?.unreadable {
            return Err(zbus::fdo::Error::Failed("Synthetic read race".into()));
        }
        lock(&self.0)?
            .settings
            .iter()
            .map(|(section, values)| {
                let copied = values
                    .iter()
                    .filter(|(k, _)| k.as_str() != "secrets")
                    .map(|(k, v)| {
                        v.try_clone()
                            .map(|v| (k.clone(), v))
                            .map_err(|_| zbus::fdo::Error::Failed("Fixture clone failed".into()))
                    })
                    .collect::<zbus::fdo::Result<HashMap<_, _>>>()?;
                Ok((section.clone(), copied))
            })
            .collect()
    }
    #[zbus(property)]
    fn unsaved(&self) -> zbus::fdo::Result<bool> {
        Ok(lock(&self.0)?.flags.last() == Some(&2))
    }
}
#[zbus::interface(name = "org.freedesktop.NetworkManager")]
impl FakeManager {
    #[zbus(property)]
    fn active_connections(&self) -> zbus::fdo::Result<Vec<OwnedObjectPath>> {
        Ok(if lock(&self.0)?.active {
            vec![object(ACTIVE)?]
        } else {
            vec![]
        })
    }
    fn activate_connection(
        &self,
        profile: OwnedObjectPath,
        _device: OwnedObjectPath,
        _specific: OwnedObjectPath,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        if profile.as_str() != PROFILE {
            return Err(zbus::fdo::Error::InvalidArgs(
                "Wrong fixture profile".into(),
            ));
        }
        let mut state = lock(&self.0)?;
        state.activations += 1;
        state.active = true;
        object(ACTIVE)
    }
    fn deactivate_connection(&self, active: OwnedObjectPath) -> zbus::fdo::Result<()> {
        if active.as_str() != ACTIVE {
            return Err(zbus::fdo::Error::InvalidArgs(
                "Wrong fixture active path".into(),
            ));
        }
        let mut state = lock(&self.0)?;
        state.deactivations += 1;
        state.active = false;
        Ok(())
    }
}
#[zbus::interface(name = "org.freedesktop.NetworkManager.Connection.Active")]
impl FakeActive {
    #[zbus(property)]
    fn connection(&self) -> zbus::fdo::Result<OwnedObjectPath> {
        object(PROFILE)
    }
    #[zbus(property)]
    fn uuid(&self) -> zbus::fdo::Result<String> {
        lock(&self.0)?
            .settings
            .get("connection")
            .and_then(|s| s.get("uuid"))
            .and_then(|v| <&str>::try_from(v).ok())
            .map(str::to_owned)
            .ok_or_else(|| zbus::fdo::Error::Failed("Missing fixture UUID".into()))
    }
    #[zbus(property)]
    fn state(&self) -> u32 {
        1
    } // Activation request is not Connected.
    #[zbus(property, name = "Type")]
    fn connection_type(&self) -> &str {
        "vpn"
    }
}

async fn private_bus() -> Result<(tokio::process::Child, String), Box<dyn std::error::Error>> {
    let mut daemon = tokio::process::Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--print-address=1"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut address = String::new();
    BufReader::new(daemon.stdout.take().ok_or("Missing bus pipe")?)
        .read_line(&mut address)
        .await?;
    Ok((daemon, address.trim().to_owned()))
}

async fn serve(server: &zbus::Connection, state: &Shared) -> zbus::Result<()> {
    server
        .object_server()
        .at(
            "/org/freedesktop/NetworkManager/Settings",
            FakeSettings(Arc::clone(state)),
        )
        .await?;
    server
        .object_server()
        .at(PROFILE, FakeProfile(Arc::clone(state)))
        .await?;
    server
        .object_server()
        .at(ROOT, FakeManager(Arc::clone(state)))
        .await?;
    server
        .object_server()
        .at(ACTIVE, FakeActive(Arc::clone(state)))
        .await?;
    server.request_name(NM).await
}

#[tokio::test]
async fn explicit_storage_control_and_owner_replacement_preserve_boundaries()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let (mut daemon, address) = private_bus().await?;
        let server = zbus::connection::Builder::address(address.trim())?
            .build()
            .await?;
        let client = zbus::connection::Builder::address(address.trim())?
            .build()
            .await?;
        let state = Shared::default();
        serve(&server, &state).await?;
        let bus = Bus::on(client.clone()).await?;
        assert!(bus.snapshot().await?.profiles.is_empty());
        assert_eq!(lock(&state)?.activations, 0);
        let profile = nm_tunnel_profile::Draft {
            name: "Synthetic NM client".into(),
            server: "proxy.example".into(),
            port: "443".into(),
            server_name: "peer.example".into(),
            credential: "12345678-1234-4234-8234-123456789abc".to_owned().into(),
            security: nm_tunnel_profile::Security::Tls,
            ..Default::default()
        }
        .validate()
        .map_err(|_| "Invalid fixture")?;
        let saved = bus.save(&profile, Storage::Session).await?;
        assert!(!saved.persistent());
        assert_eq!(lock(&state)?.flags, [2]);
        assert!(bus.snapshot().await?.active.is_empty());
        bus.activate(&saved).await?;
        let snapshot = bus.snapshot().await?;
        assert_eq!(snapshot.active.len(), 1);
        assert_eq!(snapshot.active[0].state(), ConnectionState::Connecting);
        assert_eq!(snapshot.active[0].profile().id(), saved.id());
        lock(&state)?.hidden = true;
        assert!(
            matches!(bus.snapshot().await, Err(ClientError::Stale)),
            "an orphan/raced VPN must not disappear from observation as Disconnected"
        );
        assert!(lock(&state)?.active);
        assert_eq!(lock(&state)?.deactivations, 0);
        lock(&state)?.hidden = false;
        bus.deactivate(&snapshot.active[0]).await?;
        assert_eq!(lock(&state)?.deactivations, 1);
        let stored = bus.save(&profile, Storage::Persistent).await?;
        assert!(stored.persistent());
        assert_eq!(lock(&state)?.flags, [2, 1]);
        assert!(
            lock(&state)?
                .settings
                .get("vpn")
                .is_some_and(|s| s.contains_key("secrets"))
        );
        assert!(!format!("{stored:?}").contains("Synthetic NM client"));
        // A path reused for another connection must not redirect an old handle.
        assert!(matches!(
            bus.activate(&saved).await,
            Err(ClientError::Stale)
        ));
        assert_eq!(lock(&state)?.activations, 1);
        lock(&state)?.active = true;
        let current = bus.snapshot().await?.active.remove(0);
        lock(&state)?.release_on_read = true;
        let current_profile = current.profile();
        assert!(matches!(
            bus.activate(current_profile).await,
            Err(ClientError::Stale)
        ));
        assert_eq!(lock(&state)?.activations, 1);
        server.request_name(NM).await?;
        lock(&state)?.release_on_read = true;
        assert!(matches!(
            bus.deactivate(&current).await,
            Err(ClientError::Stale)
        ));
        assert_eq!(lock(&state)?.deactivations, 1);
        assert!(lock(&state)?.active);
        server.request_name(NM).await?;
        lock(&state)?.release_on_read = true;
        assert!(matches!(bus.snapshot().await, Err(ClientError::Stale)));
        server.request_name(NM).await?;
        lock(&state)?.active = true;
        lock(&state)?.unreadable = true;
        assert!(
            matches!(bus.snapshot().await, Err(ClientError::Stale)),
            "unreadable active state is not Disconnected"
        );
        assert!(lock(&state)?.active);
        assert_eq!(lock(&state)?.deactivations, 1);
        lock(&state)?.unreadable = false;
        lock(&state)?.reply_lost = true;
        assert!(matches!(
            bus.save(&profile, Storage::Session).await,
            Err(ClientError::Timeout)
        ));
        assert_eq!(
            lock(&state)?.flags,
            [2, 1, 2],
            "an indeterminate completed save must not be retried"
        );
        server.release_name(NM).await?;
        let replacement = zbus::connection::Builder::address(address.trim())?
            .build()
            .await?;
        replacement.request_name(NM).await?;
        // The old unique owner is still connected and serves the same objects.
        // It must no longer receive saves or return apparently current snapshots.
        assert!(matches!(
            bus.save(&profile, Storage::Session).await,
            Err(ClientError::Stale)
        ));
        assert!(matches!(bus.snapshot().await, Err(ClientError::Stale)));
        assert_eq!(lock(&state)?.flags, [2, 1, 2]);
        let fresh = Bus::on(client).await?;
        assert!(matches!(
            fresh.activate(&stored).await,
            Err(ClientError::Stale)
        ));
        assert_eq!(lock(&state)?.activations, 1);
        daemon.kill().await?;
        daemon.wait().await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await?
}

#[tokio::test]
async fn repeated_names_paths_and_uuids_on_another_bus_do_not_revalidate_handles()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let (mut first_daemon, first_address) = private_bus().await?;
        let first_server = zbus::connection::Builder::address(first_address.as_str())?
            .build()
            .await?;
        let first_client = zbus::connection::Builder::address(first_address.as_str())?
            .build()
            .await?;
        let first_state = Shared::default();
        serve(&first_server, &first_state).await?;
        let first = Bus::on(first_client).await?;
        let profile = nm_tunnel_profile::import_vless(
            "vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example#Synthetic",
        )?
        .validate()
        .map_err(|_| "Invalid fixture")?;
        let old_profile = first.save(&profile, Storage::Persistent).await?;
        first.activate(&old_profile).await?;
        let old_active = first.snapshot().await?.active.remove(0);

        // A second daemon gives a new GetId but deterministically repeats the
        // unique names because server/client connect in the same order.
        let (mut second_daemon, second_address) = private_bus().await?;
        let second_server = zbus::connection::Builder::address(second_address.as_str())?
            .build()
            .await?;
        let second_client = zbus::connection::Builder::address(second_address.as_str())?
            .build()
            .await?;
        let second_state = Shared::default();
        {
            let mut state = lock(&second_state)?;
            state.settings = std::mem::take(&mut lock(&first_state)?.settings);
            state.flags = vec![1];
            state.active = true;
        }
        serve(&second_server, &second_state).await?;
        let second = Bus::on(second_client).await?;
        let observed = second.snapshot().await?;
        let new_profile = &observed.profiles[0];
        let new_active = &observed.active[0];
        assert_eq!(old_profile.owner, new_profile.owner);
        assert_eq!(old_profile.path, new_profile.path);
        assert_eq!(old_profile.uuid, new_profile.uuid);
        assert_eq!(old_active.path, new_active.path);
        assert_ne!(old_profile.bus_id, new_profile.bus_id);
        assert!(matches!(second.activate(&old_profile).await, Err(ClientError::Stale)));
        assert!(matches!(second.deactivate(&old_active).await, Err(ClientError::Stale)));
        assert_eq!(lock(&second_state)?.activations, 0);
        assert_eq!(lock(&second_state)?.deactivations, 0);
        assert_eq!(lock(&second_state)?.flags, [1]);
        assert!(lock(&second_state)?.active);
        second.deactivate(new_active).await?;
        assert_eq!(lock(&second_state)?.deactivations, 1);
        first_daemon.kill().await?;
        first_daemon.wait().await?;
        second_daemon.kill().await?;
        second_daemon.wait().await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await?
}
