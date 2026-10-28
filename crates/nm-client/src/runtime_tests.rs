//! Private bus contracts: no host NM, credentials retrieval, routes or activation.
use super::observation::Settings;
use super::*;
use crate::transport::{NM, ROOT};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, BufReader};
use zbus::zvariant::OwnedValue;

const PROFILE: &str = "/org/freedesktop/NetworkManager/Settings/1";
const ACTIVE: &str = "/org/freedesktop/NetworkManager/ActiveConnection/1";

#[path = "editing_tests.rs"]
mod editing;

#[tokio::test]
async fn private_mode_observation_is_distinct_from_connected_mode_without_activation()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let (mut daemon, address) = private_bus().await?;
        let server = zbus::connection::Builder::address(address.as_str())?.build().await?;
        let client = zbus::connection::Builder::address(address.as_str())?.build().await?;
        let state = Shared::default();
        serve(&server, &state).await?;
        let bus = Bus::on(client).await?;
        let mut draft = nm_tunnel_profile::import_vless("vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example")?;
        draft.private_lan_bypass = true;
        draft.dns_interception = true;
        let profile = draft.validate().map_err(|_| "Invalid fixture")?;
        let saved = Mutation::new(&bus).save(&profile).await?;
        assert!(saved.private_lan_bypass() && !saved.lan_bypass());
        let observed = Observation::new(&bus).snapshot().await?.profiles.remove(0);
        assert!(observed.private_lan_bypass() && !observed.lan_bypass());
        assert!(observed.dns_interception());
        assert_eq!(lock(&state)?.activations, 0);
        daemon.kill().await?;
        daemon.wait().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    }).await?
}

#[derive(Default)]
struct State {
    settings: Settings,
    flags: Vec<u32>,
    save_requests: Vec<u32>,
    activations: usize,
    deactivations: usize,
    active: bool,
    unreadable: bool,
    hidden: bool,
    reply_lost: bool,
    reject_save: bool,
    release_on_read: bool,
    version_id: u64,
    updates: Vec<u32>,
    reject_update: bool,
    race_update: bool,
    unversioned: bool,
    race_read: bool,
    deletes: usize,
    reject_delete: bool,
    update_payload: Option<Settings>,
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
        state.save_requests.push(flags);
        if state.reject_save {
            return Err(zbus::fdo::Error::AccessDenied(
                "Synthetic persistent save refusal".into(),
            ));
        }
        state.settings = settings;
        state.version_id = state.version_id.max(1) + 1;
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
    fn update2(
        &self,
        settings: Settings,
        flags: u32,
        args: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<HashMap<String, OwnedValue>> {
        let mut state = lock(&self.0)?;
        state.updates.push(flags);
        if state.reject_update {
            return Err(zbus::fdo::Error::AccessDenied(
                "Synthetic update refusal".into(),
            ));
        }
        if state.race_update {
            state.version_id = state.version_id.max(1) + 1;
        }
        let expected = args
            .get("version-id")
            .and_then(|value| u64::try_from(value).ok());
        if flags != 0x61 || args.len() != 1 || expected != Some(state.version_id.max(1)) {
            return Err(zbus::fdo::Error::Failed(
                "Synthetic version mismatch".into(),
            ));
        }
        state.update_payload = Some(settings.clone());
        let mut settings = settings;
        if !settings
            .values()
            .any(|section| section.contains_key("secrets"))
            && let Some(secrets) = state
                .settings
                .get("vpn")
                .and_then(|vpn| vpn.get("secrets"))
                .and_then(|v| v.try_clone().ok())
        {
            settings
                .get_mut("vpn")
                .ok_or_else(|| zbus::fdo::Error::Failed("Missing VPN".into()))?
                .insert("secrets".into(), secrets);
        }
        state.settings = settings;
        state.version_id = state.version_id.max(1) + 1;
        if state.reply_lost {
            return Err(zbus::fdo::Error::NoReply(
                "Synthetic completed update without reply".into(),
            ));
        }
        Ok(HashMap::new())
    }
    #[zbus(property)]
    fn version_id(&self) -> zbus::fdo::Result<u64> {
        if lock(&self.0)?.unversioned {
            return Err(zbus::fdo::Error::UnknownProperty("VersionId".into()));
        }
        Ok(lock(&self.0)?.version_id.max(1))
    }
    fn delete(&self) -> zbus::fdo::Result<()> {
        let mut state = lock(&self.0)?;
        state.deletes += 1;
        if state.reject_delete {
            return Err(zbus::fdo::Error::AccessDenied("Synthetic refusal".into()));
        }
        state.settings.clear();
        if state.reply_lost {
            return Err(zbus::fdo::Error::NoReply(
                "Synthetic completed delete without reply".into(),
            ));
        }
        Ok(())
    }
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
        {
            let mut state = lock(&self.0)?;
            if std::mem::take(&mut state.race_read) {
                state.version_id = state.version_id.max(1) + 1;
            }
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

#[tokio::test]
async fn checked_replacement_preserves_identity_and_acl_without_reconnecting_or_reading_secrets()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let (mut daemon, address) = private_bus().await?;
        let server = zbus::connection::Builder::address(address.as_str())?.build().await?;
        let client = zbus::connection::Builder::address(address.as_str())?.build().await?;
        let state = Shared::default();
        serve(&server, &state).await?;
        let bus = Bus::on(client).await?;
        let original = nm_tunnel_profile::import_vless(
            "vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example#Original",
        )?.validate().map_err(|_| "Invalid fixture")?;
        let saved = Mutation::new(&bus).save(&original).await?;
        assert!(matches!(Mutation::new(&bus).replace(&saved, &original).await, Err(ClientError::UpdateUnsupported)));
        assert!(lock(&state)?.updates.is_empty());
        {
            let mut state = lock(&state)?;
            state.active = true;
            state.settings.get_mut("connection").ok_or("Missing connection")?
                .insert("permissions".into(), zbus::zvariant::Value::from(vec!["user:synthetic:".to_owned()]).try_to_owned()?);
            state.settings.get_mut("ipv4").ok_or("Missing IPv4")?
                .insert("route-metric".into(), OwnedValue::from(321_i64));
        }
        let observed = Observation::new(&bus).snapshot().await?.profiles.remove(0);
        let mut draft = original.to_draft();
        draft.name = "Do not rename existing NM profile".into();
        draft.server = "replacement.example".into();
        draft.credential = "12345678-1234-4234-8234-123456789abd".to_owned().into();
        draft.dns_override = nm_tunnel_profile::DnsOverride::CurrentNetwork;
        draft.dns_interception = true;
        draft.fake_ip = true;
        draft.source_policy = Some(nm_tunnel_profile::SourcePolicy::from_json(r#"{"version":1,"dns":{"address":"1.1.1.1","port":853,"transport":"tls","via_proxy":true,"tls_name":"1.1.1.1"},"domain_policy":"{\"version\":1,\"rules\":[{\"domain_suffix\":[\"direct.example\"],\"action\":\"direct\"}]}","fakeip_range":"198.18.0.0/15","tun_address":"172.19.0.1","tun_prefix":30,"mtu":1400}"#)?);
        let replacement = draft.validate().map_err(|_| "Invalid replacement")?;
        let updated = Mutation::new(&bus).replace(&observed, &replacement).await?;
        assert_eq!(updated.id(), saved.id());
        assert_eq!(updated.name(), "Original");
        assert!(updated.persistent() && updated.fake_ip() && updated.dns_interception());
        assert!(updated.native_source_policy());
        assert!(Observation::new(&bus).snapshot().await?.profiles.remove(0).native_source_policy());
        assert!(updated.version_id.is_none());
        {
            let state = lock(&state)?;
            assert_eq!(state.updates, [0x61]);
            assert!(state.active);
            assert_eq!((state.activations, state.deactivations), (0, 0));
            assert_eq!(<&str>::try_from(&state.settings["connection"]["uuid"])?, saved.id());
            assert_eq!(<&str>::try_from(&state.settings["connection"]["id"])?, "Original");
            assert!(!bool::try_from(&state.settings["connection"]["autoconnect"])?);
            assert_eq!(Vec::<String>::try_from(state.settings["connection"]["permissions"].try_clone()?)?, ["user:synthetic:"]);
            assert!(!state.settings["ipv4"].contains_key("route-metric"));
            let data = HashMap::<String, String>::try_from(state.settings["vpn"]["data"].try_clone()?)?;
            assert_eq!(data["server"], "replacement.example");
            assert_eq!(data["schema-version"], "2");
            assert_eq!(data["source-policy"], replacement.network().source().ok_or("Missing source policy")?.as_json());
            assert!(!data.values().any(|value| value.contains("12345678-1234")));
            let secrets = HashMap::<String, String>::try_from(state.settings["vpn"]["secrets"].try_clone()?)?;
            assert_eq!(secrets["uuid"], "12345678-1234-4234-8234-123456789abd");
        }
        assert!(matches!(Mutation::new(&bus).replace(&observed, &replacement).await, Err(ClientError::Stale)));
        assert_eq!(lock(&state)?.updates.len(), 1);
        daemon.kill().await?;
        daemon.wait().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    }).await?
}

#[tokio::test]
async fn replacement_rejection_races_and_lost_replies_never_fall_back_or_retry()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let (mut daemon, address) = private_bus().await?;
        let server = zbus::connection::Builder::address(address.as_str())?.build().await?;
        let client = zbus::connection::Builder::address(address.as_str())?.build().await?;
        let state = Shared::default();
        serve(&server, &state).await?;
        let bus = Bus::on(client).await?;
        let profile = nm_tunnel_profile::import_vless(
            "vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example#Synthetic",
        )?.validate().map_err(|_| "Invalid fixture")?;
        Mutation::new(&bus).save(&profile).await?;
        lock(&state)?.unversioned = true;
        let observed = Observation::new(&bus).snapshot().await?.profiles.remove(0);
        assert!(!observed.checked_update_available());
        assert!(matches!(Mutation::new(&bus).replace(&observed, &profile).await, Err(ClientError::UpdateUnsupported)));
        assert!(lock(&state)?.updates.is_empty());
        lock(&state)?.unversioned = false;
        let observed = Observation::new(&bus).snapshot().await?.profiles.remove(0);
        lock(&state)?.race_read = true;
        assert!(matches!(Mutation::new(&bus).replace(&observed, &profile).await, Err(ClientError::Stale)));
        assert!(lock(&state)?.updates.is_empty());
        let observed = Observation::new(&bus).snapshot().await?.profiles.remove(0);
        let before_reuse = lock(&state)?.settings.clone();
        lock(&state)?.settings.get_mut("connection").ok_or("Missing connection")?
            .insert("uuid".into(), zbus::zvariant::Value::from(uuid::Uuid::new_v4().to_string()).try_to_owned()?);
        let reused = lock(&state)?.settings.clone();
        assert!(matches!(Mutation::new(&bus).replace(&observed, &profile).await, Err(ClientError::Stale)));
        assert_eq!(lock(&state)?.settings, reused);
        assert!(lock(&state)?.updates.is_empty());
        lock(&state)?.settings = before_reuse;
        for race in [false, true] {
            let observed = Observation::new(&bus).snapshot().await?.profiles.remove(0);
            let before = lock(&state)?.settings.clone();
            lock(&state)?.reject_update = !race;
            lock(&state)?.race_update = race;
            assert!(matches!(Mutation::new(&bus).replace(&observed, &profile).await, Err(ClientError::Rejected)));
            assert_eq!(lock(&state)?.settings, before);
        }
        lock(&state)?.reject_update = false;
        lock(&state)?.race_update = false;
        let observed = Observation::new(&bus).snapshot().await?.profiles.remove(0);
        lock(&state)?.release_on_read = true;
        assert!(matches!(Mutation::new(&bus).replace(&observed, &profile).await, Err(ClientError::Stale)));
        assert_eq!(lock(&state)?.updates.len(), 2);
        server.request_name(NM).await?;
        let observed = Observation::new(&bus).snapshot().await?.profiles.remove(0);
        lock(&state)?.reply_lost = true;
        let mut draft = profile.to_draft();
        draft.server = "completed.example".into();
        let changed = draft.validate().map_err(|_| "Invalid fixture")?;
        assert!(matches!(Mutation::new(&bus).replace(&observed, &changed).await, Err(ClientError::Timeout)));
        {
            let state = lock(&state)?;
            assert_eq!(state.updates, [0x61, 0x61, 0x61]);
            assert_eq!(state.save_requests, [1]);
            assert_eq!((state.activations, state.deactivations), (0, 0));
            let data = HashMap::<String, String>::try_from(state.settings["vpn"]["data"].try_clone()?)?;
            assert_eq!(data["server"], "completed.example");
        }
        daemon.kill().await?;
        daemon.wait().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    }).await?
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
        assert!(Observation::new(&bus).snapshot().await?.profiles.is_empty());
        assert_eq!(lock(&state)?.activations, 0);
        let profile = nm_tunnel_profile::Draft {
            name: "Synthetic NM client".into(),
            server: "proxy.example".into(),
            port: "443".into(),
            server_name: "peer.example".into(),
            credential: "12345678-1234-4234-8234-123456789abc".to_owned().into(),
            security: nm_tunnel_profile::Security::Tls,
            tcp_domain_policy: Some(nm_tunnel_profile::TcpDomainPolicy::from_json(
                r#"{"version":1,"rules":[{"domain_suffix":["direct.example"],"action":"direct"}]}"#,
            )?),
            dns_override: nm_tunnel_profile::DnsOverride::CurrentNetwork,
            lan_bypass: true,
            ..Default::default()
        }
        .validate()
        .map_err(|_| "Invalid fixture")?;
        // A rejected persistent save must not create a session profile or activate.
        lock(&state)?.reject_save = true;
        assert!(matches!(
            Mutation::new(&bus).save(&profile).await,
            Err(ClientError::Rejected)
        ));
        assert!(lock(&state)?.settings.is_empty());
        assert!(lock(&state)?.flags.is_empty());
        assert_eq!(lock(&state)?.save_requests, [1], "no in-memory fallback");
        assert_eq!(lock(&state)?.activations, 0);
        lock(&state)?.reject_save = false;
        let saved = Mutation::new(&bus).save(&profile).await?;
        assert!(saved.persistent());
        assert_eq!(lock(&state)?.flags, [1]);
        let initial = Observation::new(&bus).snapshot().await?;
        assert!(initial.profiles[0].persistent());
        assert!(saved.lan_bypass());
        assert!(initial.profiles[0].lan_bypass());
        assert!(!initial.profiles[0].dns_interception());
        assert_eq!(
            initial.profiles[0].dns_override(),
            nm_tunnel_profile::DnsOverride::CurrentNetwork
        );
        assert!(initial.active.is_empty());
        assert_eq!(lock(&state)?.activations, 0);
        assert!(!bool::try_from(
            &lock(&state)?.settings["connection"]["autoconnect"]
        )?);
        Mutation::new(&bus).activate(&saved).await?;
        let snapshot = Observation::new(&bus).snapshot().await?;
        assert_eq!(snapshot.active.len(), 1);
        assert_eq!(snapshot.active[0].state(), ConnectionState::Connecting);
        assert_eq!(snapshot.active[0].profile().id(), saved.id());
        lock(&state)?.hidden = true;
        assert!(
            matches!(
                Observation::new(&bus).snapshot().await,
                Err(ClientError::Stale)
            ),
            "an orphan/raced VPN must not disappear from observation as Disconnected"
        );
        assert!(lock(&state)?.active);
        assert_eq!(lock(&state)?.deactivations, 0);
        lock(&state)?.hidden = false;
        Mutation::new(&bus).deactivate(&snapshot.active[0]).await?;
        assert_eq!(lock(&state)?.deactivations, 1);
        let mut intercepted = profile.to_draft();
        intercepted.lan_bypass = true;
        intercepted.dns_interception = true;
        intercepted.fake_ip = true;
        let stored = Mutation::new(&bus)
            .save(
                &intercepted
                    .validate()
                    .map_err(|_| "Invalid interception fixture")?,
            )
            .await?;
        assert!(stored.persistent());
        assert!(stored.dns_interception());
        assert!(stored.fake_ip());
        assert!(stored.lan_bypass());
        assert!(Observation::new(&bus).snapshot().await?.profiles[0].dns_interception());
        assert!(Observation::new(&bus).snapshot().await?.profiles[0].fake_ip());
        assert_eq!(lock(&state)?.flags, [1, 1]);
        assert!(
            lock(&state)?
                .settings
                .get("vpn")
                .is_some_and(|s| s.contains_key("secrets"))
        );
        assert!(!format!("{stored:?}").contains("Synthetic NM client"));
        // A path reused for another connection must not redirect an old handle.
        assert!(matches!(
            Mutation::new(&bus).activate(&saved).await,
            Err(ClientError::Stale)
        ));
        assert_eq!(lock(&state)?.activations, 1);
        lock(&state)?.active = true;
        let current = Observation::new(&bus).snapshot().await?.active.remove(0);
        lock(&state)?.release_on_read = true;
        let current_profile = current.profile();
        assert!(matches!(
            Mutation::new(&bus).activate(current_profile).await,
            Err(ClientError::Stale)
        ));
        assert_eq!(lock(&state)?.activations, 1);
        server.request_name(NM).await?;
        lock(&state)?.release_on_read = true;
        assert!(matches!(
            Mutation::new(&bus).deactivate(&current).await,
            Err(ClientError::Stale)
        ));
        assert_eq!(lock(&state)?.deactivations, 1);
        assert!(lock(&state)?.active);
        server.request_name(NM).await?;
        lock(&state)?.release_on_read = true;
        assert!(matches!(
            Observation::new(&bus).snapshot().await,
            Err(ClientError::Stale)
        ));
        server.request_name(NM).await?;
        lock(&state)?.active = true;
        lock(&state)?.unreadable = true;
        assert!(
            matches!(
                Observation::new(&bus).snapshot().await,
                Err(ClientError::Stale)
            ),
            "unreadable active state is not Disconnected"
        );
        assert!(lock(&state)?.active);
        assert_eq!(lock(&state)?.deactivations, 1);
        lock(&state)?.unreadable = false;
        lock(&state)?.reply_lost = true;
        assert!(matches!(
            Mutation::new(&bus).save(&profile).await,
            Err(ClientError::Timeout)
        ));
        assert_eq!(
            lock(&state)?.flags,
            [1, 1, 1],
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
            Mutation::new(&bus).save(&profile).await,
            Err(ClientError::Stale)
        ));
        assert!(matches!(
            Observation::new(&bus).snapshot().await,
            Err(ClientError::Stale)
        ));
        assert_eq!(lock(&state)?.flags, [1, 1, 1]);
        let fresh = Bus::on(client).await?;
        assert!(matches!(
            Mutation::new(&fresh).activate(&stored).await,
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
        let old_profile = Mutation::new(&first).save(&profile).await?;
        Mutation::new(&first).activate(&old_profile).await?;
        let old_active = Observation::new(&first).snapshot().await?.active.remove(0);

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
        let observed = Observation::new(&second).snapshot().await?;
        let new_profile = &observed.profiles[0];
        let new_active = &observed.active[0];
        assert_eq!(old_profile.owner, new_profile.owner);
        assert_eq!(old_profile.path, new_profile.path);
        assert_eq!(old_profile.uuid, new_profile.uuid);
        assert_eq!(old_active.path, new_active.path);
        assert_ne!(old_profile.bus_id, new_profile.bus_id);
        assert!(matches!(Mutation::new(&second).activate(&old_profile).await, Err(ClientError::Stale)));
        assert!(matches!(Mutation::new(&second).deactivate(&old_active).await, Err(ClientError::Stale)));
        assert!(matches!(Mutation::new(&second).replace(&old_profile, &profile).await, Err(ClientError::Stale)));
        assert!(lock(&second_state)?.updates.is_empty());
        assert_eq!(lock(&second_state)?.activations, 0);
        assert_eq!(lock(&second_state)?.deactivations, 0);
        assert_eq!(lock(&second_state)?.flags, [1]);
        assert!(lock(&second_state)?.active);
        Mutation::new(&second).deactivate(new_active).await?;
        assert_eq!(lock(&second_state)?.deactivations, 1);
        first_daemon.kill().await?;
        first_daemon.wait().await?;
        second_daemon.kill().await?;
        second_daemon.wait().await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await?
}
