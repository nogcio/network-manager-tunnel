//! NM owns all saved/active state. Handles are pinned to its bus ID and unique owner.
use crate::{ClientError, TIMEOUT, encode_profile};
use nm_tunnel_profile::{Profile, SERVICE_TYPE};
use std::collections::HashMap;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

const NM: &str = "org.freedesktop.NetworkManager";
const ROOT: &str = "/org/freedesktop/NetworkManager";
type Settings = HashMap<String, HashMap<String, OwnedValue>>;

fn request_error(error: zbus::Error, saving: bool) -> ClientError {
    // NoReply/disconnection/decoding errors do not prove that a write failed.
    // Only a definite remote method error is classified as a refusal.
    let refused = matches!(&error, zbus::Error::MethodError(name, _, _)
        if !matches!(name.as_str(), "org.freedesktop.DBus.Error.NoReply" | "org.freedesktop.DBus.Error.Timeout"
            | "org.freedesktop.DBus.Error.Disconnected" | "org.freedesktop.DBus.Error.ServiceUnknown"
            | "org.freedesktop.DBus.Error.NameHasNoOwner"));
    match (saving, refused) {
        (true, true) => ClientError::Rejected,
        (true, false) => ClientError::Timeout,
        (false, true) => ClientError::Control,
        (false, false) => ClientError::ControlTimeout,
    }
}

/// Explicit storage consent. Both modes disable autoconnect. Persistent mode
/// stores credentials using NM system storage and may require a Polkit prompt;
/// it never claims a desktop secret agent owns them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Storage {
    /// Memory-only NM profile, lost when NM restarts.
    #[default]
    Session,
    /// NM saves profile and system-owned credentials to its backing storage.
    Persistent,
}

/// Non-secret profile identity obtained from NM, not an app-side profile database.
/// Invalid after bus restart or NM owner replacement; no arbitrary-path constructor exists.
#[derive(Clone, PartialEq, Eq)]
pub struct SavedProfile {
    bus_id: String,
    owner: String,
    path: OwnedObjectPath,
    uuid: String,
    name: String,
    persistent: bool,
}
impl std::fmt::Debug for SavedProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SavedProfile([redacted])")
    }
}
impl SavedProfile {
    /// Independent NM connection UUID, not the authentication UUID.
    pub fn id(&self) -> &str {
        &self.uuid
    }
    /// User-visible NM profile name. Never log it as diagnostic context.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Whether NM reports this profile as saved to its backing storage.
    pub fn persistent(&self) -> bool {
        self.persistent
    }
}

/// State observed from NM, never inferred from method-call completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    /// NM is still establishing the connection.
    Connecting,
    /// NM reports an activated connection.
    Connected,
    /// NM is tearing the connection down.
    Disconnecting,
    /// NM returned a state not handled by this client.
    Unknown,
}

/// One active NM object belonging to this service. Multiple objects are reported
/// rather than arbitrarily disconnecting another connection on the user's behalf.
#[derive(Clone)]
pub struct ActiveConnection {
    owner: String,
    path: OwnedObjectPath,
    profile: SavedProfile,
    state: ConnectionState,
}
impl std::fmt::Debug for ActiveConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ActiveConnection([redacted])")
    }
}
impl ActiveConnection {
    /// The corresponding saved profile identity.
    pub fn profile(&self) -> &SavedProfile {
        &self.profile
    }
    /// Last state returned by NM. Refresh after control requests and errors.
    pub fn state(&self) -> ConnectionState {
        self.state
    }
}

/// Read-only NM metadata. Contains no secret lookup and performs no activation.
#[derive(Clone, Debug)]
pub struct Snapshot {
    /// Schema-v1 profiles for this service; unrelated VPNs are excluded.
    pub profiles: Vec<SavedProfile>,
    /// Currently active/activating objects for those profiles.
    pub active: Vec<ActiveConnection>,
    /// D-Bus ownership/activation registration only, not runtime readiness or
    /// protocol compatibility. Checking it never starts the VPN service.
    pub backend_registered: bool,
}

struct Bus {
    connection: zbus::Connection,
    bus_id: String,
    owner: String,
}
impl Bus {
    async fn system() -> Result<Self, ClientError> {
        Self::on(
            zbus::Connection::system()
                .await
                .map_err(|_| ClientError::Unavailable)?,
        )
        .await
    }
    async fn on(connection: zbus::Connection) -> Result<Self, ClientError> {
        let dbus = zbus::fdo::DBusProxy::new(&connection)
            .await
            .map_err(|_| ClientError::Unavailable)?;
        let bus_id = dbus
            .get_id()
            .await
            .map_err(|_| ClientError::Unavailable)?
            .to_string();
        let owner = dbus
            .get_name_owner(NM.try_into().map_err(|_| ClientError::Unavailable)?)
            .await
            .map_err(|_| ClientError::Unavailable)?
            .to_string();
        Ok(Self {
            connection,
            bus_id,
            owner,
        })
    }
    async fn validate_owner(&self) -> Result<(), ClientError> {
        let owner = zbus::fdo::DBusProxy::new(&self.connection)
            .await
            .map_err(|_| ClientError::Unavailable)?
            .get_name_owner(NM.try_into().map_err(|_| ClientError::Unavailable)?)
            .await
            .map_err(|_| ClientError::Stale)?;
        if owner.as_str() != self.owner {
            return Err(ClientError::Stale);
        }
        Ok(())
    }
    async fn proxy<'a>(
        &'a self,
        path: &'a str,
        interface: &'a str,
    ) -> Result<zbus::Proxy<'a>, ClientError> {
        zbus::Proxy::new(&self.connection, self.owner.as_str(), path, interface)
            .await
            .map_err(|_| ClientError::Unavailable)
    }
    async fn profile(&self, path: OwnedObjectPath) -> Result<Option<SavedProfile>, ClientError> {
        let proxy = self
            .proxy(
                path.as_str(),
                "org.freedesktop.NetworkManager.Settings.Connection",
            )
            .await?;
        let settings: Settings = proxy
            .call("GetSettings", &())
            .await
            .map_err(|_| ClientError::Stale)?;
        let text = |section: &str, key: &str| {
            settings
                .get(section)
                .and_then(|s| s.get(key))
                .and_then(|v| <&str>::try_from(v).ok())
        };
        if text("connection", "type") != Some("vpn")
            || text("vpn", "service-type") != Some(SERVICE_TYPE)
            || !settings
                .get("vpn")
                .and_then(|s| s.get("data"))
                .and_then(|v| v.try_clone().ok())
                .and_then(|v| HashMap::<String, String>::try_from(v).ok())
                .is_some_and(|d| {
                    d.get("schema-version").is_some_and(|v| v == "1")
                        && d.get("protocol").is_some_and(|v| v == "vless")
                })
        {
            return Ok(None);
        }
        let uuid = text("connection", "uuid")
            .ok_or(ClientError::Stale)?
            .to_owned();
        uuid::Uuid::parse_str(&uuid).map_err(|_| ClientError::Stale)?;
        let name = text("connection", "id")
            .ok_or(ClientError::Stale)?
            .to_owned();
        let unsaved: bool = proxy
            .get_property("Unsaved")
            .await
            .map_err(|_| ClientError::Unavailable)?;
        Ok(Some(SavedProfile {
            bus_id: self.bus_id.clone(),
            owner: self.owner.clone(),
            path: path.clone(),
            uuid,
            name,
            persistent: !unsaved,
        }))
    }
    async fn validate(&self, profile: &SavedProfile) -> Result<(), ClientError> {
        if profile.bus_id != self.bus_id || profile.owner != self.owner {
            return Err(ClientError::Stale);
        }
        let current = self
            .profile(profile.path.clone())
            .await?
            .ok_or(ClientError::Stale)?;
        if current.uuid != profile.uuid {
            return Err(ClientError::Stale);
        }
        Ok(())
    }
    async fn save(&self, profile: &Profile, storage: Storage) -> Result<SavedProfile, ClientError> {
        let proxy = self
            .proxy(
                "/org/freedesktop/NetworkManager/Settings",
                "org.freedesktop.NetworkManager.Settings",
            )
            .await?;
        let settings = encode_profile(profile);
        let flags = match storage {
            Storage::Session => 2_u32,
            Storage::Persistent => 1_u32,
        };
        let args: HashMap<String, OwnedValue> = HashMap::new();
        // Ownership can still change between this check and dispatch. Addressing
        // the unique owner prevents redirecting the write to its replacement.
        self.validate_owner().await?;
        let (path, _): (OwnedObjectPath, HashMap<String, OwnedValue>) = proxy
            .call_with_flags(
                "AddConnection2",
                zbus::proxy::MethodFlags::AllowInteractiveAuth.into(),
                &(settings.values(), flags, args),
            )
            .await
            .map_err(|e| request_error(e, true))?
            .ok_or(ClientError::Timeout)?;
        // No second, fallible read after a successful save: that would conceal a
        // remotely completed write behind a retryable-looking read error.
        let uuid = settings
            .values()
            .get("connection")
            .and_then(|s| s.get("uuid"))
            .and_then(|v| <&str>::try_from(v).ok())
            .ok_or(ClientError::Timeout)?
            .to_owned();
        Ok(SavedProfile {
            bus_id: self.bus_id.clone(),
            owner: self.owner.clone(),
            path,
            uuid,
            name: profile.fields().name.clone(),
            persistent: storage == Storage::Persistent,
        })
    }
    async fn snapshot(&self) -> Result<Snapshot, ClientError> {
        let settings = self
            .proxy(
                "/org/freedesktop/NetworkManager/Settings",
                "org.freedesktop.NetworkManager.Settings",
            )
            .await?;
        let profile_paths: Vec<OwnedObjectPath> = settings
            .call("ListConnections", &())
            .await
            .map_err(|_| ClientError::Unavailable)?;
        if profile_paths.len() > 1024 {
            return Err(ClientError::Unavailable);
        }
        let mut profiles = Vec::new();
        for path in &profile_paths {
            if let Some(profile) = self.profile(path.clone()).await? {
                profiles.push(profile);
            }
        }
        let nm = self.proxy(ROOT, NM).await?;
        let paths: Vec<OwnedObjectPath> = nm
            .get_property("ActiveConnections")
            .await
            .map_err(|_| ClientError::Unavailable)?;
        if paths.len() > 1024 {
            return Err(ClientError::Unavailable);
        }
        let mut active = Vec::new();
        for path in paths {
            let proxy = self
                .proxy(
                    path.as_str(),
                    "org.freedesktop.NetworkManager.Connection.Active",
                )
                .await?;
            let connection: OwnedObjectPath = proxy
                .get_property("Connection")
                .await
                .map_err(|_| ClientError::Stale)?;
            let Some(profile) = profiles.iter().find(|p| p.path == connection) else {
                // A missing profile may be an in-flight removal, not a foreign
                // VPN. Do not turn that ambiguous active object into Disconnected.
                if !profile_paths.contains(&connection) {
                    let kind: String = proxy
                        .get_property("Type")
                        .await
                        .map_err(|_| ClientError::Stale)?;
                    if kind == "vpn" {
                        return Err(ClientError::Stale);
                    }
                }
                continue;
            };
            let uuid: String = proxy
                .get_property("Uuid")
                .await
                .map_err(|_| ClientError::Stale)?;
            if uuid != profile.uuid {
                return Err(ClientError::Stale);
            }
            let state: u32 = proxy
                .get_property("State")
                .await
                .map_err(|_| ClientError::Stale)?;
            if state == 4 {
                continue;
            }
            let state = match state {
                1 => ConnectionState::Connecting,
                2 => ConnectionState::Connected,
                3 => ConnectionState::Disconnecting,
                _ => ConnectionState::Unknown,
            };
            active.push(ActiveConnection {
                owner: self.owner.clone(),
                path: path.clone(),
                profile: profile.clone(),
                state,
            });
        }
        let dbus = zbus::fdo::DBusProxy::new(&self.connection)
            .await
            .map_err(|_| ClientError::Unavailable)?;
        let owned = dbus
            .name_has_owner(
                SERVICE_TYPE
                    .try_into()
                    .map_err(|_| ClientError::Unavailable)?,
            )
            .await
            .map_err(|_| ClientError::Unavailable)?;
        let registered = dbus
            .list_activatable_names()
            .await
            .map_err(|_| ClientError::Unavailable)?
            .iter()
            .any(|name| name.as_str() == SERVICE_TYPE);
        self.validate_owner().await?;
        Ok(Snapshot {
            profiles,
            active,
            backend_registered: owned || registered,
        })
    }
    async fn activate(&self, profile: &SavedProfile) -> Result<(), ClientError> {
        self.validate(profile).await?;
        let nm = self.proxy(ROOT, NM).await?;
        let root = OwnedObjectPath::try_from("/").map_err(|_| ClientError::Control)?;
        self.validate_owner().await?;
        let _: OwnedObjectPath = nm
            .call_with_flags(
                "ActivateConnection",
                zbus::proxy::MethodFlags::AllowInteractiveAuth.into(),
                &(&profile.path, &root, &root),
            )
            .await
            .map_err(|e| request_error(e, false))?
            .ok_or(ClientError::ControlTimeout)?;
        Ok(())
    }
    async fn deactivate(&self, active: &ActiveConnection) -> Result<(), ClientError> {
        self.validate(&active.profile).await?;
        if active.owner != self.owner {
            return Err(ClientError::Stale);
        }
        let proxy = self
            .proxy(
                active.path.as_str(),
                "org.freedesktop.NetworkManager.Connection.Active",
            )
            .await?;
        let path: OwnedObjectPath = proxy
            .get_property("Connection")
            .await
            .map_err(|_| ClientError::Stale)?;
        let uuid: String = proxy
            .get_property("Uuid")
            .await
            .map_err(|_| ClientError::Stale)?;
        if path != active.profile.path || uuid != active.profile.uuid {
            return Err(ClientError::Stale);
        }
        let nm = self.proxy(ROOT, NM).await?;
        self.validate_owner().await?;
        nm.call_with_flags::<_, _, ()>(
            "DeactivateConnection",
            zbus::proxy::MethodFlags::AllowInteractiveAuth.into(),
            &(&active.path,),
        )
        .await
        .map_err(|e| request_error(e, false))?
        .ok_or(ClientError::ControlTimeout)
    }
}

/// Explicit save. Session is the default; Persistent requires visible user consent
/// to NM system-stored credentials. Timeout is indeterminate: never auto-retry.
pub async fn save_profile_with_storage(
    profile: Profile,
    storage: Storage,
) -> Result<SavedProfile, ClientError> {
    tokio::time::timeout(TIMEOUT, async {
        Bus::system().await?.save(&profile, storage).await
    })
    .await
    .map_err(|_| ClientError::Timeout)?
}
/// Read profile/active metadata, not credentials; never activates a service/profile.
/// Races/removal return an error, not a fabricated disconnected state.
pub async fn snapshot() -> Result<Snapshot, ClientError> {
    tokio::time::timeout(TIMEOUT, async { Bus::system().await?.snapshot().await })
        .await
        .map_err(|_| ClientError::Unavailable)?
}
/// Request activation of an NM-issued handle. Success is request acceptance only;
/// observe `snapshot` for Connected. Cancellation/timeout may leave activation running.
pub async fn activate(profile: &SavedProfile) -> Result<(), ClientError> {
    tokio::time::timeout(TIMEOUT, async {
        Bus::system().await?.activate(profile).await
    })
    .await
    .map_err(|_| ClientError::ControlTimeout)?
}
/// Explicitly deactivate only this observed active object. Never clears a firewall
/// guard or chooses another VPN. Completion does not prove resource teardown.
pub async fn deactivate(active: &ActiveConnection) -> Result<(), ClientError> {
    tokio::time::timeout(TIMEOUT, async {
        Bus::system().await?.deactivate(active).await
    })
    .await
    .map_err(|_| ClientError::ControlTimeout)?
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
