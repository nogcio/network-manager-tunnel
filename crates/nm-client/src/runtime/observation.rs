//! Read-only NM metadata and handle validation. Never retrieves secrets or writes.
use super::{ActiveConnection, ConnectionState, SavedProfile, Snapshot};
use crate::{
    ClientError,
    transport::{Bus, NM, ROOT},
};
use nm_tunnel_profile::SERVICE_TYPE;
use std::collections::HashMap;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

pub(super) type Settings = HashMap<String, HashMap<String, OwnedValue>>;

pub(super) struct Observation<'a> {
    bus: &'a Bus,
}

impl<'a> Observation<'a> {
    pub(super) fn new(bus: &'a Bus) -> Self {
        Self { bus }
    }

    pub(super) async fn profile(
        &self,
        path: OwnedObjectPath,
    ) -> Result<Option<SavedProfile>, ClientError> {
        Ok(self
            .profile_with_settings(path)
            .await?
            .map(|(profile, _)| profile))
    }

    pub(super) async fn profile_with_settings(
        &self,
        path: OwnedObjectPath,
    ) -> Result<Option<(SavedProfile, Settings)>, ClientError> {
        let proxy = self
            .bus
            .proxy(
                path.as_str(),
                "org.freedesktop.NetworkManager.Settings.Connection",
            )
            .await?;
        let version_id = proxy
            .get_property::<u64>("VersionId")
            .await
            .ok()
            .filter(|id| *id != 0);
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
        let data = settings
            .get("vpn")
            .and_then(|s| s.get("data"))
            .and_then(|value| value.try_clone().ok())
            .and_then(|value| HashMap::<String, String>::try_from(value).ok());
        if text("connection", "type") != Some("vpn")
            || text("vpn", "service-type") != Some(SERVICE_TYPE)
            || !data.as_ref().is_some_and(|d| {
                d.get("schema-version")
                    .is_some_and(|v| matches!(v.as_str(), "1" | "2"))
                    && d.get("protocol").is_some_and(|v| v == "vless")
            })
        {
            return Ok(None);
        }
        let policy = nm_tunnel_schema::decode_policy(data.as_ref().ok_or(ClientError::Stale)?)
            .map_err(|_| ClientError::Stale)?;
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
        let final_version = proxy
            .get_property::<u64>("VersionId")
            .await
            .ok()
            .filter(|id| *id != 0);
        if version_id != final_version {
            return Err(ClientError::Stale);
        }
        Ok(Some((
            SavedProfile {
                bus_id: self.bus.bus_id.clone(),
                owner: self.bus.owner.clone(),
                path,
                uuid,
                name,
                persistent: !unsaved,
                dns_override: policy.dns_override(),
                lan_bypass: policy.lan_bypass() == nm_tunnel_schema::LanBypass::Connected,
                private_lan_bypass: policy.lan_bypass() == nm_tunnel_schema::LanBypass::Private,
                dns_interception: policy.intercepts_dns(),
                fake_ip: policy.fake_ip(),
                version_id,
                source_policy: policy.source().is_some(),
            },
            settings,
        )))
    }

    pub(super) fn validate_identity(&self, profile: &SavedProfile) -> Result<(), ClientError> {
        if profile.bus_id != self.bus.bus_id || profile.owner != self.bus.owner {
            return Err(ClientError::Stale);
        }
        Ok(())
    }

    pub(super) async fn validate(&self, profile: &SavedProfile) -> Result<(), ClientError> {
        self.validate_identity(profile)?;
        let current = self
            .profile(profile.path.clone())
            .await?
            .ok_or(ClientError::Stale)?;
        if current.uuid != profile.uuid {
            return Err(ClientError::Stale);
        }
        Ok(())
    }

    pub(super) async fn snapshot(&self) -> Result<Snapshot, ClientError> {
        let settings = self
            .bus
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
        let nm = self.bus.proxy(ROOT, NM).await?;
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
                .bus
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
                // A removed VPN profile must not fabricate Disconnected state.
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
                owner: self.bus.owner.clone(),
                path,
                profile: profile.clone(),
                state,
            });
        }
        let dbus = zbus::fdo::DBusProxy::new(&self.bus.connection)
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
        self.bus.validate_owner().await?;
        Ok(Snapshot {
            profiles,
            active,
            backend_registered: owned || registered,
        })
    }
}
