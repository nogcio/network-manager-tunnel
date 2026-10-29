//! Explicit NM writes/control. Every request has one dispatch, no fallback or retry.
use super::{ActiveConnection, SavedProfile, observation::Observation};
use crate::{
    ClientError,
    transport::{Bus, NM, ROOT},
};
use nm_tunnel_profile::Profile;
use std::collections::HashMap;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

fn request_error(error: zbus::Error, saving: bool) -> ClientError {
    // Only a definite remote refusal proves the operation failed.
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

pub(super) struct Mutation<'a> {
    bus: &'a Bus,
}

impl<'a> Mutation<'a> {
    pub(super) fn new(bus: &'a Bus) -> Self {
        Self { bus }
    }

    async fn checked_settings(
        &self,
        saved: &SavedProfile,
    ) -> Result<(u64, crate::runtime::observation::Settings), ClientError> {
        let observation = Observation::new(self.bus);
        observation.validate_identity(saved)?;
        let expected = saved.version_id.ok_or(ClientError::UpdateUnsupported)?;
        let (current, settings) = observation
            .profile_with_settings(saved.path.clone())
            .await?
            .ok_or(ClientError::Stale)?;
        if current.uuid != saved.uuid || current.version_id != Some(expected) {
            return Err(ClientError::Stale);
        }
        Ok((expected, settings))
    }

    pub(super) async fn edit(
        &self,
        saved: &SavedProfile,
        changes: &crate::ProfileChanges,
    ) -> Result<(), ClientError> {
        let (expected, settings) = self.checked_settings(saved).await?;
        let settings = changes.apply(settings).map_err(|_| ClientError::Rejected)?;
        let proxy = self
            .bus
            .proxy(
                saved.path.as_str(),
                "org.freedesktop.NetworkManager.Settings.Connection",
            )
            .await?;
        let args = HashMap::from([("version-id".to_owned(), OwnedValue::from(expected))]);
        self.bus.validate_owner().await?;
        let _: HashMap<String, OwnedValue> = proxy
            .call_with_flags(
                "Update2",
                zbus::proxy::MethodFlags::AllowInteractiveAuth.into(),
                &(settings, 0x61_u32, args),
            )
            .await
            .map_err(|error| request_error(error, true))?
            .ok_or(ClientError::Timeout)?;
        Ok(())
    }

    pub(super) async fn source_update(
        &self,
        saved: &SavedProfile,
        profile: &Profile,
    ) -> Result<(), ClientError> {
        let (expected, settings) = self.checked_settings(saved).await?;
        let settings = crate::settings::source_update_settings(settings, profile)?;
        let proxy = self
            .bus
            .proxy(
                saved.path.as_str(),
                "org.freedesktop.NetworkManager.Settings.Connection",
            )
            .await?;
        let args = HashMap::from([("version-id".to_owned(), OwnedValue::from(expected))]);
        self.bus.validate_owner().await?;
        let _: HashMap<String, OwnedValue> = proxy
            .call_with_flags(
                "Update2",
                zbus::proxy::MethodFlags::AllowInteractiveAuth.into(),
                &(settings, 0x61_u32, args),
            )
            .await
            .map_err(|error| request_error(error, true))?
            .ok_or(ClientError::Timeout)?;
        Ok(())
    }

    pub(super) async fn delete(&self, saved: &SavedProfile) -> Result<(), ClientError> {
        let _ = self.checked_settings(saved).await?;
        let snapshot = Observation::new(self.bus).snapshot().await?;
        if !snapshot.profiles.contains(saved)
            || snapshot
                .active
                .iter()
                .any(|active| active.profile.id() == saved.id())
        {
            return Err(ClientError::Stale);
        }
        let proxy = self
            .bus
            .proxy(
                saved.path.as_str(),
                "org.freedesktop.NetworkManager.Settings.Connection",
            )
            .await?;
        self.bus.validate_owner().await?;
        proxy
            .call_with_flags::<_, _, ()>(
                "Delete",
                zbus::proxy::MethodFlags::AllowInteractiveAuth.into(),
                &(),
            )
            .await
            .map_err(|error| request_error(error, true))?
            .ok_or(ClientError::Timeout)
    }

    #[cfg(test)]
    pub(super) async fn save(&self, profile: &Profile) -> Result<SavedProfile, ClientError> {
        self.save_with_options(profile, crate::ProfileOptions::default())
            .await
    }

    pub(super) async fn save_with_options(
        &self,
        profile: &Profile,
        options: crate::ProfileOptions,
    ) -> Result<SavedProfile, ClientError> {
        let proxy = self
            .bus
            .proxy(
                "/org/freedesktop/NetworkManager/Settings",
                "org.freedesktop.NetworkManager.Settings",
            )
            .await?;
        let settings = nm_tunnel_schema::encode_profile_with_options(profile, options);
        // TO_DISK only; never fall back to memory on authorization/storage failure.
        let flags = 1_u32;
        let args: HashMap<String, OwnedValue> = HashMap::new();
        self.bus.validate_owner().await?;
        let (path, _): (OwnedObjectPath, HashMap<String, OwnedValue>) = proxy
            .call_with_flags(
                "AddConnection2",
                zbus::proxy::MethodFlags::AllowInteractiveAuth.into(),
                &(settings.values(), flags, args),
            )
            .await
            .map_err(|e| request_error(e, true))?
            .ok_or(ClientError::Timeout)?;
        // No fallible post-write read can hide a remotely completed save.
        let uuid = settings
            .values()
            .get("connection")
            .and_then(|s| s.get("uuid"))
            .and_then(|v| <&str>::try_from(v).ok())
            .ok_or(ClientError::Timeout)?
            .to_owned();
        Ok(SavedProfile {
            bus_id: self.bus.bus_id.clone(),
            owner: self.bus.owner.clone(),
            path,
            uuid,
            name: profile.name().to_owned(),
            persistent: true,
            dns_override: profile.network().dns_override(),
            lan_bypass: profile.lan_bypass() == nm_tunnel_profile::LanBypass::Connected,
            private_lan_bypass: profile.lan_bypass() == nm_tunnel_profile::LanBypass::Private,
            dns_interception: profile.network().intercepts_dns(),
            fake_ip: profile.network().fake_ip(),
            version_id: None,
            source_policy: profile.network().source().is_some(),
        })
    }

    pub(super) async fn replace(
        &self,
        saved: &SavedProfile,
        profile: &Profile,
    ) -> Result<SavedProfile, ClientError> {
        let observation = Observation::new(self.bus);
        observation.validate_identity(saved)?;
        let expected = saved.version_id.ok_or(ClientError::UpdateUnsupported)?;
        let (current, settings) = observation
            .profile_with_settings(saved.path.clone())
            .await?
            .ok_or(ClientError::Stale)?;
        if current.uuid != saved.uuid || current.version_id != Some(expected) {
            return Err(ClientError::Stale);
        }
        let settings = crate::settings::replacement_settings(settings, profile)?;
        let proxy = self
            .bus
            .proxy(
                saved.path.as_str(),
                "org.freedesktop.NetworkManager.Settings.Connection",
            )
            .await?;
        let args = HashMap::from([("version-id".to_owned(), OwnedValue::from(expected))]);
        // TO_DISK | BLOCK_AUTOCONNECT | NO_REAPPLY. No legacy Update fallback.
        self.bus.validate_owner().await?;
        let _: HashMap<String, OwnedValue> = proxy
            .call_with_flags(
                "Update2",
                zbus::proxy::MethodFlags::AllowInteractiveAuth.into(),
                &(settings, 0x61_u32, args),
            )
            .await
            .map_err(|error| request_error(error, true))?
            .ok_or(ClientError::Timeout)?;
        // Preserve confirmed success without post-write reads or guessed VersionId.
        Ok(SavedProfile {
            persistent: true,
            dns_override: profile.network().dns_override(),
            lan_bypass: profile.lan_bypass() == nm_tunnel_profile::LanBypass::Connected,
            private_lan_bypass: profile.lan_bypass() == nm_tunnel_profile::LanBypass::Private,
            dns_interception: profile.network().intercepts_dns(),
            fake_ip: profile.network().fake_ip(),
            version_id: None,
            source_policy: profile.network().source().is_some(),
            ..current
        })
    }

    pub(super) async fn activate(&self, profile: &SavedProfile) -> Result<(), ClientError> {
        Observation::new(self.bus).validate(profile).await?;
        let nm = self.bus.proxy(ROOT, NM).await?;
        let root = OwnedObjectPath::try_from("/").map_err(|_| ClientError::Control)?;
        self.bus.validate_owner().await?;
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

    pub(super) async fn deactivate(&self, active: &ActiveConnection) -> Result<(), ClientError> {
        Observation::new(self.bus).validate(&active.profile).await?;
        if active.owner != self.bus.owner {
            return Err(ClientError::Stale);
        }
        let proxy = self
            .bus
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
        let nm = self.bus.proxy(ROOT, NM).await?;
        self.bus.validate_owner().await?;
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
