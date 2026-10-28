//! Owner-pinned NM transport. No profile observation or mutation policy lives here.
use crate::ClientError;

pub(super) const NM: &str = "org.freedesktop.NetworkManager";
pub(super) const ROOT: &str = "/org/freedesktop/NetworkManager";

pub(super) struct Bus {
    pub(super) connection: zbus::Connection,
    pub(super) bus_id: String,
    pub(super) owner: String,
}

impl Bus {
    pub(super) async fn system() -> Result<Self, ClientError> {
        Self::on(
            zbus::Connection::system()
                .await
                .map_err(|_| ClientError::Unavailable)?,
        )
        .await
    }

    pub(super) async fn on(connection: zbus::Connection) -> Result<Self, ClientError> {
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

    pub(super) async fn validate_owner(&self) -> Result<(), ClientError> {
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

    pub(super) async fn proxy<'a>(
        &'a self,
        path: &'a str,
        interface: &'a str,
    ) -> Result<zbus::Proxy<'a>, ClientError> {
        zbus::proxy::Builder::<zbus::Proxy<'_>>::new(&self.connection)
            .destination(self.owner.as_str())
            .map_err(|_| ClientError::Unavailable)?
            .path(path)
            .map_err(|_| ClientError::Unavailable)?
            .interface(interface)
            .map_err(|_| ClientError::Unavailable)?
            .cache_properties(zbus::proxy::CacheProperties::No)
            .build()
            .await
            .map_err(|_| ClientError::Unavailable)
    }
}

/// Read-only service observation, separate from NM mutation identity. Pin/recheck
/// unique ownership, disable caching, and require NoAutoStart at every call site.
pub(super) struct ReadOnly<'a> {
    connection: &'a zbus::Connection,
    name: &'static str,
    owner: zbus::names::OwnedUniqueName,
}

impl<'a> ReadOnly<'a> {
    pub async fn pin(
        connection: &'a zbus::Connection,
        name: &'static str,
    ) -> zbus::Result<Option<Self>> {
        let dbus = zbus::fdo::DBusProxy::new(connection).await?;
        let owner = match dbus.get_name_owner(name.try_into()?).await {
            Ok(owner) => owner,
            Err(zbus::fdo::Error::NameHasNoOwner(_)) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        Ok(Some(Self {
            connection,
            name,
            owner,
        }))
    }

    pub async fn proxy<'b>(
        &'b self,
        path: &'b str,
        interface: &'b str,
    ) -> zbus::Result<zbus::Proxy<'b>> {
        zbus::proxy::Builder::<zbus::Proxy<'_>>::new(self.connection)
            .destination(self.owner.as_str())?
            .path(path)?
            .interface(interface)?
            .cache_properties(zbus::proxy::CacheProperties::No)
            .build()
            .await
    }

    pub async fn validate(&self) -> zbus::Result<()> {
        let current = zbus::fdo::DBusProxy::new(self.connection)
            .await?
            .get_name_owner(self.name.try_into()?)
            .await?;
        if current != self.owner {
            return Err(zbus::Error::Failure("Observation owner changed.".into()));
        }
        Ok(())
    }
}
