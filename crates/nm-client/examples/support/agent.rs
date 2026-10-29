//! VM-only synthetic NM agent peer, not a desktop credential store. The real
//! service talks only to NM; this fixture exercises its standard AgentManager.
use nm_tunnel_schema::Settings;
use std::collections::HashMap;
use zbus::{
    message::Header,
    zvariant::{OwnedObjectPath, OwnedValue, Value},
};

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.NetworkManager.SecretAgent")]
enum Error {
    NoSecrets(String),
    UserCanceled(String),
    PermissionDenied(String),
}

struct Agent {
    bus: zbus::Connection,
}

impl Agent {
    async fn authorize(&self, header: &Header<'_>, connection: &Settings) -> Result<(), Error> {
        let proxy = zbus::fdo::DBusProxy::new(&self.bus)
            .await
            .map_err(|_| Error::PermissionDenied("Bus unavailable.".into()))?;
        let owner = proxy
            .get_name_owner(
                "org.freedesktop.NetworkManager"
                    .try_into()
                    .map_err(|_| Error::PermissionDenied("Invalid owner.".into()))?,
            )
            .await
            .map_err(|_| Error::PermissionDenied("Owner unavailable.".into()))?;
        if header.sender().map(|s| s.as_str()) != Some(owner.as_str()) {
            return Err(Error::PermissionDenied(
                "Only NM may request synthetic credentials.".into(),
            ));
        }
        let (name, data, _) = nm_tunnel_schema::data(connection)
            .map_err(|_| Error::NoSecrets("Not a fixture profile.".into()))?;
        if !matches!(name.as_str(), "NMT VM agent-secret" | "NMT VM ask-secret") {
            return Err(Error::NoSecrets("Not a fixture profile.".into()));
        }
        nm_tunnel_schema::decode_configuration(name, &data)
            .map_err(|_| Error::NoSecrets("Invalid fixture profile.".into()))?;
        Ok(())
    }
}

#[zbus::interface(name = "org.freedesktop.NetworkManager.SecretAgent")]
impl Agent {
    async fn get_secrets(
        &self,
        connection: Settings,
        _connection_path: OwnedObjectPath,
        setting_name: &str,
        hints: Vec<String>,
        flags: u32,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Settings, Error> {
        self.authorize(&header, &connection).await?;
        if setting_name != "vpn" || flags & 1 == 0 {
            return Err(Error::NoSecrets(
                "No noninteractive synthetic cache.".into(),
            ));
        }
        if !hints.iter().any(|key| key == "uuid") {
            return Err(Error::NoSecrets("Exact UUID hint is required.".into()));
        }
        if std::path::Path::new("/run/nmt-vm/agent-cancel").exists() {
            println!("EVENT user-cancelled");
            return Err(Error::UserCanceled("Synthetic user cancellation.".into()));
        }
        println!("EVENT hinted-credential-request");
        let secrets = HashMap::from([(
            "uuid".to_owned(),
            "12345678-1234-4234-8234-123456789abc".to_owned(),
        )]);
        let value = OwnedValue::try_from(Value::from(secrets))
            .map_err(|_| Error::NoSecrets("Encoding unavailable.".into()))?;
        Ok(HashMap::from([(
            "vpn".into(),
            HashMap::from([("secrets".into(), value)]),
        )]))
    }

    async fn cancel_get_secrets(
        &self,
        _connection_path: OwnedObjectPath,
        _setting_name: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), Error> {
        let owner = zbus::fdo::DBusProxy::new(&self.bus)
            .await
            .map_err(|_| Error::PermissionDenied("Bus unavailable.".into()))?
            .get_name_owner(
                "org.freedesktop.NetworkManager"
                    .try_into()
                    .map_err(|_| Error::PermissionDenied("Invalid owner.".into()))?,
            )
            .await
            .map_err(|_| Error::PermissionDenied("Owner unavailable.".into()))?;
        if header.sender().map(|s| s.as_str()) != Some(owner.as_str()) {
            return Err(Error::PermissionDenied("Only NM may cancel.".into()));
        }
        println!("EVENT request-cancelled");
        Ok(())
    }

    async fn save_secrets(
        &self,
        connection: Settings,
        _connection_path: OwnedObjectPath,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), Error> {
        self.authorize(&header, &connection).await?;
        // Deliberately no keyring/files: a standard desktop agent owns real
        // persistence. This synthetic peer tests dispatch, not encrypted storage.
        let (name, data, secrets) = nm_tunnel_schema::data(&connection)
            .map_err(|_| Error::NoSecrets("Invalid save request.".into()))?;
        if data.get("uuid-flags").map(String::as_str) == Some("2") {
            println!("EVENT not-saved-persistence-ignored");
        } else {
            nm_tunnel_schema::decode(name, &data, &secrets)
                .map_err(|_| Error::NoSecrets("Missing supplied synthetic credential.".into()))?;
            if secrets.get("uuid").map(String::as_str)
                != Some("12345678-1234-4234-8234-123456789abc")
            {
                return Err(Error::NoSecrets(
                    "Not the published fixture credential.".into(),
                ));
            }
            println!("EVENT agent-save-request");
        }
        Ok(())
    }

    async fn delete_secrets(
        &self,
        connection: Settings,
        _connection_path: OwnedObjectPath,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), Error> {
        self.authorize(&header, &connection).await?;
        println!("EVENT agent-delete-request");
        Ok(())
    }
}

pub async fn serve() -> Result<(), Box<dyn std::error::Error>> {
    let bus = zbus::Connection::system().await?;
    bus.object_server()
        .at(
            "/org/freedesktop/NetworkManager/SecretAgent",
            Agent { bus: bus.clone() },
        )
        .await?;
    let manager = zbus::Proxy::new(
        &bus,
        "org.freedesktop.NetworkManager",
        "/org/freedesktop/NetworkManager/AgentManager",
        "org.freedesktop.NetworkManager.AgentManager",
    )
    .await?;
    let _: () = manager
        .call(
            "RegisterWithCapabilities",
            &("org.nmtunnel.VmAcceptance", 1_u32),
        )
        .await?;
    println!("READY synthetic NM agent registered");
    let mut stop = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    stop.recv().await;
    let _: () = manager.call("Unregister", &()).await?;
    Ok(())
}
