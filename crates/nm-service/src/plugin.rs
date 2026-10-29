//! Standard NM VPN D-Bus contract, authorized only for the current NM unique owner.
use crate::{
    lifecycle::Request,
    schema::{self, Settings},
    wire::WorkerConfig,
};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};
use tokio::sync::{mpsc, oneshot};
use zbus::{message::Header, object_server::SignalEmitter, zvariant::OwnedValue};

pub(crate) const PATH: &str = "/org/freedesktop/NetworkManager/VPN/Plugin";
pub(crate) const NM: &str = "org.freedesktop.NetworkManager";
type Config = HashMap<String, OwnedValue>;

#[cfg(test)]
#[path = "plugin_tests.rs"]
mod tests;

pub(crate) struct Plugin {
    pub bus: zbus::Connection,
    pub state: Arc<AtomicU32>,
    pub requests: mpsc::Sender<Request>,
}

impl Plugin {
    async fn authorize(&self, header: &Header<'_>) -> zbus::fdo::Result<()> {
        let dbus = zbus::fdo::DBusProxy::new(&self.bus)
            .await
            .map_err(|_| denied())?;
        let name = NM.try_into().map_err(|_| denied())?;
        let owner = dbus.get_name_owner(name).await.map_err(|_| denied())?;
        if header.sender().map(|s| s.as_str()) != Some(owner.as_str()) {
            return Err(denied());
        }
        Ok(())
    }

    async fn start(
        &self,
        settings: Settings,
        header: &Header<'_>,
        interactive: bool,
    ) -> zbus::fdo::Result<()> {
        self.authorize(header).await?;
        let (name, data, secrets) = schema::data(&settings).map_err(bad)?;
        schema::decode_configuration(name.clone(), &data).map_err(bad)?;
        let missing = missing_credential(&secrets).map_err(bad)?;
        if !missing || !interactive {
            let profile = schema::decode(name.clone(), &data, &secrets).map_err(bad)?;
            nm_tunnel_engine::validate_profile(&profile)
                .map_err(|_| bad("Unsupported engine configuration."))?;
        }
        schema::ip_policy(&settings).map_err(bad)?;
        let config = WorkerConfig {
            name,
            data,
            secrets,
            endpoint: "0.0.0.0:0"
                .parse()
                .map_err(|_| bad("Internal address failed."))?,
            lan: Vec::new(),
            persistent: connection_persistent(&settings).map_err(bad)?,
        };
        let (reply, admitted) = oneshot::channel();
        let request = if missing {
            Request::Authenticate(connection_id(&settings).map_err(bad)?, config, reply)
        } else {
            Request::Start(config, reply)
        };
        self.requests
            .send(request)
            .await
            .map_err(|_| bad("VPN lifecycle is unavailable."))?;
        admitted
            .await
            .map_err(|_| bad("VPN lifecycle is unavailable."))?
            .map_err(bad)
    }
}

fn denied() -> zbus::fdo::Error {
    zbus::fdo::Error::AccessDenied("Only NetworkManager may control this plugin.".into())
}

fn connection_persistent(settings: &Settings) -> Result<bool, &'static str> {
    settings
        .get("vpn")
        .and_then(|vpn| vpn.get("persistent"))
        .map(|value| bool::try_from(value).map_err(|_| "Invalid VPN persistence setting."))
        .transpose()
        .map(|value| value.unwrap_or(false))
}

fn connection_id(settings: &Settings) -> Result<String, &'static str> {
    let id = settings
        .get("connection")
        .and_then(|s| s.get("uuid"))
        .and_then(|v| <&str>::try_from(v).ok())
        .ok_or("Missing NM connection identity.")?;
    uuid::Uuid::parse_str(id).map_err(|_| "Invalid NM connection identity.")?;
    Ok(id.to_owned())
}

fn missing_credential(secrets: &schema::Strings) -> Result<bool, &'static str> {
    if secrets.keys().any(|key| key != "uuid") {
        return Err("Unsupported secrets.");
    }
    Ok(secrets.get("uuid").is_none_or(String::is_empty))
}
fn bad(message: &'static str) -> zbus::fdo::Error {
    zbus::fdo::Error::InvalidArgs(message.into())
}

#[zbus::interface(name = "org.freedesktop.NetworkManager.VPN.Plugin")]
impl Plugin {
    async fn connect(
        &self,
        connection: Settings,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<()> {
        self.start(connection, &header, false).await
    }
    async fn connect_interactive(
        &self,
        connection: Settings,
        _details: Config,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<()> {
        self.start(connection, &header, true).await
    }
    async fn need_secrets(
        &self,
        settings: Settings,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<String> {
        self.authorize(&header).await?;
        let (name, data, secrets) = schema::data(&settings).map_err(bad)?;
        schema::decode_configuration(name.clone(), &data).map_err(bad)?;
        let missing = missing_credential(&secrets).map_err(bad)?;
        if !missing {
            schema::decode(name, &data, &secrets).map_err(bad)?;
        }
        // Agent-owned/not-saved credentials use ConnectInteractive followed by
        // SecretsRequired with the exact UUID key. A generic pre-connect prompt
        // has no key hints and desktop agents can otherwise assume "password".
        Ok(
            if missing && data.get("uuid-flags").is_none_or(|flag| flag == "0") {
                "vpn"
            } else {
                ""
            }
            .into(),
        )
    }
    async fn disconnect(&self, #[zbus(header)] header: Header<'_>) -> zbus::fdo::Result<()> {
        self.authorize(&header).await?;
        self.requests
            .send(Request::Stop)
            .await
            .map_err(|_| bad("VPN lifecycle is unavailable."))
    }
    async fn new_secrets(
        &self,
        connection: Settings,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<()> {
        self.authorize(&header).await?;
        let (name, data, secrets) = schema::data(&connection).map_err(bad)?;
        let profile = schema::decode(name.clone(), &data, &secrets).map_err(bad)?;
        nm_tunnel_engine::validate_profile(&profile)
            .map_err(|_| bad("Unsupported engine configuration."))?;
        schema::ip_policy(&connection).map_err(bad)?;
        let config = WorkerConfig {
            name,
            data,
            secrets,
            endpoint: "0.0.0.0:0"
                .parse()
                .map_err(|_| bad("Internal address failed."))?,
            lan: Vec::new(),
            persistent: connection_persistent(&connection).map_err(bad)?,
        };
        let (reply, received) = oneshot::channel();
        self.requests
            .send(Request::Secrets(
                connection_id(&connection).map_err(bad)?,
                config,
                reply,
            ))
            .await
            .map_err(|_| bad("VPN lifecycle is unavailable."))?;
        received
            .await
            .map_err(|_| bad("VPN lifecycle is unavailable."))?
            .map_err(bad)
    }
    #[zbus(property)]
    fn state(&self) -> u32 {
        self.state.load(Ordering::SeqCst)
    }
    #[zbus(signal, name = "StateChanged")]
    async fn emit_state(emitter: &SignalEmitter<'_>, state: u32) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn config(emitter: &SignalEmitter<'_>, config: Config) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn ip4_config(emitter: &SignalEmitter<'_>, config: Config) -> zbus::Result<()>;
    #[zbus(signal)]
    pub(crate) async fn failure(emitter: &SignalEmitter<'_>, reason: u32) -> zbus::Result<()>;
    #[zbus(signal)]
    pub(crate) async fn secrets_required(
        emitter: &SignalEmitter<'_>,
        message: &str,
        secrets: Vec<&str>,
    ) -> zbus::Result<()>;
}

pub(crate) async fn change(
    bus: &zbus::Connection,
    state: &AtomicU32,
    value: u32,
) -> zbus::Result<()> {
    state.store(value, Ordering::SeqCst);
    Plugin::emit_state(&SignalEmitter::new(bus, PATH)?, value).await
}

fn ip4(ip: std::net::Ipv4Addr) -> OwnedValue {
    OwnedValue::from(u32::from_ne_bytes(ip.octets()))
}

pub(crate) async fn announce(
    bus: &zbus::Connection,
    endpoint: std::net::SocketAddr,
    resolver: std::net::Ipv4Addr,
    lan: &crate::lan::Plan,
    source_policy: Option<&nm_tunnel_profile::SourcePolicy>,
) -> zbus::Result<()> {
    let std::net::IpAddr::V4(gateway) = endpoint.ip() else {
        return Err(zbus::Error::Failure("IPv6 endpoint refused.".into()));
    };
    let emitter = SignalEmitter::new(bus, PATH)?;
    Plugin::config(
        &emitter,
        HashMap::from([
            (
                "tundev".into(),
                OwnedValue::from(zbus::zvariant::Str::from("nmtun0")),
            ),
            ("gateway".into(), ip4(gateway)),
            (
                "mtu".into(),
                OwnedValue::from(source_policy.map_or(1400, |policy| u32::from(policy.mtu()))),
            ),
            ("has-ip4".into(), OwnedValue::from(true)),
            ("has-ip6".into(), OwnedValue::from(false)),
            ("can-persist".into(), OwnedValue::from(true)),
        ]),
    )
    .await?;
    let dns = OwnedValue::try_from(zbus::zvariant::Value::from(vec![u32::from_ne_bytes(
        resolver.octets(),
    )]))?;
    let mut config = HashMap::from([
        (
            "address".into(),
            ip4(
                source_policy.map_or(std::net::Ipv4Addr::new(198, 18, 0, 1), |policy| {
                    policy.tun_address()
                }),
            ),
        ),
        ("ptp".into(), ip4(std::net::Ipv4Addr::new(198, 18, 0, 2))),
        (
            "prefix".into(),
            OwnedValue::from(source_policy.map_or(32, |policy| u32::from(policy.tun_prefix()))),
        ),
        ("dns".into(), dns),
        ("never-default".into(), OwnedValue::from(true)),
    ]);
    if source_policy.is_some() {
        config.remove("ptp");
    }
    config.insert(
        "routes".into(),
        OwnedValue::try_from(zbus::zvariant::Value::from(lan.routes()))?,
    );
    Plugin::ip4_config(&emitter, config).await
}
