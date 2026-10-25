//! Standard NM VPN D-Bus contract, authorized only for the current NM unique owner.
use crate::{
    activation::{self, AbortTask, Session},
    network,
    schema::{self, Settings},
    telemetry::Telemetry,
    wire::WorkerConfig,
};
use std::{
    collections::HashMap,
    io,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};
use tokio::sync::{mpsc, oneshot};
use zbus::{message::Header, object_server::SignalEmitter, zvariant::OwnedValue};

pub(crate) const PATH: &str = "/org/freedesktop/NetworkManager/VPN/Plugin";
const NM: &str = "org.freedesktop.NetworkManager";
type Config = HashMap<String, OwnedValue>;

#[cfg(test)]
#[path = "plugin_tests.rs"]
mod tests;

pub(crate) enum Request {
    Start(WorkerConfig, oneshot::Sender<Result<(), &'static str>>),
    Stop,
}

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

    async fn start(&self, settings: Settings, header: &Header<'_>) -> zbus::fdo::Result<()> {
        self.authorize(header).await?;
        let (name, data, secrets) = schema::data(&settings).map_err(bad)?;
        let profile = schema::decode(name.clone(), &data, &secrets, false).map_err(bad)?;
        nm_tunnel_engine::validate_profile(&profile)
            .map_err(|_| bad("Unsupported engine configuration."))?;
        schema::ip_policy(&settings).map_err(bad)?;
        let config = WorkerConfig {
            name,
            data,
            secrets,
            endpoint: "0.0.0.0:0"
                .parse()
                .map_err(|_| bad("Internal address failed."))?,
        };
        let (reply, admitted) = oneshot::channel();
        self.requests
            .send(Request::Start(config, reply))
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
        self.start(connection, &header).await
    }
    async fn connect_interactive(
        &self,
        connection: Settings,
        _details: Config,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<()> {
        self.start(connection, &header).await
    }
    async fn need_secrets(
        &self,
        settings: Settings,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<String> {
        self.authorize(&header).await?;
        let (name, data, secrets) = schema::data(&settings).map_err(bad)?;
        schema::decode(name, &data, &secrets, true).map_err(bad)?;
        Ok(if secrets.get("uuid").is_none_or(String::is_empty) {
            "vpn"
        } else {
            ""
        }
        .into())
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
        _connection: Settings,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<()> {
        self.authorize(&header).await?;
        Err(bad("Secrets must be supplied before Connect."))
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
    async fn failure(emitter: &SignalEmitter<'_>, reason: u32) -> zbus::Result<()>;
}

async fn change(bus: &zbus::Connection, state: &AtomicU32, value: u32) -> zbus::Result<()> {
    state.store(value, Ordering::SeqCst);
    Plugin::emit_state(&SignalEmitter::new(bus, PATH)?, value).await
}

fn ip4(ip: std::net::Ipv4Addr) -> OwnedValue {
    OwnedValue::from(u32::from_ne_bytes(ip.octets()))
}

async fn announce(bus: &zbus::Connection, endpoint: std::net::SocketAddr) -> zbus::Result<()> {
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
            ("mtu".into(), OwnedValue::from(1400_u32)),
            ("has-ip4".into(), OwnedValue::from(true)),
            ("has-ip6".into(), OwnedValue::from(false)),
            ("can-persist".into(), OwnedValue::from(false)),
        ]),
    )
    .await?;
    let dns = OwnedValue::try_from(zbus::zvariant::Value::from(vec![u32::from_ne_bytes(
        network::VPN_DNS.octets(),
    )]))?;
    Plugin::ip4_config(
        &emitter,
        HashMap::from([
            (
                "address".into(),
                ip4(std::net::Ipv4Addr::new(198, 18, 0, 1)),
            ),
            ("ptp".into(), ip4(std::net::Ipv4Addr::new(198, 18, 0, 2))),
            ("prefix".into(), OwnedValue::from(32_u32)),
            ("dns".into(), dns),
            ("never-default".into(), OwnedValue::from(false)),
        ]),
    )
    .await
}

async fn await_preparation(
    pending: &mut Option<AbortTask<io::Result<Session>>>,
) -> io::Result<Session> {
    match pending {
        Some(task) => (&mut task.0)
            .await
            .map_err(|_| io::Error::other("Activation task failed."))?,
        None => std::future::pending().await,
    }
}

/// Only the lifecycle owner admits starts, in queue order with Stops. Check owned
/// resources as well as reported state so a stale state cannot replace a task.
fn admit_start(state: &AtomicU32, pending: bool, session: bool) -> Result<(), &'static str> {
    if pending || session || !matches!(state.load(Ordering::SeqCst), 1 | 6) {
        return Err("A VPN activation is already owned by this service.");
    }
    state.store(3, Ordering::SeqCst);
    Ok(())
}

async fn cancel_preparation(pending: &mut Option<AbortTask<io::Result<Session>>>) {
    if let Some(mut task) = pending.take() {
        task.0.abort();
        // Completion may have won the cancellation race. Retain that Session's
        // ownership until its child has been stopped, rather than detaching it.
        if let Ok(Ok(active)) = (&mut task.0).await {
            active.stop().await;
        }
    }
}
async fn await_worker(session: &mut Option<Session>) {
    match session {
        Some(session) => {
            tokio::select! { _ = session.child.wait() => {}, _ = &mut session.broker.0 => {} }
        }
        None => std::future::pending().await,
    }
}

pub(crate) async fn lifecycle(
    bus: zbus::Connection,
    state: Arc<AtomicU32>,
    mut requests: mpsc::Receiver<Request>,
    telemetry: Telemetry,
) -> zbus::Result<()> {
    let mut pending = None;
    let mut session: Option<Session> = None;
    // NM may D-Bus-activate a replacement just to send Disconnect after a crash.
    // That replacement must not interpret a retained guard as its own clean session.
    let mut failed = network::guard_present().await.unwrap_or(true);
    let dbus = zbus::fdo::DBusProxy::new(&bus).await?;
    let mut owners = dbus.receive_name_owner_changed().await?;
    let mut termination = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| zbus::Error::Failure("Signal handling unavailable.".into()))?;
    use futures_util::StreamExt;
    enum Event {
        Request(Option<Request>),
        Prepared(io::Result<Session>),
        Worker,
        Shutdown,
    }
    loop {
        let event = tokio::select! {
            request = requests.recv() => Event::Request(request),
            result = await_preparation(&mut pending) => Event::Prepared(result),
            _ = await_worker(&mut session) => Event::Worker,
            _ = tokio::signal::ctrl_c() => Event::Shutdown,
            _ = termination.recv() => Event::Shutdown,
            signal = owners.next() => {
                if signal.is_none_or(|signal| signal.args().is_ok_and(|args| args.name().as_str() == NM)) { Event::Shutdown } else { continue; }
            }
        };
        match event {
            Event::Request(Some(Request::Start(config, reply))) => {
                if reply.is_closed() {
                    continue;
                }
                if let Err(error) = admit_start(&state, pending.is_some(), session.is_some()) {
                    let _ = reply.send(Err(error));
                    continue;
                }
                change(&bus, &state, 3).await?;
                telemetry.begin();
                pending = Some(AbortTask(tokio::spawn(activation::prepare(
                    bus.clone(),
                    config,
                    telemetry.clone(),
                ))));
                // Once admitted, cancellation of the D-Bus reply does not detach
                // preparation: the lifecycle still owns it through Stop/shutdown.
                let _ = reply.send(Ok(()));
            }
            Event::Prepared(result) => {
                pending = None;
                match result {
                    Ok(active) => {
                        failed = false;
                        announce(&bus, active.endpoint).await?;
                        session = Some(active);
                        change(&bus, &state, 4).await?;
                        telemetry.stage("ready");
                        telemetry.state("running");
                        eprintln!("VPN worker ready; NM owns IP configuration.");
                    }
                    Err(error) => {
                        failed = true;
                        telemetry.state("failed");
                        Plugin::failure(&SignalEmitter::new(&bus, PATH)?, 1).await?;
                        change(&bus, &state, 6).await?;
                        eprintln!(
                            "VPN activation failed (kind {:?}, OS error {:?}); protection was not cleared.",
                            error.kind(),
                            error.raw_os_error()
                        );
                    }
                }
            }
            Event::Worker => {
                failed = true;
                telemetry.state("failed");
                if let Some(active) = session.take() {
                    active.stop().await;
                }
                Plugin::failure(&SignalEmitter::new(&bus, PATH)?, 1).await?;
                change(&bus, &state, 6).await?;
                eprintln!("VPN worker stopped unexpectedly; fail-closed guard remains.");
            }
            Event::Request(Some(Request::Stop)) => {
                telemetry.state("stopping");
                change(&bus, &state, 5).await?;
                cancel_preparation(&mut pending).await;
                if let Some(active) = session.take() {
                    active.stop().await;
                }
                if !failed {
                    network::guard(false)
                        .await
                        .map_err(|_| zbus::Error::Failure("Guard teardown failed.".into()))?;
                }
                change(&bus, &state, 6).await?;
                telemetry.state(if failed { "failed" } else { "stopped" });
            }
            Event::Shutdown | Event::Request(None) => {
                telemetry.state("stopped");
                cancel_preparation(&mut pending).await;
                if let Some(active) = session.take() {
                    active.stop().await;
                }
                return Ok(());
            }
        }
    }
}
