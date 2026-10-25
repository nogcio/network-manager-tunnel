//! Privileged activation resources; protocol parsing and packet processing run unprivileged.
use crate::{
    network,
    telemetry::Telemetry,
    wire::{self, WorkerConfig},
};
use std::{collections::HashMap, io, net::Ipv4Addr, os::fd::AsFd, process::Stdio, time::Duration};
use tokio::{
    io::AsyncReadExt,
    net::UnixStream,
    process::{Child, Command},
    sync::oneshot,
    task::JoinHandle,
    time::timeout,
};
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

pub(crate) struct AbortTask<T>(pub JoinHandle<T>);
impl<T> Drop for AbortTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) struct Session {
    pub child: Child,
    pub broker: AbortTask<io::Result<()>>,
    pub endpoint: std::net::SocketAddr,
    _telemetry: AbortTask<io::Result<()>>,
    _device: tun_rs::SyncDevice,
}

/// A fixed-window grant limit with bounded backpressure, never a session failure.
/// The broker processes one request at a time; no additional request queue is allocated.
struct SocketBudget {
    window: tokio::time::Instant,
    used: u32,
}

impl SocketBudget {
    fn new() -> Self {
        Self {
            window: tokio::time::Instant::now(),
            used: 0,
        }
    }

    async fn acquire(&mut self) {
        let end = self.window + Duration::from_secs(1);
        if self.used == 64 && tokio::time::Instant::now() < end {
            tokio::time::sleep_until(end).await;
        }
        if tokio::time::Instant::now() >= end {
            self.window = tokio::time::Instant::now();
            self.used = 0;
        }
        self.used += 1;
    }
}

#[cfg(test)]
#[path = "activation_tests.rs"]
mod tests;

impl Session {
    pub async fn stop(mut self) {
        let _ = self.child.start_kill();
        let _ = timeout(Duration::from_secs(3), self.child.wait()).await;
    }
}

async fn uplink(bus: &zbus::Connection) -> io::Result<(String, Ipv4Addr)> {
    let nm = zbus::Proxy::new(
        bus,
        "org.freedesktop.NetworkManager",
        "/org/freedesktop/NetworkManager",
        "org.freedesktop.NetworkManager",
    )
    .await
    .map_err(|_| failure())?;
    let active: OwnedObjectPath = nm
        .get_property("PrimaryConnection")
        .await
        .map_err(|_| failure())?;
    if active.as_str() == "/" {
        return Err(failure());
    }
    let active = zbus::Proxy::new(
        bus,
        "org.freedesktop.NetworkManager",
        active,
        "org.freedesktop.NetworkManager.Connection.Active",
    )
    .await
    .map_err(|_| failure())?;
    let devices: Vec<OwnedObjectPath> = active
        .get_property("Devices")
        .await
        .map_err(|_| failure())?;
    let path = devices.first().ok_or_else(failure)?;
    let device = zbus::Proxy::new(
        bus,
        "org.freedesktop.NetworkManager",
        path,
        "org.freedesktop.NetworkManager.Device",
    )
    .await
    .map_err(|_| failure())?;
    let interface: String = device
        .get_property("Interface")
        .await
        .map_err(|_| failure())?;
    if interface.len() > 15
        || !interface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.:".contains(&b))
    {
        return Err(failure());
    }
    let ip4: OwnedObjectPath = active
        .get_property("Ip4Config")
        .await
        .map_err(|_| failure())?;
    let config = zbus::Proxy::new(
        bus,
        "org.freedesktop.NetworkManager",
        ip4,
        "org.freedesktop.NetworkManager.IP4Config",
    )
    .await
    .map_err(|_| failure())?;
    let dns: Vec<HashMap<String, OwnedValue>> = config
        .get_property("NameserverData")
        .await
        .map_err(|_| failure())?;
    let dns = dns
        .iter()
        .filter_map(|entry| entry.get("address"))
        .filter_map(|v| <&str>::try_from(v).ok())
        .filter_map(|v| v.parse::<Ipv4Addr>().ok())
        .find(|v| !v.is_loopback() && !v.is_unspecified())
        .ok_or_else(failure)?;
    Ok((interface, dns))
}

fn failure() -> io::Error {
    io::Error::other("No usable NetworkManager uplink/bootstrap DNS.")
}

pub(crate) async fn prepare(
    bus: zbus::Connection,
    mut config: WorkerConfig,
    telemetry: Telemetry,
) -> io::Result<Session> {
    let (interface, dns) = timeout(Duration::from_secs(5), uplink(&bus))
        .await
        .map_err(|_| failure())??;
    eprintln!("Activation stage: uplink selected.");
    let host = config.data.get("server").ok_or_else(failure)?;
    let port = config
        .data
        .get("port")
        .ok_or_else(failure)?
        .parse::<u16>()
        .map_err(|_| failure())?;
    telemetry.stage("guard");
    network::guard(true).await?;
    eprintln!("Activation stage: guard installed.");
    telemetry.stage("resolve");
    config.endpoint = network::resolve(host, port, &interface, dns).await?;
    eprintln!("Activation stage: endpoint resolved.");
    telemetry.stage("tun");
    let device = tun_rs::DeviceBuilder::new()
        .name("nmtun0")
        .enable(false)
        .packet_information(false)
        .offload(false)
        .build_sync()?;
    eprintln!("Activation stage: TUN created.");
    let tun_file: std::fs::File = device.as_fd().try_clone_to_owned()?.into();
    let (parent, child) = std::os::unix::net::UnixStream::pair()?;
    parent.set_nonblocking(true)?;
    let control: std::os::fd::OwnedFd = child.into();
    let (statistics, worker_statistics) = std::os::unix::net::UnixDatagram::pair()?;
    statistics.set_nonblocking(true)?;
    worker_statistics.set_nonblocking(true)?;
    let statistics = tokio::net::UnixDatagram::from_std(statistics)?;
    let worker_statistics: std::os::fd::OwnedFd = worker_statistics.into();
    telemetry.stage("worker");
    let mut worker = Command::new("/usr/bin/setpriv")
        .args([
            "--reuid",
            "nm-tunnel",
            "--regid",
            "nm-tunnel",
            "--clear-groups",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--no-new-privs",
            "--pdeathsig",
            "KILL",
            "--",
        ])
        .arg(std::env::current_exe()?)
        .arg("--worker")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::from(tun_file))
        .stdout(Stdio::from(worker_statistics))
        .stderr(Stdio::from(control))
        .kill_on_drop(true)
        .spawn()?;
    // NM's normal capability set omits CAP_SETPCAP, so dropping the inherited
    // bounding ceiling is not permitted. The UID transition clears permitted
    // and effective caps; inheritable/ambient are explicitly empty, and
    // no-new-privs prevents later exec from regaining privilege.
    eprintln!("Activation stage: unprivileged worker spawned.");
    telemetry.stage("readiness");
    let receiver = telemetry.clone();
    let telemetry_task = AbortTask(tokio::spawn(
        async move { receiver.receive(statistics).await },
    ));
    let mut stream = UnixStream::from_std(parent)?;
    wire::send_config(&mut stream, &config).await?;
    let endpoint = config.endpoint;
    drop(config);
    let (ready_tx, ready_rx) = oneshot::channel();
    let broker = AbortTask(tokio::spawn(async move {
        let mut ready_tx = Some(ready_tx);
        let mut budget = SocketBudget::new();
        loop {
            let code = stream.read_u8().await?;
            match code {
                b'O' => {
                    budget.acquire().await;
                    let socket = network::tcp(endpoint, &interface).await?;
                    wire::send_socket(&stream, &socket).await?;
                }
                b'R' => {
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(());
                    } else {
                        return Err(io::Error::other("Duplicate worker readiness."));
                    }
                }
                b'E' => {
                    let stage = stream.read_u8().await?;
                    telemetry.worker_stage(stage);
                    eprintln!("Unprivileged worker failed at setup stage {stage}.");
                    return Err(io::Error::other("Worker reported failure."));
                }
                _ => {
                    return Err(io::Error::other(
                        "Worker failed or sent invalid control data.",
                    ));
                }
            }
        }
    }));
    if !matches!(timeout(Duration::from_secs(25), ready_rx).await, Ok(Ok(()))) {
        let _ = worker.start_kill();
        return Err(io::Error::other("Worker readiness timeout."));
    }
    if broker.0.is_finished() || worker.try_wait()?.is_some() {
        return Err(io::Error::other("Worker failed before readiness."));
    }
    Ok(Session {
        child: worker,
        broker,
        endpoint,
        _telemetry: telemetry_task,
        _device: device,
    })
}
