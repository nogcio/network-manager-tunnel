//! Privileged activation and selected source-DNS authority; application packets run unprivileged.
use crate::{
    network::{bootstrap, guard},
    schema,
    task::AbortTask,
    telemetry::Telemetry,
    wire::{self, WorkerConfig},
};
use std::{collections::HashMap, io, net::Ipv4Addr, os::fd::AsFd, process::Stdio, time::Duration};
use tokio::{net::UnixStream, process::Command, sync::oneshot, time::timeout};
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

pub(crate) struct Session {
    pub(super) resources: std::sync::Arc<tokio::sync::Mutex<super::resources::Resources>>,
    pub prepared: Prepared,
}

pub(crate) struct Prepared {
    pub endpoint: std::net::SocketAddr,
    pub dns: Ipv4Addr,
    pub lan: crate::lan::Plan,
    pub source_policy: Option<Box<nm_tunnel_profile::SourcePolicy>>,
}

impl Session {
    pub async fn stop(self) -> io::Result<()> {
        self.resources.lock().await.stop().await
    }

    pub async fn wait(&mut self) {
        let mut resources = self.resources.lock().await;
        let super::resources::Resources { child, broker, .. } = &mut *resources;
        if let (Some(child), Some(broker)) = (child, broker) {
            tokio::select! { _ = child.wait() => {}, _ = &mut broker.0 => {} }
        }
    }
}

async fn uplink(
    bus: &zbus::Connection,
    bypass: bool,
    source: bool,
) -> io::Result<super::plan::Uplink> {
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
    if !crate::lan::valid_interface(&interface) {
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
        .find(|v| crate::dns::valid_uplink_server(*v))
        .ok_or_else(failure)?;
    let addresses = if bypass {
        let device_ip4: OwnedObjectPath = device
            .get_property("Ip4Config")
            .await
            .map_err(|_| failure())?;
        let device_config = zbus::Proxy::new(
            bus,
            "org.freedesktop.NetworkManager",
            device_ip4,
            "org.freedesktop.NetworkManager.IP4Config",
        )
        .await
        .map_err(|_| failure())?;
        let entries: Vec<HashMap<String, OwnedValue>> = device_config
            .get_property("AddressData")
            .await
            .map_err(|_| failure())?;
        if entries.len() > 16 {
            return Err(failure());
        }
        let mut addresses = entries
            .iter()
            .map(|entry| {
                let address = entry
                    .get("address")
                    .and_then(|v| <&str>::try_from(v).ok())
                    .and_then(|text| text.parse::<Ipv4Addr>().ok())
                    .ok_or_else(failure)?;
                let prefix = entry
                    .get("prefix")
                    .and_then(|v| u32::try_from(v).ok())
                    .and_then(|v| u8::try_from(v).ok())
                    .ok_or_else(failure)?;
                Ok((address, prefix))
            })
            .collect::<io::Result<Vec<_>>>()?;
        if source {
            let routes: Vec<HashMap<String, OwnedValue>> = config
                .get_property("RouteData")
                .await
                .map_err(|_| failure())?;
            if routes.len() > 48 {
                return Err(failure());
            }
            for route in routes {
                let prefix = route
                    .get("prefix")
                    .and_then(|v| u32::try_from(v).ok())
                    .and_then(|p| u8::try_from(p).ok())
                    .ok_or_else(failure)?;
                if prefix == 0 {
                    continue;
                }
                let address = route
                    .get("dest")
                    .and_then(|v| <&str>::try_from(v).ok())
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(failure)?;
                addresses.push((address, prefix));
            }
        }
        addresses
    } else {
        Vec::new()
    };
    Ok(super::plan::Uplink {
        interface,
        dns,
        addresses,
    })
}

fn failure() -> io::Error {
    io::Error::other("No usable NetworkManager uplink/bootstrap DNS.")
}

pub(crate) async fn prepare(
    bus: zbus::Connection,
    mut config: WorkerConfig,
    telemetry: Telemetry,
    resources: &mut super::resources::Resources,
) -> io::Result<Prepared> {
    // Recheck the complete model and cross-policy invariants before privileged
    // resources, not just the worker-provided names in later socket requests.
    let profile = schema::decode(config.name.clone(), &config.data, &config.secrets)
        .map_err(io::Error::other)?;
    let source = matches!(
        profile.routing(),
        nm_tunnel_profile::RoutingPolicy::Complete(_)
    );
    let bypass = profile.lan_bypass() == nm_tunnel_profile::LanBypass::Connected || source;
    let uplink = timeout(Duration::from_secs(5), uplink(&bus, bypass, source))
        .await
        .map_err(|_| failure())??;
    let super::plan::Plan {
        profile,
        interface,
        bootstrap_dns: dns,
        advertised_dns,
        lan,
    } = super::plan::Plan::new(profile, uplink)?;
    // Reserve the public name with a newly created, disabled device before any
    // firewall mutation. A collision must not temporarily authorize another TUN.
    telemetry.stage("tun");
    resources.device = Some(super::tun::create()?);
    eprintln!("Activation stage: TUN created.");
    let fake_ip = profile.network().fake_ip();
    let intercept = profile.network().intercepts_dns();
    let session_policy = profile.network().source().cloned().map(Box::new);
    config.lan = lan.worker_addresses();
    let fake_state = if fake_ip {
        let base = crate::fakeip_boot::state_base(&bus).await.inspect_err(|_| {
            eprintln!("Activation refused: FakeIP state namespace configuration is unavailable or invalid.");
        })?;
        Some(crate::fakeip::open_at(base).await.inspect_err(|_| {
            eprintln!("Activation refused: FakeIP journal cannot be opened safely in the configured namespace; check confinement, storage access and migration requirements. No state reset or fallback was attempted.");
        })?)
    } else {
        None
    };
    eprintln!("Activation stage: uplink selected.");
    let host = profile.node().endpoint().host();
    let port = profile.node().endpoint().port();
    // Independent recovery must be reachable before the first host guard change.
    crate::guard_recovery::arm(&bus).await?;
    telemetry.stage("guard");
    guard::guard_with_lan(&lan, &interface, intercept, &mut resources.guard_writer).await?;
    if fake_ip {
        guard::ensure_owned_fakeip_guard(&mut resources.guard_writer).await?;
    }
    eprintln!("Activation stage: guard installed.");
    telemetry.stage("resolve");
    config.endpoint = bootstrap::resolve(host, port, &interface, dns).await?;
    eprintln!("Activation stage: endpoint resolved.");
    let device = resources.device.as_ref().ok_or_else(failure)?;
    let tun_file: std::fs::File = device.as_fd().try_clone_to_owned()?.into();
    let worker_image = crate::executable::worker_image()?;
    let (parent, child) = std::os::unix::net::UnixStream::pair()?;
    parent.set_nonblocking(true)?;
    let control: std::os::fd::OwnedFd = child.into();
    let (statistics, worker_statistics) = std::os::unix::net::UnixDatagram::pair()?;
    statistics.set_nonblocking(true)?;
    worker_statistics.set_nonblocking(true)?;
    let statistics = tokio::net::UnixDatagram::from_std(statistics)?;
    let worker_statistics: std::os::fd::OwnedFd = worker_statistics.into();
    telemetry.stage("worker");
    resources.child = Some(
        Command::new("/usr/bin/setpriv")
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
            .arg(crate::executable::WORKER_IMAGE)
            .arg("--worker")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::from(worker_image))
            .stdout(Stdio::from(worker_statistics))
            .stderr(Stdio::from(control))
            .kill_on_drop(true)
            .spawn()?,
    );
    // NM's normal capability set omits CAP_SETPCAP, so dropping the inherited
    // bounding ceiling is not permitted. The UID transition clears permitted
    // and effective caps; inheritable/ambient are explicitly empty, and
    // no-new-privs prevents later exec from regaining privilege.
    eprintln!("Activation stage: unprivileged worker spawned.");
    telemetry.stage("readiness");
    let receiver = telemetry.clone();
    resources.telemetry = Some(AbortTask(tokio::spawn(async move {
        receiver.receive(statistics).await
    })));
    let mut stream = UnixStream::from_std(parent)?;
    timeout(
        Duration::from_secs(5),
        wire::send_socket(&stream, &tun_file),
    )
    .await
    .map_err(|_| io::Error::other("Worker TUN grant timeout."))??;
    drop(tun_file);
    wire::send_config(&mut stream, &config).await?;
    let endpoint = config.endpoint;
    drop(config);
    let (ready_tx, ready_rx) = oneshot::channel();
    let authority = super::broker::Authority {
        profile,
        endpoint,
        interface,
        dns,
        lan: lan.clone(),
        fake_state,
        telemetry,
    };
    resources.broker = Some(AbortTask(tokio::spawn(authority.serve(
        stream,
        ready_tx,
        std::sync::Arc::clone(&resources.relays),
    ))));
    if !matches!(timeout(Duration::from_secs(25), ready_rx).await, Ok(Ok(()))) {
        return Err(io::Error::other("Worker readiness timeout."));
    }
    if resources
        .broker
        .as_ref()
        .is_none_or(|broker| broker.0.is_finished())
        || resources
            .child
            .as_mut()
            .ok_or_else(failure)?
            .try_wait()?
            .is_some()
    {
        return Err(io::Error::other("Worker failed before readiness."));
    }
    Ok(Prepared {
        endpoint,
        dns: advertised_dns,
        lan,
        source_policy: session_policy,
    })
}
