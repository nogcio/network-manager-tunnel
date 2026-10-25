//! NetworkManager Tunnel VPN plugin and unprivileged packet worker.
mod activation;
mod network;
mod plugin;
mod schema;
mod telemetry;
#[cfg(test)]
mod test_support;
mod wire;
mod worker;

use std::sync::{Arc, atomic::AtomicU32};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--worker"] {
        if worker::run().await.is_err() {
            use std::io::Write;
            let _ = std::io::stderr().write_all(&[
                b'E',
                worker::STAGE.load(std::sync::atomic::Ordering::SeqCst),
            ]);
            std::process::exit(1);
        }
        return;
    }
    if !rustix::process::geteuid().is_root() {
        eprintln!("This backend requires privileged NM activation, never a privileged GUI.");
        std::process::exit(2);
    }
    if args == ["--clear-guard"] {
        if network::guard(false).await.is_err() {
            eprintln!("Guard removal failed.");
            std::process::exit(1);
        }
        return;
    }
    if !args.is_empty() && args != ["--bus-name", nm_tunnel_profile::SERVICE_TYPE] {
        eprintln!("Unsupported backend arguments.");
        std::process::exit(2);
    }
    let result = async {
        let state = Arc::new(AtomicU32::new(1));
        let telemetry = telemetry::Telemetry::default();
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let bus = zbus::Connection::system().await?;
        bus.object_server()
            .at(
                plugin::PATH,
                plugin::Plugin {
                    bus: bus.clone(),
                    state: Arc::clone(&state),
                    requests: tx,
                },
            )
            .await?;
        bus.object_server()
            .at(plugin::PATH, telemetry.clone())
            .await?;
        bus.request_name(nm_tunnel_profile::SERVICE_TYPE).await?;
        eprintln!("NetworkManager Tunnel VPN plugin initialized.");
        plugin::lifecycle(bus, state, rx, telemetry).await
    }
    .await;
    if result.is_err() {
        eprintln!("VPN service failed; inspect NM state and fail-closed guard.");
        std::process::exit(1);
    }
}
