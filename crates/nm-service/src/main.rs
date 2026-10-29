//! NetworkManager Tunnel VPN plugin and unprivileged packet worker.
mod authentication;
mod dns;
mod executable;
mod fakeip;
mod fakeip_boot;
mod guard_recovery;
mod health;
mod lan;
mod lan_relay;
mod lifecycle;
mod network;
mod plugin;
mod schema;
mod source_dns;
mod stream_relay;
mod supervisor;
mod task;
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
        if let Err(error) = worker::run().await {
            use std::io::Write;
            let _ = std::io::stderr().write_all(&[
                b'E',
                worker::STAGE.load(std::sync::atomic::Ordering::SeqCst),
                health::Failure::from_error(&error) as u8,
            ]);
            std::process::exit(1);
        }
        return;
    }
    if !rustix::process::geteuid().is_root() {
        eprintln!("This backend requires privileged NM activation, never a privileged GUI.");
        std::process::exit(2);
    }
    if args == ["--guard-recovery"] {
        if guard_recovery::run().await.is_err() {
            eprintln!("Automatic guard recovery service failed; systemd will restart it.");
            std::process::exit(1);
        }
        return;
    }
    if args == ["--clear-guard"] {
        if network::guard::clear_session_guards().await.is_err() {
            eprintln!("Guard removal failed.");
            std::process::exit(1);
        }
        return;
    }
    if args == ["--clear-fakeip-guard"] {
        eprintln!(
            "Removing reserved FakeIP-range protection. Flush DNS/application caches first; the identity journal is retained."
        );
        if network::guard::clear_fakeip_guard().await.is_err() {
            eprintln!("FakeIP guard removal failed.");
            std::process::exit(1);
        }
        return;
    }
    if args == ["--restore-fakeip-guard"] {
        eprintln!("Restoring the reserved FakeIP-range egress guard.");
        if network::guard::ensure_fakeip_guard().await.is_err() {
            eprintln!("FakeIP guard restoration failed; do not activate persistent FakeIP.");
            std::process::exit(1);
        }
        eprintln!("Reserved FakeIP-range guard restored; normal networking is unchanged.");
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
        lifecycle::run(bus, state, rx, telemetry).await
    }
    .await;
    if result.is_err() {
        eprintln!("VPN service failed; independent automatic guard recovery will continue.");
        std::process::exit(1);
    }
}
