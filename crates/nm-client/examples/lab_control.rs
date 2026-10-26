//! Explicit synthetic NM client lifecycle probe, restricted to the disposable VM.
use nm_tunnel_client::{ConnectionState, activate, deactivate, save_profile, snapshot};
use nm_tunnel_profile::{Draft, Security};
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

const NAME: &str = "NMT client contract";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !std::path::Path::new("/run/nmt-lab-authorized").is_file() {
        return Err("Explicit lab VM authorization is required.".into());
    }
    let virt = timeout(
        Duration::from_secs(3),
        tokio::process::Command::new("systemd-detect-virt")
            .arg("--vm")
            .output(),
    )
    .await??;
    if !virt.status.success() {
        return Err("This probe requires a disposable VM, never the host.".into());
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["inspect"] {
        let observed = snapshot().await?;
        println!(
            "PASS: read-only NM observation: {} profile(s), {} active connection(s).",
            observed.profiles.len(),
            observed.active.len()
        );
        return Ok(());
    }
    if args == ["disconnect"] {
        let observed = snapshot().await?;
        let active: Vec<_> = observed
            .active
            .into_iter()
            .filter(|a| a.profile().name() == NAME)
            .collect();
        let [active] = active.as_slice() else {
            return Err("Expected exactly one synthetic active profile.".into());
        };
        println!("Observed the existing active profile; requesting explicit deactivation.");
        deactivate(active).await?;
        println!("Deactivation accepted; waiting for a stable read-only NM observation.");
        timeout(Duration::from_secs(10), async {
            loop {
                match snapshot().await {
                    Ok(observed) if observed.active.iter().all(|a| a.profile().name() != NAME) => {
                        return Ok::<(), nm_tunnel_client::ClientError>(());
                    }
                    // NM can remove an active object between ListConnections
                    // and property reads. Retry only this read, never control.
                    Err(nm_tunnel_client::ClientError::Stale) | Ok(_) => {}
                    Err(error) => return Err(error),
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await??;
        println!("PASS: a new client process observed and deactivated the existing NM connection.");
        return Ok(());
    }
    let [endpoint] = args.as_slice() else {
        return Err("Expected VM_UPLINK_IPV4 (saves profile and credentials to disk), inspect, or disconnect.".into());
    };
    let endpoint: Ipv4Addr = endpoint.parse()?;
    if endpoint.is_unspecified() || endpoint.is_multicast() || endpoint.is_loopback() {
        return Err("Expected VM uplink IPv4.".into());
    }
    let before = snapshot().await?;
    if !before.backend_registered
        || !before.active.is_empty()
        || before.profiles.iter().any(|p| p.name() == NAME)
    {
        return Err(
            "Need registered backend, no active VPN and no pre-existing synthetic profile.".into(),
        );
    }
    let profile = Draft {
        name: NAME.into(),
        server: endpoint.to_string(),
        port: "24444".into(),
        credential: "12345678-1234-4234-8234-123456789abc".to_owned().into(),
        security: Security::Reality,
        server_name: "peer.example".into(),
        public_key: "8y8p8aO5lpROX8wIDsOzzLt13iQ-2DXZmTuqXjy0om0".into(),
        short_id: "abababababababab".into(),
        vision: false,
        ..Default::default()
    }
    .validate()
    .map_err(|_| "Invalid synthetic profile.")?;
    println!(
        "Saving the synthetic profile and credentials on disk in NetworkManager; autoconnect is off."
    );
    let saved = save_profile(profile).await?;
    let observed = snapshot().await?;
    if !observed
        .profiles
        .iter()
        .any(|p| p.id() == saved.id() && p.persistent())
    {
        return Err("NM did not report the requested profile storage.".into());
    }
    println!("PASS: explicit save and NM storage observation; no secret retrieval.");
    activate(&saved).await?;
    timeout(Duration::from_secs(30), async {
        loop {
            if snapshot()
                .await?
                .active
                .iter()
                .any(|a| a.profile().id() == saved.id() && a.state() == ConnectionState::Connected)
            {
                return Ok::<(), nm_tunnel_client::ClientError>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    println!("PASS: NM reports Connected after explicit client activation.");
    timeout(Duration::from_secs(5), async {
        let mut stream =
            tokio::net::TcpStream::connect(SocketAddr::from(([198, 51, 100, 10], 12345))).await?;
        let payload: Vec<u8> = (0..65549).map(|i| (i % 251) as u8).collect();
        stream.write_all(&payload).await?;
        let mut response = vec![0; payload.len()];
        stream.read_exact(&mut response).await?;
        if response != payload {
            return Err(std::io::Error::other("Synthetic payload mismatch."));
        }
        Ok::<(), std::io::Error>(())
    })
    .await??;
    println!("PASS: actual TUN TCP echo; exiting the client deliberately leaves NM in control.");
    Ok(())
}
