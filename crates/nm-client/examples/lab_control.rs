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
    if args == ["storage"] {
        return storage_contract().await;
    }
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
        public_key: std::env::var("NM_TUNNEL_LAB_PUBLIC_KEY")
            .unwrap_or_else(|_| "8y8p8aO5lpROX8wIDsOzzLt13iQ-2DXZmTuqXjy0om0".into()),
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
            match snapshot().await {
                Ok(observed)
                    if observed.active.iter().any(|a| {
                        a.profile().id() == saved.id() && a.state() == ConnectionState::Connected
                    }) =>
                {
                    return Ok::<(), nm_tunnel_client::ClientError>(());
                }
                // TUN creation/rename can change NM's object list during this
                // read. Retry only observation under the existing deadline;
                // never repeat save or activation after an accepted request.
                Err(nm_tunnel_client::ClientError::Stale) | Ok(_) => {}
                Err(error) => return Err(error),
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

/// Exercise real NM persistence and version checks without activating any tunnel.
async fn storage_contract() -> Result<(), Box<dyn std::error::Error>> {
    use nm_tunnel_client::{
        ClientError, LanBypass, ProfileChanges, delete_profile, edit_profile, update_from_source,
    };
    use nm_tunnel_profile::DnsOverride;
    const STORAGE_NAME: &str = "NMT storage contract";
    let before = snapshot().await?;
    if before
        .profiles
        .iter()
        .any(|profile| profile.name() == STORAGE_NAME)
    {
        return Err("Refusing to overwrite a pre-existing lab profile.".into());
    }
    let draft = || Draft {
        name: STORAGE_NAME.into(),
        server: "192.0.2.2".into(),
        port: "24444".into(),
        credential: "12345678-1234-4234-8234-123456789abc".to_owned().into(),
        security: Security::Tls,
        server_name: "peer.example".into(),
        ..Default::default()
    };
    let saved = save_profile(draft().validate().map_err(|_| "Invalid lab profile")?).await?;
    let current = || async { snapshot().await };
    let observed = current().await?;
    let first = observed
        .profiles
        .iter()
        .find(|profile| profile.id() == saved.id())
        .ok_or("Saved profile missing")?;
    if !first.persistent() {
        return Err("NM did not persist the lab profile".into());
    }
    let changes = ProfileChanges {
        name: STORAGE_NAME.into(),
        dns: DnsOverride::ProxyIpv4("9.9.9.9".parse()?),
        lan: LanBypass::None,
        intercept: true,
        fake_ip: false,
    };
    edit_profile(first, changes.clone()).await?;
    if edit_profile(first, changes.clone()).await != Err(ClientError::Stale) {
        return Err("A stale native NM version did not reject".into());
    }
    let observed = current().await?;
    let second = observed
        .profiles
        .iter()
        .find(|profile| profile.id() == saved.id())
        .ok_or("Edited profile missing")?;
    if second.dns_override() != changes.dns || !second.dns_interception() {
        return Err("Native NM edit metadata mismatch".into());
    }
    let mut changed_source = draft();
    changed_source.port = "24449".into();
    update_from_source(
        second,
        changed_source
            .validate()
            .map_err(|_| "Invalid updated lab source")?,
    )
    .await?;
    let observed = current().await?;
    let third = observed
        .profiles
        .iter()
        .find(|profile| profile.id() == saved.id())
        .ok_or("Updated profile missing")?;
    if third.name() != STORAGE_NAME
        || third.dns_override() != changes.dns
        || !third.dns_interception()
    {
        return Err("Source update did not preserve compatible native overrides".into());
    }
    delete_profile(third).await?;
    let after = current().await?;
    if after
        .profiles
        .iter()
        .any(|profile| profile.id() == saved.id())
        || after.active.len() != before.active.len()
        || after.profiles.len() != before.profiles.len()
    {
        return Err("Native storage contract changed unrelated profile/lifecycle state".into());
    }
    println!(
        "PASS: native NM persistent save, narrow edit, stale-version refusal, source override preservation and deletion; no activation or secret retrieval."
    );
    Ok(())
}
