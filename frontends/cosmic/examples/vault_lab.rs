//! Explicit synthetic integration probe. Requires a private bus and temporary HOME.
//! Never run this against the desktop's real keyring or session bus.
#![cfg(not(test))]
#[path = "../src/source_store.rs"]
mod source_store;

use secrecy::ExposeSecret;
use source_store::{Catalog, Record, Store};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let home = std::path::PathBuf::from(std::env::var_os("HOME").ok_or("Missing isolated HOME")?)
        .canonicalize()?;
    let allowed = std::env::current_dir()?
        .join("target/vault-lab")
        .canonicalize()?;
    let parent = home.parent().ok_or("Invalid isolated HOME")?;
    let address = format!("unix:path={}", parent.join("bus").display());
    if std::env::var("NM_TUNNEL_ISOLATED_VAULT").as_deref() != Ok("1")
        || !home.starts_with(allowed)
        || std::env::var("DBUS_SESSION_BUS_ADDRESS").as_deref() != Ok(address.as_str())
    {
        return Err("Refusing non-isolated keyring probe".into());
    }
    println!("Vault probe: opening isolated storage");
    let (store, existing) = Store::open(false)
        .await
        .map_err(|error| error.to_string())?;
    if !existing.sources.is_empty() {
        return Err("Isolated vault must start empty".into());
    }
    let fixture = Catalog {
        version: 1,
        next: 1,
        sources: vec![Record {
            id: 1,
            name: "Synthetic".into(),
            url: "https://subscription.example/synthetic-lab-token".into(),
            complete: true,
            links: std::collections::BTreeMap::from([(
                "12345678-1234-4234-8234-123456789abc".into(),
                "North".into(),
            )]),
        }],
    };
    store
        .save(fixture)
        .await
        .map_err(|error| error.to_string())?;
    drop(store);
    println!("Vault probe: checking reopen and source associations");
    let (store, mut restored) = Store::open(false)
        .await
        .map_err(|error| error.to_string())?;
    if restored.sources.len() != 1
        || restored.sources[0].url.expose_secret()
            != "https://subscription.example/synthetic-lab-token"
        || restored.sources[0].links.len() != 1
        || restored.next != 1
    {
        return Err("Isolated source roundtrip failed".into());
    }
    restored.sources.clear();
    store
        .save(restored)
        .await
        .map_err(|error| error.to_string())?;
    drop(store);
    let (store, restored) = Store::open(false)
        .await
        .map_err(|error| error.to_string())?;
    if !restored.sources.is_empty() {
        return Err("Removed source survived the confirmed catalog replacement".into());
    }
    drop(restored);
    drop(store);
    let service =
        secret_service::SecretService::connect(secret_service::EncryptionType::Dh).await?;
    service.get_default_collection().await?.lock().await?;
    if Store::open(false).await.err() != Some(source_store::Error::Locked) {
        return Err("Locked keyring read did not reject without prompting".into());
    }
    println!(
        "PASS isolated Secret Service save, reopen, associations, removal and locked read; no HTTP or NetworkManager requests"
    );
    Ok(())
}
