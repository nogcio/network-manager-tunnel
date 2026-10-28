//! Owner-approved subscription storage, not an NM profile/credential database.
//! One Secret Service secret holds bounded source metadata and URLs over encrypted
//! DH transport; the provider owns at-rest protection and locking.
//! Only a cooperative single-writer lock is stored in XDG state, never a URL.
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::File,
    path::{Component, Path},
    sync::Arc,
    time::Duration,
};

const MAX_BYTES: usize = 1024 * 1024;
const LABEL: &str = "NetworkManager Tunnel subscriptions";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Unavailable,
    Locked,
    Invalid,
    Busy,
    Unknown,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "The desktop keyring could not be reached. Subscriptions are not saved.",
            Self::Locked => "Unlock the desktop keyring to restore subscriptions.",
            Self::Invalid => "Saved subscription data or its storage location is unsupported or unsafe. Nothing was replaced.",
            Self::Busy => "Another Tunnel instance owns subscription storage. No subscription write was requested.",
            Self::Unknown => "Subscription persistence was not confirmed. Do not retry automatically; the write may have completed.",
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub id: u64,
    pub name: String,
    #[serde(serialize_with = "serialize_url", deserialize_with = "deserialize_url")]
    pub url: SecretString,
    pub complete: bool,
    // Independent NM UUID to former source label; no imported node or credential.
    pub links: BTreeMap<String, String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Catalog {
    pub version: u8,
    pub next: u64,
    pub sources: Vec<Record>,
}
impl Default for Catalog {
    fn default() -> Self {
        Self {
            version: 1,
            next: 0,
            sources: Vec::new(),
        }
    }
}
impl std::fmt::Debug for Catalog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoredSubscriptions([redacted])")
    }
}
fn serialize_url<S: serde::Serializer>(
    url: &SecretString,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(url.expose_secret())
}
fn deserialize_url<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<SecretString, D::Error> {
    String::deserialize(deserializer).map(Into::into)
}

impl Catalog {
    fn validate(&self) -> Result<(), Error> {
        if self.version != 1 || self.sources.len() > 128 {
            return Err(Error::Invalid);
        }
        let mut ids = HashSet::new();
        let mut profiles = HashSet::new();
        for source in &self.sources {
            if source.id == 0
                || source.id > self.next
                || !ids.insert(source.id)
                || source.name.trim().is_empty()
                || source.name.len() > 128
                || source.name.chars().any(char::is_control)
                || nm_tunnel_subscription::validate_url(source.url.expose_secret()).is_err()
                || source.links.len() > 4096
            {
                return Err(Error::Invalid);
            }
            for (uuid, label) in &source.links {
                if profiles.len() >= 4096 {
                    return Err(Error::Invalid);
                }
                if uuid::Uuid::parse_str(uuid).is_err()
                    || !profiles.insert(uuid)
                    || label.len() > 128
                    || label.chars().any(char::is_control)
                {
                    return Err(Error::Invalid);
                }
            }
        }
        Ok(())
    }
    fn encode(&self) -> Result<SecretSlice<u8>, Error> {
        self.validate()?;
        let bytes: SecretSlice<u8> = serde_json::to_vec(self).map_err(|_| Error::Invalid)?.into();
        if bytes.expose_secret().len() > MAX_BYTES {
            return Err(Error::Invalid);
        }
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_BYTES {
            return Err(Error::Invalid);
        }
        let catalog: Self = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
        catalog.validate()?;
        Ok(catalog)
    }
}

/// Held until app exit, including after unknown writes. No lock stealing/deletion.
pub(crate) struct Store {
    _lock: File,
}
impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SourceStore([redacted])")
    }
}

fn attributes() -> HashMap<&'static str, &'static str> {
    HashMap::from([
        ("application", "io.github.networkmanager.Tunnel"),
        ("kind", "subscription-catalog-v1"),
    ])
}
fn read_error(error: secret_service::Error) -> Error {
    match error {
        secret_service::Error::Locked | secret_service::Error::Prompt => Error::Locked,
        _ => Error::Unavailable,
    }
}

impl Store {
    #[cfg(test)]
    pub(super) fn test_store(path: &Path) -> Result<Arc<Self>, Error> {
        Ok(Arc::new(Self { _lock: lock(path)? }))
    }
    pub(super) async fn open(unlock: bool) -> Result<(Arc<Self>, Catalog), Error> {
        let base = std::env::var_os("XDG_STATE_HOME")
            .filter(|value| !value.is_empty())
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(|home| std::path::PathBuf::from(home).join(".local/state"))
            })
            .ok_or(Error::Invalid)?;
        let store = Arc::new(Self {
            _lock: lock(&base.join("network-manager-tunnel"))?,
        });
        let catalog = store.load(unlock).await?;
        Ok((store, catalog))
    }
    async fn load(&self, unlock: bool) -> Result<Catalog, Error> {
        tokio::time::timeout(Duration::from_secs(30), async {
            let service =
                secret_service::SecretService::connect(secret_service::EncryptionType::Dh)
                    .await
                    .map_err(read_error)?;
            let result = service
                .search_items(attributes())
                .await
                .map_err(read_error)?;
            if result.locked.len() + result.unlocked.len() > 1 {
                return Err(Error::Invalid);
            }
            let Some(item) = result.unlocked.first().or_else(|| result.locked.first()) else {
                return Ok(Catalog::default());
            };
            if !result.locked.is_empty() {
                if !unlock {
                    return Err(Error::Locked);
                }
                item.unlock().await.map_err(read_error)?;
            }
            let bytes: SecretSlice<u8> = item.get_secret().await.map_err(read_error)?.into();
            Catalog::decode(bytes.expose_secret())
        })
        .await
        .map_err(|_| Error::Unavailable)?
    }
    /// One replacement dispatch. After dispatch any unproven outcome is unknown;
    /// cancellation/deadline never authorizes an automatic retry or rollback.
    pub(super) async fn save(&self, catalog: Catalog) -> Result<(), Error> {
        let bytes = catalog.encode()?;
        tokio::time::timeout(Duration::from_secs(30), async {
            let service =
                secret_service::SecretService::connect(secret_service::EncryptionType::Dh)
                    .await
                    .map_err(read_error)?;
            let collection = service.get_default_collection().await.map_err(read_error)?;
            collection.unlock().await.map_err(read_error)?;
            collection.ensure_unlocked().await.map_err(read_error)?;
            collection
                .create_item(
                    LABEL,
                    attributes(),
                    bytes.expose_secret(),
                    true,
                    "application/json",
                )
                .await
                .map_err(|_| Error::Unknown)?;
            Ok(())
        })
        .await
        .map_err(|_| Error::Unknown)?
    }
}

fn lock(path: &Path) -> Result<File, Error> {
    use rustix::fs::{FileType, Mode, OFlags, fstat, mkdirat, open, openat};
    let uid = rustix::process::geteuid().as_raw();
    if !path.is_absolute() {
        return Err(Error::Invalid);
    }
    let mut directory = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::Invalid)?;
    for component in path.components() {
        let Component::Normal(name) = component else {
            if component == Component::RootDir {
                continue;
            }
            return Err(Error::Invalid);
        };
        match mkdirat(&directory, name, Mode::from_raw_mode(0o700)) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(_) => return Err(Error::Invalid),
        }
        directory = openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::Invalid)?;
        let stat = fstat(&directory).map_err(|_| Error::Invalid)?;
        if stat.st_uid != 0 && stat.st_uid != uid {
            return Err(Error::Invalid);
        }
        if stat.st_mode & 0o022 != 0 && !(stat.st_uid == 0 && stat.st_mode & 0o1000 != 0) {
            return Err(Error::Invalid);
        }
    }
    let stat = fstat(&directory).map_err(|_| Error::Invalid)?;
    if stat.st_uid != uid || stat.st_mode & 0o077 != 0 {
        return Err(Error::Invalid);
    }
    let fd = openat(
        &directory,
        "sources.lock",
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| Error::Invalid)?;
    let stat = fstat(&fd).map_err(|_| Error::Invalid)?;
    if stat.st_uid != uid
        || stat.st_mode & 0o077 != 0
        || stat.st_nlink != 1
        || FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
    {
        return Err(Error::Invalid);
    }
    let file = File::from(fd);
    file.try_lock().map_err(|_| Error::Busy)?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn root() -> std::path::PathBuf {
        std::env::current_dir()
            .unwrap_or_else(|error| panic!("Test root unavailable: {error}"))
            .join("target/source-store-tests")
            .join(uuid::Uuid::new_v4().to_string())
    }
    fn catalog() -> Catalog {
        Catalog {
            version: 1,
            next: 7,
            sources: vec![Record {
                id: 7,
                name: "Synthetic".into(),
                url: "https://subscription.example/synthetic-token".into(),
                complete: true,
                links: BTreeMap::from([(
                    "12345678-1234-4234-8234-123456789abc".into(),
                    "North".into(),
                )]),
            }],
        }
    }

    #[test]
    fn encrypted_payload_codec_is_versioned_bounded_and_never_debugs_urls() {
        let source = catalog();
        let bytes = source
            .encode()
            .unwrap_or_else(|error| panic!("Synthetic encoding: {error}"));
        let restored = Catalog::decode(bytes.expose_secret())
            .unwrap_or_else(|error| panic!("Synthetic decoding: {error}"));
        assert_eq!(
            restored.sources[0].url.expose_secret(),
            source.sources[0].url.expose_secret()
        );
        assert_eq!(restored.sources[0].links, source.sources[0].links);
        assert!(!format!("{source:?}").contains("synthetic-token"));
        for bytes in [
            br#"{"version":2,"next":0,"sources":[]}"#.as_slice(),
            br#"{"version":1,"next":0,"sources":[],"url":"hidden"}"#.as_slice(),
            br#"{"version":1,"version":1,"next":0,"sources":[]}"#.as_slice(),
        ] {
            assert_eq!(Catalog::decode(bytes).err(), Some(Error::Invalid));
        }
        let before = bytes.expose_secret().to_vec();
        assert_eq!(
            Catalog::decode(&vec![b'x'; MAX_BYTES + 1]).err(),
            Some(Error::Invalid)
        );
        assert_eq!(bytes.expose_secret(), before);
        let mut duplicated = catalog();
        duplicated.sources.push(duplicated.sources[0].clone());
        assert_eq!(duplicated.encode().err(), Some(Error::Invalid));
        let mut invalid = catalog();
        invalid.sources[0].url = "http://invalid.example/synthetic".into();
        assert_eq!(invalid.encode().err(), Some(Error::Invalid));
    }

    #[test]
    fn lock_is_exclusive_private_and_rejects_links_or_unsafe_modes_without_truncation()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = root();
        let first = Store::test_store(&path).map_err(|error| error.to_string())?;
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(path.join("sources.lock"))?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(lock(&path).err(), Some(Error::Busy));
        drop(first);
        drop(lock(&path).map_err(|error| error.to_string())?);
        let linked = root();
        symlink(&path, &linked)?;
        assert_eq!(lock(&linked).err(), Some(Error::Invalid));
        let victim = path.join("unrelated");
        std::fs::write(&victim, b"unchanged")?;
        std::fs::remove_file(path.join("sources.lock"))?;
        symlink(&victim, path.join("sources.lock"))?;
        assert_eq!(lock(&path).err(), Some(Error::Invalid));
        assert_eq!(std::fs::read(&victim)?, b"unchanged");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
        assert_eq!(lock(&path).err(), Some(Error::Invalid));
        assert_eq!(std::fs::read(&victim)?, b"unchanged");
        Ok(())
    }
}
