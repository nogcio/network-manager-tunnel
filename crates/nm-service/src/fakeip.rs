//! Root-owned, append-only FakeIP identities. No profile database or cache eviction.
#[cfg(test)]
use nm_tunnel_dataplane::fakeip::MAX_NAMES;
pub(crate) use nm_tunnel_dataplane::fakeip::in_range;
use nm_tunnel_dataplane::fakeip::{HEADER, Identities, MAX_BYTES, failure};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    net::Ipv4Addr,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

pub(crate) type Shared = Arc<Mutex<Store>>;

pub(crate) struct Store {
    identities: Identities,
    journal: File,
    _lock: File,
}

pub(crate) async fn open_at(base: PathBuf) -> io::Result<Shared> {
    if !base.is_absolute() {
        return Err(failure());
    }
    tokio::task::spawn_blocking(move || {
        // The former default lives under ProtectHome=read-only in NM's mount
        // namespace. Never silently start a new identity epoch if it was used.
        if base == Path::new("/var/lib") {
            reject_legacy_namespace(Path::new(
                "/root/.local/state/network-manager-tunnel-fakeip-v1",
            ))?;
        }
        trusted_ancestors(&base)?;
        create_state_base(&base)?;
        Store::open(&base.join("network-manager-tunnel-fakeip-v1"))
            .map(|state| Arc::new(Mutex::new(state)))
    })
    .await
    .map_err(|_| failure())?
}

fn reject_legacy_namespace(legacy: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(legacy) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err(io::Error::other(
            "A former FakeIP identity namespace exists or cannot be inspected; explicit offline migration is required, never reset or fall back.",
        )),
    }
}

impl Store {
    /// A missing journal in an existing identity directory is an error, not a new
    /// allocation epoch. The directory is exclusively locked through every write.
    fn open(directory: &Path) -> io::Result<Self> {
        trusted_ancestors(directory.parent().ok_or_else(failure)?)?;
        let fresh = match std::fs::DirBuilder::new().mode(0o700).create(directory) {
            Ok(()) => true,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
            Err(_) => return Err(failure()),
        };
        let metadata = std::fs::symlink_metadata(directory).map_err(|_| failure())?;
        if !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
        {
            return Err(failure());
        }
        let lock = OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(directory)
            .map_err(|_| failure())?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
            |error| {
                io::Error::new(
                    io::Error::from(error).kind(),
                    "FakeIP identity journal is in use or cannot be locked.",
                )
            },
        )?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .append(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
        if fresh {
            options.create_new(true);
        }
        let mut journal = options
            .open(directory.join("identities.jsonl"))
            .map_err(|_| failure())?;
        let metadata = journal.metadata().map_err(|_| failure())?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
            || metadata.len() > MAX_BYTES
        {
            return Err(failure());
        }
        if fresh {
            journal
                .write_all(HEADER)
                .and_then(|()| journal.sync_all())
                .and_then(|()| lock.sync_all())
                .and_then(|()| {
                    File::open(directory.parent().ok_or_else(failure)?)
                        .and_then(|parent| parent.sync_all())
                })
                .map_err(|_| failure())?;
        }
        let mut bytes = Vec::new();
        journal.seek(SeekFrom::Start(0)).map_err(|_| failure())?;
        (&mut journal)
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| failure())?;
        Ok(Self {
            identities: Identities::restore(&bytes)?,
            journal,
            _lock: lock,
        })
    }

    pub fn lookup(&mut self, name: &str) -> io::Result<Ipv4Addr> {
        let journal = &mut self.journal;
        self.identities.lookup(name, |record| {
            journal.write_all(record).and_then(|()| journal.sync_all())
        })
    }

    pub fn reverse(&self, ip: Ipv4Addr) -> io::Result<String> {
        self.identities.reverse(ip)
    }
}

fn trusted_ancestors(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(failure());
    }
    let uid = rustix::process::geteuid().as_raw();
    for ancestor in path.ancestors() {
        let metadata = match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => return Err(failure()),
        };
        let sticky_root = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        if !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != uid)
            || (metadata.mode() & 0o022 != 0 && !sticky_root)
        {
            return Err(failure());
        }
    }
    Ok(())
}

fn create_state_base(path: &Path) -> io::Result<()> {
    if path.exists() {
        return trusted_ancestors(path);
    }
    let parent = path.parent().ok_or_else(failure)?;
    create_state_base(parent)?;
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {
            File::open(path)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| failure())?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| failure())?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => trusted_ancestors(path),
        Err(_) => Err(failure()),
    }
}

pub(crate) async fn dns(state: Shared, request: Vec<u8>) -> io::Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        nm_tunnel_dataplane::fakeip::answer(&request, |name| {
            state.lock().map_err(|_| failure())?.lookup(name)
        })
    })
    .await
    .map_err(|_| failure())?
}

pub(crate) async fn reverse(state: Shared, ip: Ipv4Addr) -> io::Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        state
            .lock()
            .map_err(|_| failure())?
            .reverse(ip)
            .map(String::into_bytes)
    })
    .await
    .map_err(|_| failure())?
}

#[cfg(test)]
#[path = "fakeip_tests.rs"]
mod tests;
