use super::*;

#[test]
fn namespace_change_never_discards_a_former_identity_epoch() -> io::Result<()> {
    let directory = Directory::new()?;
    assert!(reject_legacy_namespace(&directory.0).is_ok());
    drop(Store::open(&directory.0)?);
    let before = std::fs::read(directory.journal())?;
    assert!(reject_legacy_namespace(&directory.0).is_err());
    assert_eq!(std::fs::read(directory.journal())?, before);
    let alias = Directory::new()?;
    std::os::unix::fs::symlink(&directory.0, &alias.0)?;
    assert!(reject_legacy_namespace(&alias.0).is_err());
    assert_eq!(std::fs::read(directory.journal())?, before);
    std::fs::remove_file(&alias.0)?;
    Ok(())
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/fakeip-tests");
        std::fs::create_dir_all(&root)?;
        Ok(Self(root.join(uuid::Uuid::new_v4().to_string())))
    }
    fn journal(&self) -> PathBuf {
        self.0.join("identities.jsonl")
    }
    fn reopen(&self) -> io::Result<Store> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match Store::open(&self.0) {
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::yield_now()
                }
                result => return result,
            }
        }
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn identities_survive_reopen_and_exclusive_ownership_without_reassigning_old_addresses()
-> io::Result<()> {
    let directory = Directory::new()?;
    let mut store = Store::open(&directory.0)?;
    let first = store.lookup("First.Example.")?;
    let second = store.lookup("second.example")?;
    assert_ne!(first, second);
    assert!(in_range(first));
    let before = std::fs::read(directory.journal())?;
    assert!(Store::open(&directory.0).is_err());
    assert_eq!(std::fs::read(directory.journal())?, before);
    assert_eq!(store.lookup("first.example")?, first);
    assert_eq!(std::fs::read(directory.journal())?, before);
    assert!(store.reverse(Ipv4Addr::new(198, 18, 0, 3)).is_err());
    drop(store);
    let mut reopened = directory.reopen()?;
    assert_eq!(reopened.reverse(first)?, "first.example");
    assert_eq!(reopened.lookup("second.example")?, second);
    assert_ne!(reopened.lookup("third.example")?, first);
    Ok(())
}

#[test]
fn corrupt_truncated_duplicate_or_missing_journals_reject_without_reset_or_mutation()
-> io::Result<()> {
    for suffix in [
        b"\"first.example\"".as_slice(),
        b"\n".as_slice(),
        b"\"first.example\"\n\"first.example\"\n".as_slice(),
        b"\"https://private-token.example\"\n".as_slice(),
    ] {
        let directory = Directory::new()?;
        drop(Store::open(&directory.0)?);
        let mut bytes = HEADER.to_vec();
        bytes.extend_from_slice(suffix);
        std::fs::write(directory.journal(), &bytes)?;
        let error = Store::open(&directory.0).err().ok_or_else(failure)?;
        assert!(!error.to_string().contains("private-token"));
        assert_eq!(std::fs::read(directory.journal())?, bytes);
    }
    let directory = Directory::new()?;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory.0)?;
    assert!(Store::open(&directory.0).is_err());
    assert!(!directory.journal().exists());
    Ok(())
}

#[test]
fn failed_durable_write_poisoning_does_not_publish_or_reuse_an_identity() -> io::Result<()> {
    let directory = Directory::new()?;
    let mut store = Store::open(&directory.0)?;
    let first = store.lookup("first.example")?;
    let before = std::fs::read(directory.journal())?;
    // Linux's deterministic failing writer; no host files or networking change.
    store.journal = OpenOptions::new().append(true).open("/dev/full")?;
    assert!(store.lookup("never-published.example").is_err());
    assert!(store.lookup("first.example").is_err());
    assert!(store.reverse(first).is_err());
    assert!(store.lookup("another.example").is_err());
    assert_eq!(std::fs::read(directory.journal())?, before);
    drop(store);
    let mut reopened = directory.reopen()?;
    assert_eq!(reopened.reverse(first)?, "first.example");
    assert_ne!(reopened.lookup("another.example")?, first);
    Ok(())
}

#[test]
fn capacity_rejection_preserves_all_published_identities_and_journal() -> io::Result<()> {
    let directory = Directory::new()?;
    drop(Store::open(&directory.0)?);
    let mut file = OpenOptions::new().append(true).open(directory.journal())?;
    for index in 0..MAX_NAMES {
        writeln!(file, "\"entry-{index}.example\"")?;
    }
    file.sync_all()?;
    let before = std::fs::read(directory.journal())?;
    let mut store = Store::open(&directory.0)?;
    let first = store.lookup("entry-0.example")?;
    assert!(store.lookup("exhausted.example").is_err());
    assert_eq!(store.lookup("entry-0.example")?, first);
    assert_eq!(store.reverse(first)?, "entry-0.example");
    assert_eq!(std::fs::read(directory.journal())?, before);
    Ok(())
}

#[test]
fn unsafe_identity_storage_rejects_without_following_links_or_changing_records() -> io::Result<()> {
    use std::os::unix::fs::{PermissionsExt, symlink};

    for directory_mode in [true, false] {
        let directory = Directory::new()?;
        let mut store = Store::open(&directory.0)?;
        store.lookup("owned.example")?;
        drop(store);
        let before = std::fs::read(directory.journal())?;
        let path = if directory_mode {
            directory.0.clone()
        } else {
            directory.journal()
        };
        let mode = if directory_mode { 0o750 } else { 0o640 };
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
        assert!(directory.reopen().is_err());
        assert_eq!(std::fs::metadata(&path)?.mode() & 0o777, mode);
        assert_eq!(std::fs::read(directory.journal())?, before);
    }

    for symbolic in [true, false] {
        let directory = Directory::new()?;
        drop(Store::open(&directory.0)?);
        let original = directory.0.join("original.jsonl");
        std::fs::rename(directory.journal(), &original)?;
        let before = std::fs::read(&original)?;
        if symbolic {
            symlink(&original, directory.journal())?;
        } else {
            std::fs::hard_link(&original, directory.journal())?;
        }
        assert!(directory.reopen().is_err());
        assert_eq!(std::fs::read(&original)?, before);
        assert_eq!(std::fs::read(directory.journal())?, before);
        assert_eq!(
            std::fs::symlink_metadata(directory.journal())?.is_symlink(),
            symbolic
        );
    }

    let original = Directory::new()?;
    drop(Store::open(&original.0)?);
    let alias = Directory::new()?;
    symlink(&original.0, &alias.0)?;
    let before = std::fs::read(original.journal())?;
    assert!(Store::open(&alias.0).is_err());
    assert!(std::fs::symlink_metadata(&alias.0)?.is_symlink());
    assert_eq!(std::fs::read(original.journal())?, before);
    // Remove only the test-created symlink, not its target.
    std::fs::remove_file(&alias.0)?;
    Ok(())
}

#[tokio::test]
async fn unsafe_state_ancestors_reject_before_creating_an_identity_directory() -> io::Result<()> {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let parent = Directory::new()?;
    std::fs::DirBuilder::new().mode(0o700).create(&parent.0)?;
    let writable = parent.0.join("writable");
    std::fs::create_dir(&writable)?;
    std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777))?;
    let rejected = writable.join("new-state");
    assert!(open_at(rejected.clone()).await.is_err());
    assert!(!rejected.exists());

    let alias = parent.0.join("alias");
    let trusted = parent.0.join("trusted");
    std::fs::create_dir(&trusted)?;
    symlink(&trusted, &alias)?;
    assert!(open_at(alias.join("new-state")).await.is_err());
    assert!(!trusted.join("new-state").exists());
    assert!(std::fs::symlink_metadata(&alias)?.is_symlink());
    Ok(())
}

#[tokio::test]
async fn read_only_state_namespace_fails_without_creating_or_resetting_identities() -> io::Result<()>
{
    use std::os::unix::fs::PermissionsExt;
    let parent = Directory::new()?;
    std::fs::DirBuilder::new().mode(0o700).create(&parent.0)?;
    let home = parent.0.join("read-only-home");
    std::fs::DirBuilder::new().mode(0o500).create(&home)?;
    let base = home.join("state");
    let result = open_at(base.clone()).await;
    // Restore only our fixture permissions so its owner can clean it up.
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))?;
    assert!(result.is_err());
    assert!(!base.exists());
    let writable = parent.0.join("service-state");
    let state = open_at(writable.clone()).await?;
    assert!(
        writable
            .join("network-manager-tunnel-fakeip-v1/identities.jsonl")
            .is_file()
    );
    drop(state);
    assert!(!base.exists());
    Ok(())
}

#[tokio::test]
async fn dns_answers_are_backed_by_durable_identity_and_ipv6_is_explicitly_unavailable()
-> io::Result<()> {
    let directory = Directory::new()?;
    let state = Arc::new(Mutex::new(Store::open(&directory.0)?));
    let (id, query) = crate::dns::query("first.example")?;
    let response = dns(Arc::clone(&state), query).await?;
    let addresses = crate::dns::dns_answer(id, &response)?;
    assert_eq!(addresses.len(), 1);
    assert_eq!(
        reverse(Arc::clone(&state), addresses[0]).await?,
        b"first.example"
    );
    let (_, mut query) = crate::dns::query("first.example")?;
    let mut parsed = hickory_proto::op::Message::from_vec(&query).map_err(|_| failure())?;
    parsed.queries[0].set_query_type(hickory_proto::rr::RecordType::AAAA);
    query = parsed.to_vec().map_err(|_| failure())?;
    let response = dns(state, query).await?;
    assert!(
        hickory_proto::op::Message::from_vec(&response)
            .map_err(|_| failure())?
            .answers
            .is_empty()
    );
    Ok(())
}
