//! Package replacement never authorizes mixed-image worker execution or live restart.
use std::{
    fs::{self, File},
    io,
    os::unix::fs::MetadataExt,
    path::PathBuf,
};

/// Identity of this process at startup. Missing/replaced installed files retire
/// only an idle backend, never an active session or unconfirmed cleanup.
pub(crate) struct Image {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Image {
    pub fn capture() -> io::Result<Self> {
        let metadata = fs::metadata("/proc/self/exe")?;
        Ok(Self {
            path: std::env::current_exe()?,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    pub fn replaced(&self) -> bool {
        fs::metadata(&self.path).map_or(true, |m| m.dev() != self.device || m.ino() != self.inode)
    }
}

/// Open the running image, not its replaceable pathname. Stdio duplicates this
/// close-on-exec file to fd 0 for setpriv; `/proc/self/fd/0` then refers to exactly
/// this image after the UID transition. No globally inheritable extra fd is made.
pub(crate) fn worker_image() -> io::Result<File> {
    File::open("/proc/self/exe")
}

pub(crate) const WORKER_IMAGE: &str = "/proc/self/fd/0";

#[cfg(test)]
mod tests {
    use super::*;
    use std::{process::Stdio, time::Duration};

    #[tokio::test]
    async fn replaced_path_does_not_change_the_image_executed_through_setpriv() -> io::Result<()> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/executable-tests")
            .join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&root)?;
        let path = root.join("backend");
        fs::copy("/usr/bin/true", &path)?;
        let file = File::open(&path)?;
        let metadata = file.metadata()?;
        let image = Image {
            path: path.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        assert!(!image.replaced());
        let replacement = root.join("replacement");
        fs::copy("/usr/bin/false", &replacement)?;
        fs::rename(replacement, &path)?;
        assert!(image.replaced());
        let mut child = tokio::process::Command::new("/usr/bin/setpriv")
            .args(["--no-new-privs", "--", WORKER_IMAGE])
            .stdin(Stdio::from(file))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        assert!(
            tokio::time::timeout(Duration::from_secs(5), child.wait())
                .await
                .map_err(|_| io::Error::other("Pinned image test deadline."))??
                .success()
        );
        fs::remove_file(&path)?;
        assert!(image.replaced());
        fs::remove_dir(root)?;
        Ok(())
    }
}
