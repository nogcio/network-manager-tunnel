//! Read-only installed-image observation; never a package manager or VPN controller.
use std::{fs, os::unix::fs::MetadataExt};

const INSTALLED: &str = "/usr/bin/nm-tunnel-cosmic";

#[derive(Default)]
pub(super) struct Update {
    running: Option<(u64, u64)>,
    pending: bool,
    pub changed: bool,
    pub notified: bool,
}

impl Update {
    pub fn installed() -> Self {
        let running = std::env::current_exe()
            .ok()
            .filter(|path| path == std::path::Path::new(INSTALLED))
            .and_then(|_| fs::metadata("/proc/self/exe").ok())
            .map(|m| (m.dev(), m.ino()));
        Self {
            running,
            ..Self::default()
        }
    }
    pub fn begin(&mut self) -> Option<(u64, u64)> {
        if self.pending || self.changed {
            return None;
        }
        let running = self.running?;
        self.pending = true;
        Some(running)
    }
    pub fn finish(&mut self, changed: bool) {
        if self.pending {
            self.pending = false;
            self.changed |= changed;
        }
    }
}

pub(super) async fn replaced(running: (u64, u64)) -> bool {
    tokio::task::spawn_blocking(move || {
        fs::metadata(INSTALLED).is_ok_and(|m| (m.dev(), m.ino()) != running)
    })
    .await
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn observations_coalesce_and_never_turn_unknown_into_an_update() {
        let mut unavailable = Update::default();
        assert!(unavailable.begin().is_none());
        unavailable.finish(true);
        assert!(!unavailable.changed);
        let mut update = Update {
            running: Some((1, 2)),
            ..Update::default()
        };
        assert_eq!(update.begin(), Some((1, 2)));
        assert_eq!(update.begin(), None);
        update.finish(false);
        assert!(!update.changed);
        assert_eq!(update.begin(), Some((1, 2)));
        update.finish(true);
        assert!(update.changed);
        assert_eq!(update.begin(), None);
    }
}
