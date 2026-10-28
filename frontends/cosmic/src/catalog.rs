//! Imported-node ownership and admission, independent of widgets and network tasks.
use nm_tunnel_profile::Profile;
use nm_tunnel_subscription::Subscription;
use std::collections::{BTreeMap, HashSet};

#[derive(Default)]
pub(super) struct Catalog {
    pub subscription: Option<Subscription>,
    pub selected: Option<usize>,
    // Only this loaded list's explicit additions; NM remains authoritative.
    pub added: BTreeMap<usize, String>,
    pub page: usize,
    pub search: String,
    pub admitted: bool,
}

impl Catalog {
    pub fn admit(&mut self, subscription: Subscription) {
        self.selected = subscription
            .entries()
            .iter()
            .position(|entry| entry.profile().is_ok());
        self.subscription = Some(subscription);
        self.admitted = true;
        self.added.clear();
        self.page = 0;
    }

    /// Retained nodes remain readable, but cannot authorize saves or replacements.
    pub fn invalidate(&mut self) {
        self.admitted = false;
    }

    pub fn profile(&self, index: usize) -> Option<&Profile> {
        self.admitted.then_some(())?;
        self.subscription
            .as_ref()?
            .entries()
            .get(index)?
            .profile()
            .ok()
    }

    pub fn selected_profile(&self) -> Option<&Profile> {
        self.profile(self.selected?)
    }

    pub fn select(&mut self, index: usize) -> bool {
        if self
            .subscription
            .as_ref()
            .and_then(|list| list.entries().get(index))
            .is_some_and(|entry| entry.profile().is_ok())
        {
            self.selected = Some(index);
            true
        } else {
            false
        }
    }

    pub fn search(&mut self, value: String) {
        self.search = value.chars().take(128).collect();
        self.page = 0;
    }

    pub fn matching(&self) -> Vec<usize> {
        let query = self.search.trim().to_lowercase();
        self.subscription.as_ref().map_or_else(Vec::new, |list| {
            list.entries()
                .iter()
                .enumerate()
                .filter_map(|(index, entry)| {
                    (query.is_empty() || entry.name().to_lowercase().contains(&query))
                        .then_some(index)
                })
                .collect()
        })
    }

    pub fn selected_added(&self) -> bool {
        self.selected
            .is_some_and(|index| self.added.contains_key(&index))
    }

    /// A failed NM read must not call this: it proves no profile was removed.
    pub fn reconcile<'a>(&mut self, profiles: impl Iterator<Item = &'a str>) {
        let ids: HashSet<_> = profiles.collect();
        self.added.retain(|_, id| ids.contains(id.as_str()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalidation_retains_read_only_nodes_but_revokes_all_save_candidates()
    -> Result<(), Box<dyn std::error::Error>> {
        let list = nm_tunnel_subscription::parse_subscription(b"vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example#Synthetic")?;
        let mut catalog = Catalog::default();
        catalog.admit(list);
        assert!(catalog.profile(0).is_some());
        catalog.added.insert(0, "nm-connection-id".into());
        catalog.invalidate();
        assert!(catalog.subscription.is_some());
        assert!(catalog.select(0));
        assert_eq!(catalog.matching(), vec![0]);
        assert!(catalog.profile(0).is_none());
        assert!(catalog.selected_profile().is_none());
        assert_eq!(
            catalog.added.get(&0).map(String::as_str),
            Some("nm-connection-id")
        );
        Ok(())
    }
}
