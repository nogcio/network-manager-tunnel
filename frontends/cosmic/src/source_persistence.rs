//! Async vault ownership and explicit source persistence feedback.
use super::super::source_store::{Catalog as StoredCatalog, Error, Record, Store};
use super::*;
use crate::i18n::fl;
use std::sync::Arc;

impl App {
    pub(in super::super) fn source_store_update(&mut self, action: Action) -> Task<Message> {
        match action {
            Action::Restore(unlock)
                if !self.sources.store_loading
                    && self.sources.store_pending.is_none()
                    && self.sources.store.is_none()
                    && self.sources.records.is_empty() =>
            {
                let Some(ticket) = self.sources.store_next.checked_add(1) else {
                    return Task::none();
                };
                self.sources.store_next = ticket;
                self.sources.store_load_ticket = Some(ticket);
                self.sources.store_loading = true;
                return cosmic::task::future(async move {
                    message(Action::Restored(ticket, Store::open(unlock).await))
                });
            }
            Action::Restored(ticket, result)
                if self.sources.store_loading && self.sources.store_load_ticket == Some(ticket) =>
            {
                self.sources.store_load_ticket = None;
                self.sources.store_loading = false;
                match result {
                    Ok((store, catalog)) if self.sources.records.is_empty() => {
                        self.sources.next = catalog.next;
                        self.sources.records = catalog
                            .sources
                            .into_iter()
                            .map(|record| Source {
                                id: SourceId(record.id),
                                name: record.name,
                                url: record.url,
                                format: if record.complete {
                                    SubscriptionFormat::Complete
                                } else {
                                    SubscriptionFormat::NodesOnly
                                },
                                catalog: Catalog::default(),
                                links: record
                                    .links
                                    .into_iter()
                                    .map(|(uuid, label)| (uuid, Link { index: None, label }))
                                    .collect(),
                                updated: None,
                                scroll: Default::default(),
                            })
                            .collect();
                        self.sources.store = Some(store);
                        self.sources.store_error = None;
                        self.sources.dirty = false;
                    }
                    Ok(_) => self.sources.store_error = Some(Error::Busy),
                    Err(error) => self.sources.store_error = Some(error),
                }
            }
            Action::Persist
                if self.sources.store_pending.is_none()
                    && self.sources.store_error != Some(Error::Unknown) =>
            {
                self.sources.store_error = None;
            }
            Action::Persisted(ticket, result) if self.sources.store_pending == Some(ticket) => {
                self.sources.store_pending = None;
                if let Err(error) = result {
                    self.sources.dirty = true;
                    self.sources.store_error = Some(error);
                    if error == Error::Unknown {
                        self.operations.block_uncertain_storage();
                    }
                    self.notice = Some(Notice::Error);
                    self.status = fl!("persistence-failed-status", error = storage_error(error));
                } else {
                    self.sources.store_error = None;
                }
            }
            _ => {}
        }
        Task::none()
    }

    /// The only vault write scheduler. One acknowledged snapshot at a time; definite
    /// failure needs explicit Retry, unknown outcomes block all later storage.
    pub(in super::super) fn persist_sources(&mut self) -> Task<Message> {
        if !self.sources.dirty
            || self.operations.busy()
            || self.operations.uncertain()
            || self.sources.store_pending.is_some()
            || self.sources.store_error.is_some()
        {
            return Task::none();
        }
        let Some(store) = self.sources.store.as_ref().map(Arc::clone) else {
            return Task::none();
        };
        let Some(ticket) = self.sources.store_next.checked_add(1) else {
            return Task::none();
        };
        let catalog = StoredCatalog {
            version: 1,
            next: self.sources.next,
            sources: self
                .sources
                .records
                .iter()
                .map(|source| Record {
                    id: source.id.0,
                    name: source.name.clone(),
                    url: source.url.clone(),
                    complete: source.format == SubscriptionFormat::Complete,
                    links: source
                        .links
                        .iter()
                        .map(|(uuid, link)| (uuid.clone(), link.label.clone()))
                        .collect(),
                })
                .collect(),
        };
        self.sources.store_next = ticket;
        self.sources.store_pending = Some(ticket);
        self.sources.dirty = false;
        cosmic::task::future(async move {
            message(Action::Persisted(ticket, store.save(catalog).await))
        })
    }

    pub(in super::super) fn source_storage_view(&self) -> Option<Element<'_, Message>> {
        if self.sources.store_loading {
            return Some(widget::text::caption(fl!("restoring-subscriptions")).into());
        }
        if self.sources.store_error.is_none() && self.sources.store_pending.is_none() {
            return None;
        }
        let mut content = widget::column::with_capacity(2).spacing(theme::spacing().space_s);
        if let Some(error) = self.sources.store_error {
            content = content.push(widget::text::body(storage_error(error)));
            if error != Error::Unknown
                && self.sources.store.is_none()
                && self.sources.records.is_empty()
            {
                content = content.push(
                    widget::button::standard(fl!("restore-subscriptions"))
                        .on_press(message(Action::Restore(true))),
                );
            } else if error != Error::Unknown && self.sources.store.is_some() {
                content = content.push(
                    widget::button::standard(fl!("retry-subscription-save"))
                        .on_press(message(Action::Persist)),
                );
            }
        } else if self.sources.store_pending.is_some() {
            content = content.push(widget::text::caption(fl!("saving-subscriptions")));
        }
        Some(content.into())
    }

    pub(in super::super) fn source_storage_caption(&self) -> String {
        if self.sources.dirty
            || self.sources.store_pending.is_some()
            || self.sources.store_error.is_some()
        {
            fl!("storage-unconfirmed-caption")
        } else if self.sources.store.is_some() || self.synthetic_preview() {
            fl!("storage-keyring-caption")
        } else {
            fl!("storage-session-caption")
        }
    }
}

fn storage_error(error: Error) -> String {
    match error {
        Error::Unavailable => fl!("storage-unavailable"),
        Error::Locked => fl!("storage-locked"),
        Error::Invalid => fl!("storage-invalid"),
        Error::Busy => fl!("storage-busy"),
        Error::Unknown => fl!("storage-unknown"),
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::Flags;
    use super::*;
    use cosmic::{Application, Core};

    #[test]
    fn stale_restore_and_write_completions_cannot_install_data_or_release_a_newer_write() {
        let (mut app, _) = App::init(Core::default(), Flags::default());
        let _ = app.update(message(Action::Restore(false)));
        let ticket = app
            .sources
            .store_load_ticket
            .unwrap_or_else(|| panic!("Missing restore ticket"));
        let _ = app.update(message(Action::Restored(
            ticket + 1,
            Err(Error::Unavailable),
        )));
        assert!(app.sources.store_loading);
        let _ = app.update(message(Action::Restored(ticket, Err(Error::Locked))));
        assert!(!app.sources.store_loading && app.sources.store_error == Some(Error::Locked));
        app.sources.store_pending = Some(50);
        let _ = app.update(message(Action::Persisted(49, Err(Error::Unknown))));
        assert_eq!(app.sources.store_pending, Some(50));
        assert!(!app.operations.uncertain());
        let _ = app.update(message(Action::Persisted(50, Err(Error::Unknown))));
        assert!(app.sources.store_pending.is_none() && app.sources.dirty);
        assert!(app.operations.uncertain());
        let _ = app.update(message(Action::Persist));
        assert_eq!(app.sources.store_error, Some(Error::Unknown));
        assert!(app.sources.records.is_empty());
    }

    #[test]
    fn restored_sources_contain_no_nodes_and_do_not_dispatch_http_nm_or_automatic_activation()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut app, _) = App::init(Core::default(), Flags::default());
        let path = std::env::current_dir()?
            .join("target/source-store-tests")
            .join(uuid::Uuid::new_v4().to_string());
        let store = Store::test_store(&path).map_err(|error| error.to_string())?;
        let _ = app.update(message(Action::Restore(false)));
        let ticket = app.sources.store_load_ticket.ok_or("Restore ticket")?;
        let catalog = StoredCatalog {
            version: 1,
            next: 4,
            sources: vec![Record {
                id: 4,
                name: "Restored".into(),
                url: "https://subscription.example/synthetic".into(),
                complete: true,
                links: BTreeMap::from([(
                    "12345678-1234-4234-8234-123456789abc".into(),
                    "North".into(),
                )]),
            }],
        };
        let _ = app.update(message(Action::Restored(ticket, Ok((store, catalog)))));
        let _ = app.update(message(Action::Open(SourceId(4))));
        assert!(app.sources.store.is_some() && !app.sources.dirty);
        assert_eq!(app.sources.active_name(), Some("Restored"));
        assert!(app.catalog.subscription.is_none() && app.download.pending().is_none());
        assert!(
            app.sources
                .active()
                .is_some_and(|source| source.links.values().all(|link| link.index.is_none()))
        );
        assert!(!app.operations.busy() && app.operations.control().is_none());
        assert!(app.sources.store_pending.is_none());
        Ok(())
    }

    #[test]
    fn confirmed_snapshots_flush_newer_changes_but_failure_requires_an_explicit_retry()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut app, _) = App::init(Core::default(), Flags::default());
        let path = std::env::current_dir()?
            .join("target/source-store-tests")
            .join(uuid::Uuid::new_v4().to_string());
        app.sources.store = Some(Store::test_store(&path).map_err(|error| error.to_string())?);
        app.sources.dirty = true;
        assert!(app.operations.begin_add(0));
        let _ = app.persist_sources();
        assert!(
            app.sources.store_pending.is_none() && app.sources.dirty,
            "source association writes wait for the complete NM mutation/batch"
        );
        assert_eq!(app.operations.finish_add(None), Some(0));
        let _ = app.persist_sources();
        let first = app.sources.store_pending.ok_or("First save")?;
        app.sources.dirty = true;
        let _ = app.update(message(Action::Persisted(first, Ok(()))));
        let second = app.sources.store_pending.ok_or("Newer snapshot")?;
        assert_ne!(first, second);
        let _ = app.update(message(Action::Persisted(first, Err(Error::Unknown))));
        assert_eq!(app.sources.store_pending, Some(second));
        assert!(!app.operations.uncertain());
        let _ = app.update(message(Action::Persisted(second, Err(Error::Unavailable))));
        assert!(app.sources.store_pending.is_none() && app.sources.dirty);
        assert_eq!(app.sources.store_error, Some(Error::Unavailable));
        let _ = app.persist_sources();
        assert!(
            app.sources.store_pending.is_none(),
            "a failed write must not automatically retry"
        );
        let _ = app.update(message(Action::Persist));
        assert!(
            app.sources
                .store_pending
                .is_some_and(|ticket| ticket != second)
        );
        assert!(!app.operations.busy() && app.operations.control().is_none());
        Ok(())
    }
}
