//! Subscription navigation/admission/identity tests without HTTP or host NM.
use super::super::Flags;
use super::*;
use cosmic::{Application, Core};

const A: &str = "vless://12345678-1234-4234-8234-123456789abc@a.example:443?security=tls&sni=peer.example#Duplicate";
const B: &str = "vless://12345678-1234-4234-8234-123456789abd@b.example:443?security=tls&sni=peer.example#Duplicate";

#[test]
fn source_write_progress_is_target_bound_and_retains_only_confirmed_steps_on_failure() -> TestResult
{
    let mut operations = super::super::operations::Operations::default();
    let ticket = operations.begin_storage().ok_or("Storage ticket")?;
    let mut completed = BTreeMap::new();
    let mut pending = Some((ticket, "first".to_owned()));
    assert!(complete_step(
        &mut pending,
        &mut completed,
        ticket,
        "first",
        3,
        &Ok(())
    ));
    assert_eq!(completed.get("first"), Some(&3));
    pending = Some((ticket, "second".to_owned()));
    assert!(
        !complete_step(&mut pending, &mut completed, ticket, "first", 3, &Ok(())),
        "a duplicate first reply cannot finish the second write"
    );
    assert!(pending.as_ref().is_some_and(|(_, id)| id == "second"));
    assert!(complete_step(
        &mut pending,
        &mut completed,
        ticket,
        "second",
        4,
        &Err(ClientError::Rejected)
    ));
    assert!(pending.is_none());
    assert_eq!(completed.len(), 1);
    assert!(!completed.contains_key("second"));
    assert!(operations.finish_storage(ticket, Some(ClientError::Rejected)));
    assert!(!operations.uncertain());
    let ticket = operations.begin_storage().ok_or("New explicit ticket")?;
    pending = Some((ticket, "second".to_owned()));
    assert!(complete_step(
        &mut pending,
        &mut completed,
        ticket,
        "second",
        4,
        &Err(ClientError::Timeout)
    ));
    assert_eq!(
        completed.len(),
        1,
        "unknown outcomes cannot be counted as confirmed or rolled back"
    );
    assert!(operations.finish_storage(ticket, Some(ClientError::Timeout)));
    assert!(operations.uncertain());
    assert!(operations.begin_storage().is_none());
    Ok(())
}

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn nested_scroll_positions_belong_to_each_source_not_the_current_primary_page() -> TestResult {
    use cosmic::iced::widget::scrollable::AbsoluteOffset;
    let (mut app, _) = App::init(Core::default(), Flags::default());
    let first = add(&mut app, "First", A)?;
    let second = add(&mut app, "Second", B)?;
    let _ = app.update(message(Action::Scrolled(
        Some(first),
        Screen::Nodes,
        AbsoluteOffset { x: 0.0, y: 320.0 },
    )));
    assert_eq!(app.sources.active().ok_or("Second source")?.scroll.y, 0.0);
    let _ = app.update(message(Action::Scrolled(
        Some(second),
        Screen::Nodes,
        AbsoluteOffset { x: 0.0, y: 640.0 },
    )));
    let _ = app.update(message(Action::Scrolled(
        Some(second),
        Screen::List,
        AbsoluteOffset { x: 0.0, y: 100.0 },
    )));
    let _ = app.update(message(Action::Open(first)));
    assert_eq!(app.sources.active().ok_or("First source")?.scroll.y, 320.0);
    assert_eq!(app.sources.list_scroll.y, 100.0);
    let _ = app.update(message(Action::Open(second)));
    assert_eq!(app.sources.active().ok_or("Second source")?.scroll.y, 640.0);
    assert!(!app.operations.busy() && app.operations.control().is_none());
    Ok(())
}

#[test]
fn a_saved_source_marker_cannot_authorize_activation_without_a_current_nm_profile() -> TestResult {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    add(&mut app, "Source", A)?;
    app.catalog.added.insert(0, "missing-nm-profile".into());
    assert!(app.source_connect_action(0).is_none());
    assert!(app.source_connect_action(usize::MAX).is_none());
    assert!(app.operations.control().is_none() && !app.operations.busy());
    Ok(())
}

#[test]
fn add_action_checks_once_then_admits_the_source_without_saving_or_connecting_profiles()
-> TestResult {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    let _ = app.update(message(Action::New));
    let _ = app.update(message(Action::Add));
    assert!(app.download.pending().is_none());
    let _ = app.update(message(Action::Name("Source".into())));
    let _ = app.update(Message::Source(
        "https://subscription.example/synthetic".into(),
    ));
    let _ = app.update(message(Action::Add));
    let ticket = app.download.pending().ok_or("Check started")?;
    let _ = app.update(message(Action::Add));
    assert!(app.download.pending() == Some(ticket));
    let _ = app.update(Message::Loaded(ticket, Ok(list(A)?)));
    assert_eq!(app.sources.active_name(), Some("Source"));
    assert!(app.sources.screen == Screen::Nodes);
    assert!(!app.sources.adding && !app.operations.busy());
    assert!(app.operations.control().is_none() && app.catalog.added.is_empty());
    Ok(())
}

#[test]
fn cancelling_or_failing_an_add_check_never_creates_a_source_or_profile() -> TestResult {
    for cancelled in [false, true] {
        let (mut app, _) = App::init(Core::default(), Flags::default());
        let _ = app.update(message(Action::New));
        let _ = app.update(message(Action::Name("Source".into())));
        let _ = app.update(Message::Source(
            "https://subscription.example/synthetic".into(),
        ));
        let _ = app.update(message(Action::Add));
        let ticket = app.download.pending().ok_or("Check started")?;
        if cancelled {
            let _ = app.update(message(Action::Back));
        }
        let result = if cancelled {
            Ok(list(A)?)
        } else {
            Err(SubscriptionError::Download)
        };
        let _ = app.update(Message::Loaded(ticket, result));
        assert!(app.sources.records.is_empty());
        assert!(!app.sources.adding && !app.operations.busy());
        assert!(app.catalog.added.is_empty() && app.operations.control().is_none());
    }
    Ok(())
}
fn list(text: &str) -> TestResult<Subscription> {
    Ok(nm_tunnel_subscription::parse_subscription(text.as_bytes())?)
}

fn add(app: &mut App, name: &str, text: &str) -> TestResult<SourceId> {
    let _ = app.update(message(Action::New));
    let _ = app.update(message(Action::Name(name.into())));
    let _ = app.update(Message::Source(
        "https://subscription.example/synthetic-private-token".into(),
    ));
    let _ = app.update(Message::Load);
    let ticket = app.download.pending().ok_or("Admitted download")?;
    let _ = app.update(Message::Loaded(ticket, Ok(list(text)?)));
    let _ = app.update(message(Action::Save));
    app.sources.active.ok_or_else(|| "Admitted source".into())
}

#[test]
fn multiple_sources_keep_their_catalogs_and_urls_without_nm_mutations() -> TestResult {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    let first = add(&mut app, "First", A)?;
    app.catalog.search("First search".into());
    let second = add(&mut app, "Second", B)?;
    assert!(first != second);
    let reads = app.reads.clone();
    let _ = app.update(message(Action::Open(first)));
    assert_eq!(app.catalog.search, "First search");
    assert_eq!(
        app.catalog
            .subscription
            .as_ref()
            .ok_or("First source")?
            .entries()[0]
            .profile()
            .map_err(|_| "Unsupported")?
            .node()
            .endpoint()
            .host(),
        "a.example"
    );
    let _ = app.update(message(Action::Open(second)));
    assert_eq!(
        app.catalog
            .subscription
            .as_ref()
            .ok_or("Second source")?
            .entries()[0]
            .profile()
            .map_err(|_| "Unsupported")?
            .node()
            .endpoint()
            .host(),
        "b.example"
    );
    assert_eq!(app.reads, reads);
    assert!(!app.operations.busy());
    assert!(app.operations.control().is_none());
    Ok(())
}

#[test]
fn source_checks_must_succeed_before_save_and_cancel_never_saves_a_profile() -> TestResult {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    let _ = app.update(message(Action::New));
    let _ = app.update(message(Action::Name("Source".into())));
    let _ = app.update(message(Action::Save));
    assert!(app.sources.records.is_empty());
    app.catalog.admit(list(A)?);
    let _ = app.update(Message::AddProfile(0));
    assert!(!app.operations.busy());
    assert!(app.catalog.added.is_empty());
    let _ = app.update(message(Action::Back));
    assert!(app.sources.records.is_empty());
    assert!(app.operations.control().is_none());
    Ok(())
}

#[test]
fn failed_update_retains_the_previous_admitted_source_and_never_retries_or_falls_back() -> TestResult
{
    let (mut app, _) = App::init(Core::default(), Flags::default());
    add(&mut app, "Source", A)?;
    let _ = app.update(message(Action::Update));
    let ticket = app.download.pending().ok_or("Update download")?;
    let _ = app.update(Message::Loaded(ticket, Err(SubscriptionError::Download)));
    assert!(app.catalog.admitted);
    assert_eq!(
        app.catalog
            .subscription
            .as_ref()
            .ok_or("Retained source")?
            .entries()
            .len(),
        1
    );
    assert!(app.download.pending().is_none());
    assert!(app.sources.review.is_none());
    assert_eq!(app.download.format(), SubscriptionFormat::Complete);
    assert!(!app.operations.busy());
    assert!(app.catalog.added.is_empty());
    Ok(())
}

#[test]
fn updates_require_apply_and_exact_identity_never_uses_names_or_order() -> TestResult {
    let first = list(A)?;
    let reordered = list(&format!("{B}\n{A}"))?;
    let profile = first.entries()[0].profile().map_err(|_| "Unsupported")?;
    assert_eq!(unique_match(profile, &reordered), Some(1));
    assert_eq!(
        unique_match(profile, &list(B)?),
        None,
        "same display name is not identity"
    );
    assert_eq!(
        unique_match(profile, &list(&format!("{A}\n{A}"))?),
        None,
        "duplicate identity cannot be resolved by choosing the first row"
    );
    let (mut app, _) = App::init(Core::default(), Flags::default());
    add(&mut app, "Source", A)?;
    let _ = app.update(message(Action::Update));
    let ticket = app.download.pending().ok_or("Update download")?;
    let _ = app.update(Message::Loaded(ticket, Ok(reordered)));
    assert!(app.sources.screen == Screen::Review);
    assert_eq!(
        app.catalog
            .subscription
            .as_ref()
            .ok_or("Old source")?
            .entries()
            .len(),
        1
    );
    let _ = app.update(message(Action::Apply));
    assert_eq!(
        app.catalog
            .subscription
            .as_ref()
            .ok_or("Applied source")?
            .entries()
            .len(),
        2
    );
    assert!(app.catalog.added.is_empty());
    assert!(!app.operations.busy());
    assert!(app.operations.control().is_none());
    Ok(())
}

#[test]
fn remove_confirmation_and_escape_do_not_mutate_networkmanager_or_cascade_to_profiles() -> TestResult
{
    let (mut app, _) = App::init(Core::default(), Flags::default());
    add(&mut app, "Source", A)?;
    app.sources
        .added(0, "independent-nm-uuid".into(), "Server".into());
    let _ = app.update(message(Action::AskRemove));
    let _ = app.on_escape();
    assert_eq!(app.sources.records.len(), 1);
    assert!(!app.sources.removing);
    let reads = app.reads.clone();
    let _ = app.update(message(Action::AskRemove));
    let _ = app.update(message(Action::Remove));
    assert!(app.sources.records.is_empty());
    assert_eq!(app.reads, reads);
    assert!(!app.operations.busy());
    assert!(app.operations.control().is_none());
    assert!(app.download.source().expose_secret().is_empty());
    Ok(())
}

#[test]
fn late_downloads_cannot_replace_another_source_or_unblock_an_unknown_write() -> TestResult {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    let first = add(&mut app, "First", A)?;
    let _ = app.update(message(Action::Update));
    let old = app.download.pending().ok_or("Old download")?;
    let _ = app.update(Message::Loaded(old, Ok(list(A)?)));
    let _ = app.update(message(Action::CancelReview));
    let second = add(&mut app, "Second", B)?;
    assert!(app.operations.begin_add(0));
    app.operations.finish_add(Some(ClientError::Timeout));
    let _ = app.update(Message::Loaded(old, Ok(list(A)?)));
    assert!(app.sources.active == Some(second));
    assert!(app.operations.uncertain());
    let _ = app.update(message(Action::Open(first)));
    assert!(app.operations.uncertain());
    assert_eq!(
        app.catalog
            .subscription
            .as_ref()
            .ok_or("First source")?
            .entries()[0]
            .profile()
            .map_err(|_| "Unsupported")?
            .node()
            .endpoint()
            .host(),
        "a.example"
    );
    assert!(!app.operations.busy());
    Ok(())
}

#[test]
fn changed_source_url_is_checked_and_requires_apply_without_mutating_the_previous_source()
-> TestResult {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    add(&mut app, "Original", A)?;
    let original_url = app.sources.active().ok_or("Source")?.url.clone();
    let _ = app.update(message(Action::Settings));
    let _ = app.update(message(Action::Rename("Renamed".into())));
    let _ = app.update(message(Action::Url(
        "https://changed.example/synthetic-private-token".into(),
    )));
    let _ = app.update(message(Action::SaveSettings));
    let ticket = app.download.pending().ok_or("Candidate check")?;
    assert_eq!(
        app.sources.active().ok_or("Source")?.url.expose_secret(),
        original_url.expose_secret()
    );
    assert_eq!(app.sources.active_name(), Some("Original"));
    let _ = app.update(Message::Loaded(ticket, Ok(list(B)?)));
    assert_eq!(app.sources.active_name(), Some("Original"));
    let _ = app.update(message(Action::Apply));
    assert_eq!(app.sources.active_name(), Some("Renamed"));
    assert_eq!(
        app.sources.active().ok_or("Source")?.url.expose_secret(),
        "https://changed.example/synthetic-private-token"
    );
    assert!(app.operations.control().is_none());
    assert!(app.catalog.added.is_empty());
    Ok(())
}

#[test]
fn invalid_failed_or_cancelled_url_changes_keep_the_source_and_never_start_profile_writes()
-> TestResult {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    add(&mut app, "Original", A)?;
    let url = app.sources.active().ok_or("Source")?.url.clone();
    let _ = app.update(message(Action::Settings));
    let _ = app.update(message(Action::Url("http://invalid.example".into())));
    let _ = app.update(message(Action::SaveSettings));
    assert!(app.download.pending().is_none());
    for result in [Err(SubscriptionError::Download), Ok(list(B)?)] {
        let _ = app.update(message(Action::Settings));
        let _ = app.update(message(Action::Url(
            "https://changed.example/synthetic".into(),
        )));
        let _ = app.update(message(Action::SaveSettings));
        let ticket = app.download.pending().ok_or("Candidate check")?;
        let _ = app.update(Message::Loaded(ticket, result));
        let _ = app.update(message(Action::CancelReview));
        assert_eq!(
            app.sources.active().ok_or("Source")?.url.expose_secret(),
            url.expose_secret()
        );
        assert_eq!(app.download.source().expose_secret(), url.expose_secret());
        assert_eq!(app.sources.active_name(), Some("Original"));
        assert!(app.catalog.admitted);
        assert!(!app.operations.busy());
        assert!(app.operations.control().is_none());
    }
    Ok(())
}
