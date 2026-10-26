//! Pure subscription UI state tests; no HTTP, host NM writes or desktop input.
use super::{App, Flags, Message, Notice};
use cosmic::{Application, Core};
use nm_tunnel_client::ClientError;
use nm_tunnel_subscription::{SubscriptionError, parse_subscription};

const LIST: &str = "vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=www.example.com#Imported\ntrojan://secret@proxy.example:443#Not%20supported";

#[test]
fn local_search_preserves_entry_identity_and_remains_available_during_io()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    let _ = app.update(Message::Loaded(Ok(parse_subscription(LIST.as_bytes())?)));
    let selected = app.selected;
    app.busy = true;
    app.fetching = true;
    let _ = app.update(Message::SearchProfiles("  NOT SUPPORTED ".into()));
    assert_eq!(
        app.matching_profiles(),
        [1],
        "unsupported entries remain discoverable with original identity"
    );
    assert_eq!(app.selected, selected);
    let _ = app.update(Message::SearchProfiles("private-token-no-match".into()));
    assert!(app.matching_profiles().is_empty());
    assert_eq!(
        app.selected, selected,
        "filtering never chooses or activates another profile"
    );
    assert!(
        app.busy && app.fetching,
        "local actions must not finish an unrelated I/O operation"
    );
    let _ = app.update(Message::SearchProfiles(String::new()));
    assert_eq!(app.matching_profiles(), [0, 1]);
    app.notice = Some(Notice::Error);
    app.uncertain = true;
    let _ = app.update(Message::DismissNotice);
    assert!(app.notice.is_none());
    assert!(
        app.uncertain,
        "dismissing feedback must not permit retry of an ambiguous save"
    );
    Ok(())
}

#[test]
fn search_is_bounded_and_does_not_search_endpoint_or_credentials()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    let _ = app.update(Message::Loaded(Ok(parse_subscription(LIST.as_bytes())?)));
    let _ = app.update(Message::SearchProfiles("proxy.example".into()));
    assert!(app.matching_profiles().is_empty());
    let _ = app.update(Message::SearchProfiles("12345678".into()));
    assert!(app.matching_profiles().is_empty());
    let _ = app.update(Message::SearchProfiles("я".repeat(200)));
    assert_eq!(app.profile_search.chars().count(), 128);
    assert_eq!(app.profile_page, 0);
    Ok(())
}

#[test]
fn large_subscription_paging_preserves_selection_and_rejects_out_of_range_pages()
-> Result<(), Box<dyn std::error::Error>> {
    let body = (0..512).map(|i| format!(
        "vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=www.example.com#Node{i}"
    )).collect::<Vec<_>>().join("\n");
    let (mut app, _) = App::init(Core::default(), Flags::default());
    let _ = app.update(Message::Loaded(Ok(parse_subscription(body.as_bytes())?)));
    let last = 511 / super::view::PAGE_SIZE;
    let _ = app.update(Message::ProfilePage(last));
    assert_eq!(app.profile_page, last);
    let _ = app.update(Message::Select(511));
    let _ = app.update(Message::ProfilePage(0));
    assert_eq!(
        app.selected,
        Some(511),
        "paging never changes or activates the selected node"
    );
    let _ = app.update(Message::ProfilePage(usize::MAX));
    assert_eq!(app.profile_page, 0);
    let _ = app.update(Message::ProfilePage(last));
    let _ = app.update(Message::Loaded(Err(SubscriptionError::Download)));
    assert_eq!(
        app.profile_page, last,
        "failed refresh keeps page and profiles"
    );
    assert_eq!(app.selected, Some(511));
    let _ = app.update(Message::Loaded(Ok(parse_subscription(LIST.as_bytes())?)));
    assert_eq!(
        app.profile_page, 0,
        "a shorter list cannot leave the view on an invalid page"
    );
    assert!(!app.busy);
    Ok(())
}

#[test]
fn debug_does_not_expose_subscription_tokens() {
    assert!(
        !format!(
            "{:?}",
            Message::Source("https://example.com/private-token".into())
        )
        .contains("private-token")
    );
}

#[test]
fn failed_update_preserves_profiles_and_selection() -> Result<(), Box<dyn std::error::Error>> {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    let _ = app.update(Message::Loaded(Ok(parse_subscription(LIST.as_bytes())?)));
    let _ = app.update(Message::Loaded(Err(SubscriptionError::Download)));
    assert_eq!(app.selected, Some(0));
    assert_eq!(
        app.subscription
            .as_ref()
            .map(|list| list.entries()[0].name()),
        Some("Imported")
    );
    assert!(!app.busy);
    Ok(())
}

#[test]
fn loading_selects_only_supported_entries_without_nm_writes()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    let _ = app.update(Message::Loaded(Ok(parse_subscription(LIST.as_bytes())?)));
    assert_eq!(app.selected, Some(0));
    assert!(app.added.is_empty());
    assert!(!app.busy);
    let _ = app.update(Message::Select(1));
    assert_eq!(
        app.selected,
        Some(0),
        "unsupported record must not be selectable"
    );
    assert!(app.control.is_none());
    Ok(())
}

#[test]
fn connection_control_requires_observed_backend_and_profile_and_never_claims_readiness() {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    let _ = app.update(Message::Connect);
    let _ = app.update(Message::Disconnect);
    assert!(!app.busy);
    assert!(!app.can_connect());
    let _ = app.update(Message::Observed(
        0,
        Ok(nm_tunnel_client::Snapshot {
            profiles: vec![],
            active: vec![],
            backend_registered: false,
        }),
    ));
    assert!(!app.can_connect());
    let _ = app.update(Message::Controlled(Ok(())));
    assert_ne!(app.connection_title(), "Connected");
    assert!(
        app.snapshot.is_none(),
        "method acceptance must invalidate stale state"
    );
}

#[test]
fn stale_nm_observation_cannot_overwrite_state_after_a_new_action() {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    app.epoch = 1;
    app.monitor_pending = true;
    let _ = app.update(Message::Observed(
        0,
        Ok(nm_tunnel_client::Snapshot {
            profiles: vec![],
            active: vec![],
            backend_registered: true,
        }),
    ));
    assert!(app.snapshot.is_none());
    assert!(!app.monitor_pending);
    let _ = app.update(Message::Observed(1, Err(ClientError::Unavailable)));
    assert_eq!(app.connection_title(), "NetworkManager unavailable");
    assert!(!app.can_connect());
}

#[test]
fn accepted_activation_that_disappears_reports_failure_without_a_retry_or_guard_clear() {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    app.control = Some(super::connection::Intent::Connect(
        "requested-profile".into(),
    ));
    let _ = app.update(Message::Controlled(Ok(())));
    let _ = app.update(Message::Observed(
        0,
        Ok(nm_tunnel_client::Snapshot {
            profiles: vec![],
            active: vec![],
            backend_registered: true,
        }),
    ));
    assert!(matches!(app.notice, Some(Notice::Error)));
    assert!(app.status.contains("guard can remain closed"));
    assert!(app.control.is_none());
    assert!(!app.busy);
    assert!(!app.can_connect());
}

#[test]
fn invalid_source_and_empty_selection_never_start_io() {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    let _ = app.update(Message::Load);
    assert!(!app.busy);
    let _ = app.update(Message::Prepare);
    assert!(!app.busy);
}

#[test]
fn ambiguous_nm_save_is_not_retried_by_subscription_refresh()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    let _ = app.update(Message::Prepared(Err(ClientError::Timeout)));
    let _ = app.update(Message::Loaded(Ok(parse_subscription(LIST.as_bytes())?)));
    let _ = app.update(Message::Prepare);
    assert!(app.uncertain);
    assert!(!app.busy);
    Ok(())
}

#[test]
fn feedback_is_reserved_for_errors_and_action_results() -> Result<(), Box<dyn std::error::Error>> {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    assert!(app.notice.is_none());
    let _ = app.update(Message::Load);
    assert!(app.load_error.is_some());
    let _ = app.update(Message::Source("https://subscription.example/list".into()));
    assert!(app.notice.is_none());
    assert!(app.load_error.is_none());
    let _ = app.update(Message::Loaded(Ok(parse_subscription(LIST.as_bytes())?)));
    assert!(app.notice.is_none());
    let _ = app.update(Message::Controlled(Ok(())));
    assert!(matches!(app.notice, Some(Notice::Info)));
    Ok(())
}

#[test]
fn fetching_keeps_nm_monitoring_live_and_coalesced() {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    let _ = app.update(Message::Source("https://subscription.example/list".into()));
    let _ = app.update(Message::Load);
    assert!(app.fetching);
    assert!(!app.busy, "HTTP must not own the NM mutation lock");
    let _ = app.update(Message::Poll);
    assert!(app.monitor_pending);
    let epoch = app.epoch;
    let _ = app.update(Message::Poll);
    assert_eq!(app.epoch, epoch);
    let _ = app.update(Message::Observed(epoch, Err(ClientError::Unavailable)));
    assert!(!app.monitor_pending);
    assert!(app.fetching);
    assert_eq!(app.connection_title(), "NetworkManager unavailable");
    let _ = app.update(Message::Poll);
    assert!(app.monitor_pending);
}

#[test]
fn http_completion_cannot_finish_disconnect_or_replace_its_feedback()
-> Result<(), Box<dyn std::error::Error>> {
    use super::connection::Intent;
    for result in [
        Ok(parse_subscription(LIST.as_bytes())?),
        Err(SubscriptionError::Download),
    ] {
        let (mut app, _) = App::init(Core::default(), Flags::default());
        app.fetching = true;
        app.monitor_pending = true;
        app.begin_control(
            Intent::Disconnect("requested-profile".into()),
            "Disconnecting target",
        );
        let epoch = app.epoch;
        let _ = app.update(Message::Observed(
            epoch - 1,
            Ok(nm_tunnel_client::Snapshot {
                profiles: vec![],
                active: vec![],
                backend_registered: true,
            }),
        ));
        assert!(
            app.snapshot.is_none(),
            "pre-disconnect observation stays stale"
        );
        let _ = app.update(Message::Loaded(result));
        assert!(!app.fetching);
        assert!(
            app.busy,
            "HTTP completion must not release the NM mutation lock"
        );
        assert_eq!(app.status, "Disconnecting target");
        assert!(app.control.is_some());
        assert_eq!(app.epoch, epoch);
        let _ = app.update(Message::Controlled(Ok(())));
        assert!(!app.busy);
        assert!(app.monitor_pending);
        let _ = app.update(Message::Observed(
            epoch,
            Ok(nm_tunnel_client::Snapshot {
                profiles: vec![],
                active: vec![],
                backend_registered: true,
            }),
        ));
        assert!(app.control.is_none());
        assert!(app.status.contains("VPN disconnected"));
    }
    Ok(())
}

#[test]
fn nm_completion_does_not_finish_http_and_http_failure_preserves_nm_notice() {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    app.fetching = true;
    app.begin_control(
        super::connection::Intent::Disconnect("target".into()),
        "Disconnecting",
    );
    let _ = app.update(Message::Controlled(Err(ClientError::ControlTimeout)));
    assert!(app.fetching);
    assert!(!app.busy);
    let status = app.status.clone();
    let _ = app.update(Message::Loaded(Err(SubscriptionError::Download)));
    assert_eq!(app.status, status);
    assert!(matches!(app.notice, Some(Notice::Error)));
    assert!(app.load_error.is_some());
}

#[test]
fn added_rows_survive_other_additions_and_only_successful_nm_reads_reconcile_them()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    let body = LIST.replace("trojan://secret@proxy.example:443#Not%20supported", "vless://12345678-1234-4234-8234-123456789abd@proxy.example:443?security=tls&sni=www.example.com#Second");
    let _ = app.update(Message::Loaded(Ok(parse_subscription(body.as_bytes())?)));
    app.added.insert(0, "nm-a".into());
    app.added.insert(1, "nm-b".into());
    for index in [0, 1, 0] {
        let _ = app.update(Message::Select(index));
        assert!(app.selected_added());
        let _ = app.update(Message::Prepare);
        assert!(
            !app.busy,
            "a previously added row cannot create another profile"
        );
    }
    let _ = app.update(Message::Observed(0, Err(ClientError::Unavailable)));
    assert_eq!(app.added.len(), 2, "a failed read proves no removal");
    app.reconcile_added(["nm-b"].into_iter());
    assert!(
        !app.selected_added(),
        "externally removed A is addable again"
    );
    assert!(app.added.contains_key(&1));
    let _ = app.update(Message::Observed(
        0,
        Ok(nm_tunnel_client::Snapshot {
            profiles: vec![],
            active: vec![],
            backend_registered: true,
        }),
    ));
    assert!(
        app.added.is_empty(),
        "successful empty observation confirms removal"
    );
    app.added.insert(0, "nm-a".into());
    let _ = app.update(Message::Loaded(Err(SubscriptionError::Download)));
    assert!(
        app.selected_added(),
        "failed HTTP refresh preserves row identities"
    );
    let _ = app.update(Message::Loaded(Ok(parse_subscription(LIST.as_bytes())?)));
    assert!(
        app.added.is_empty(),
        "new list must not inherit positional identities"
    );
    Ok(())
}

#[test]
fn control_outcomes_match_the_requested_profile_not_unrelated_connections() {
    use super::connection::{Intent, Outcome};
    use nm_tunnel_client::ConnectionState::{Connected, Connecting, Disconnecting};
    let connect = Intent::Connect("target".into());
    assert_eq!(
        connect.observe([("other", Connected)].into_iter()),
        Some(Outcome::Failed)
    );
    assert_eq!(
        connect.observe([("target", Connecting), ("other", Connected)].into_iter()),
        None
    );
    assert_eq!(
        connect.observe([("target", Connected), ("other", Connecting)].into_iter()),
        Some(Outcome::Connected)
    );
    let disconnect = Intent::Disconnect("target".into());
    assert_eq!(
        disconnect.observe([("target", Disconnecting), ("other", Connected)].into_iter()),
        None
    );
    assert_eq!(
        disconnect.observe([("other", Connected)].into_iter()),
        Some(Outcome::Disconnected)
    );
}

fn usage() -> nm_tunnel_client::UsageSnapshot {
    nm_tunnel_client::UsageSnapshot {
        version: 1,
        generation: 3,
        state: "running".into(),
        setup_stage: "ready".into(),
        worker_stage: 7,
        elapsed_ms: 2000,
        available: true,
        live: true,
        age_ms: 0,
        counters: nm_tunnel_client::TrafficCounters {
            download_bytes: 42,
            ..Default::default()
        },
        upload_bytes_per_second: 0,
        download_bytes_per_second: 21,
        history: vec![],
    }
}

#[test]
fn navigation_details_and_search_do_not_cancel_or_complete_io() {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    app.busy = true;
    app.fetching = true;
    app.traffic.observe(Ok(Some(usage())));
    let _ = app.update(Message::Navigate(super::Page::Import));
    let _ = app.update(Message::ShowDetails(None));
    assert!(app.core.window.show_context);
    let _ = app.update(Message::SearchSaved("n".repeat(300)));
    assert_eq!(app.saved_search.len(), 128);
    let _ = app.on_escape();
    assert!(!app.core.window.show_context);
    assert_eq!(app.page, super::Page::Import);
    let _ = app.on_escape();
    assert_eq!(app.page, super::Page::Connections);
    assert!(app.busy && app.fetching);
    assert_eq!(app.traffic.snapshot.as_ref().map(|s| s.generation), Some(3));
    assert!(app.control.is_none());
}

#[test]
fn window_header_owns_title_add_action_and_import_back_navigation() {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    assert_eq!(app.header_start().len(), 1);
    assert!(app.header_center().is_empty());
    assert_eq!(app.header_end().len(), 1);
    assert!(app.core.window.header_title.is_empty());
    let _ = app.update(Message::Navigate(super::Page::Import));
    assert_eq!(app.header_start().len(), 2);
    assert!(app.header_center().is_empty());
    assert!(app.header_end().is_empty());
    assert!(app.core.window.header_title.is_empty());
    let _ = app.on_escape();
    assert_eq!(app.header_start().len(), 1);
    assert_eq!(app.header_end().len(), 1);
    assert!(app.control.is_none());
    assert!(!app.busy && !app.fetching);
}

#[test]
fn telemetry_updates_are_coalesced_and_do_not_own_nm_or_http_operations() {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    app.busy = true;
    app.fetching = true;
    let _ = app.update(Message::Tick);
    assert!(app.traffic.pending);
    assert!(!app.monitor_pending);
    let _ = app.update(Message::Tick);
    let _ = app.update(Message::UsageObserved(0, Ok(Some(usage()))));
    assert!(!app.traffic.pending);
    assert!(app.traffic.live());
    assert!(app.busy && app.fetching);
    app.epoch = 1;
    let _ = app.update(Message::UsageObserved(0, Ok(None)));
    assert!(
        app.traffic.snapshot.is_some(),
        "Stale pre-mutation results do not replace the current observation"
    );
    let _ = app.update(Message::UsageObserved(
        1,
        Err(nm_tunnel_client::UsageError::Unavailable),
    ));
    assert!(!app.traffic.live());
    assert!(
        app.traffic.snapshot.is_none(),
        "Unavailable is not zero usage or old-owner data"
    );
    assert!(app.busy && app.fetching);
    let mut stopped = usage();
    stopped.live = false;
    let _ = app.update(Message::UsageObserved(1, Ok(Some(stopped))));
    assert!(!app.traffic.live());
    assert_eq!(
        app.traffic
            .snapshot
            .as_ref()
            .map(|s| s.counters.download_bytes),
        Some(42)
    );
}

#[test]
fn per_row_add_rejects_invalid_rows_without_saving_the_previous_selection()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    let _ = app.update(Message::Loaded(Ok(parse_subscription(LIST.as_bytes())?)));
    for index in [1, usize::MAX] {
        let _ = app.update(Message::AddProfile(index));
        assert_eq!(app.selected, Some(0));
        assert!(!app.busy);
    }
    app.added.insert(0, "already-added".into());
    let _ = app.update(Message::AddProfile(0));
    assert!(!app.busy);
    let _ = app.update(Message::ConnectProfile("not-an-observed-profile".into()));
    assert!(!app.busy);
    assert!(app.control.is_none());
    Ok(())
}

#[test]
fn backend_attempt_statistics_never_become_profile_details() {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    app.traffic.observe(Ok(Some(usage())));
    for id in ["old-profile", "replacement-profile"] {
        let _ = app.update(Message::ShowDetails(Some(id.into())));
        assert!(!app.details_include_usage());
    }
    let _ = app.update(Message::ShowDetails(None));
    assert!(app.details_include_usage());
    let mut replacement = usage();
    replacement.generation = 0;
    replacement.live = false;
    app.traffic.observe(Ok(Some(replacement)));
    let _ = app.update(Message::ShowDetails(Some("replacement-profile".into())));
    assert!(!app.details_include_usage());
}

#[test]
fn an_older_accepted_control_cannot_replace_a_new_save_failure()
-> Result<(), Box<dyn std::error::Error>> {
    for error in [ClientError::Rejected, ClientError::Timeout] {
        let (mut app, _) = App::init(Core::default(), Flags::default());
        let _ = app.update(Message::Loaded(Ok(parse_subscription(LIST.as_bytes())?)));
        app.control = Some(super::connection::Intent::Connect(
            "previous-control".into(),
        ));
        let _ = app.update(Message::Prepare);
        assert!(app.busy);
        assert!(app.control.is_none());
        let _ = app.update(Message::Prepared(Err(error)));
        let failure = app.status.clone();
        let _ = app.update(Message::Observed(
            app.epoch,
            Ok(nm_tunnel_client::Snapshot {
                profiles: vec![],
                active: vec![],
                backend_registered: true,
            }),
        ));
        assert_eq!(app.status, failure);
        assert_eq!(app.notice.is_none(), error == ClientError::Timeout);
        assert_eq!(app.uncertain, error == ClientError::Timeout);
    }
    Ok(())
}
