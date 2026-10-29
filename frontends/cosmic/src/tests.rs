//! Pure subscription UI state tests; no HTTP, host NM writes or desktop input.
use super::{App, Flags, Message, Notice};
use cosmic::{Application, Core};
use nm_tunnel_client::ClientError;
use nm_tunnel_subscription::{SubscriptionError, parse_subscription};

const LIST: &str = "vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=www.example.com#Imported\ntrojan://secret@proxy.example:443#Not%20supported";

#[test]
fn installed_package_notice_never_overwrites_errors_or_dispatches_vpn_control() {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    app.package_update.changed = true;
    app.status = "Existing action failure".into();
    app.notice = Some(Notice::Error);
    let _ = app.update(Message::Tick);
    assert_eq!(app.status, "Existing action failure");
    assert!(!app.package_update.notified);
    assert!(!app.operations.busy());
    let _ = app.update(Message::DismissNotice);
    let _ = app.update(Message::Tick);
    assert!(app.package_update.notified);
    assert!(matches!(app.notice, Some(Notice::Info)));
    assert!(!app.operations.busy());
    assert!(app.snapshot.is_none());
}

// Complete the real read admission path with synthetic data, without polling I/O.
fn observe_nm(app: &mut App, result: Result<nm_tunnel_client::Snapshot, ClientError>) {
    let _ = app.update(Message::Poll);
    let Some(ticket) = app.reads.nm.pending() else {
        panic!("No admitted NM read");
    };
    let _ = app.update(Message::Observed(ticket, result));
}

fn begin_download(app: &mut App) -> super::download::Ticket {
    assert!(
        app.download
            .edit_source("https://subscription.example/synthetic-fixture".into())
    );
    let Some((ticket, _, _)) = app.download.begin() else {
        panic!("No admitted download");
    };
    ticket
}

fn loaded(app: &mut App, result: Result<nm_tunnel_subscription::Subscription, SubscriptionError>) {
    let ticket = app
        .download
        .pending()
        .unwrap_or_else(|| begin_download(app));
    let _ = app.update(Message::Loaded(ticket, result));
}

#[test]
fn fakeip_creation_is_explicit_requires_interception_and_never_disables_source_requirements()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    loaded(&mut app, Ok(parse_subscription(LIST.as_bytes())?));
    let source = app
        .catalog
        .subscription
        .as_ref()
        .ok_or("Missing fixture")?
        .entries()[0]
        .profile()
        .map_err(|_| "Unsupported fixture")?
        .clone();
    assert!(!app.options.dns_interception && !app.options.fake_ip);
    let _ = app.update(Message::FakeIp(true));
    assert!(
        !app.options.fake_ip,
        "interception must be explicitly chosen first"
    );
    let _ = app.update(Message::DnsInterception(true));
    let _ = app.update(Message::FakeIp(true));
    let selected = app.profile_with_dns(&source)?;
    assert!(selected.network().fake_ip() && selected.network().intercepts_dns());
    assert!(!source.network().fake_ip() && !source.network().intercepts_dns());
    let _ = app.update(Message::DnsInterception(false));
    assert!(
        app.options.dns_interception && app.options.fake_ip,
        "no implicit FakeIP downgrade"
    );
    assert!(app.operations.begin_add(0));
    let _ = app.update(Message::FakeIp(false));
    let _ = app.update(Message::DnsInterception(false));
    assert!(app.options.dns_interception && app.options.fake_ip);
    assert_eq!(app.operations.finish_add(None), Some(0));
    let _ = app.update(Message::FakeIp(false));
    let _ = app.update(Message::DnsInterception(false));
    assert!(!app.options.dns_interception && !app.options.fake_ip);
    let preserved = app.profile_with_dns(&selected)?;
    assert!(preserved.network().fake_ip() && preserved.network().intercepts_dns());
    let mut admitted = selected.to_draft();
    admitted.lan_bypass = true;
    let admitted = admitted
        .validate()
        .map_err(|_| "Invalid admitted fixture")?;
    assert_eq!(
        app.profile_with_dns(&admitted)?.lan_bypass(),
        nm_tunnel_profile::LanBypass::Connected
    );
    assert!(!app.operations.busy() && app.catalog.added.is_empty());
    Ok(())
}

#[test]
fn edits_and_source_mapping_need_an_observed_target_and_explicit_review_before_nm_requests()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    loaded(&mut app, Ok(parse_subscription(LIST.as_bytes())?));
    let reads = app.reads.clone();
    for message in [
        Message::Profile(super::profile_editor::Action::Edit(
            "unobserved-target".into(),
        )),
        Message::Subscription(super::subscriptions::Action::Map(
            "unobserved-target".into(),
            0,
        )),
        Message::Subscription(super::subscriptions::Action::Map(
            "unobserved-target".into(),
            usize::MAX,
        )),
        Message::Subscription(super::subscriptions::Action::Apply),
        Message::Subscription(super::subscriptions::Action::CancelReview),
    ] {
        let _ = app.update(message);
        assert!(!app.operations.busy());
        assert!(app.sources.review.is_none() && app.editor.is_none());
        assert!(app.catalog.added.is_empty());
        assert_eq!(app.reads, reads);
    }
    assert!(app.catalog.admitted);
    assert_eq!(app.catalog.selected, Some(0));
    Ok(())
}

#[test]
fn profile_edit_failure_preserves_loaded_nodes_and_timeout_blocks_further_saves()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    loaded(&mut app, Ok(parse_subscription(LIST.as_bytes())?));
    app.catalog
        .added
        .insert(0, "previously-saved-independent-id".into());
    for error in [
        ClientError::Rejected,
        ClientError::Stale,
        ClientError::UpdateUnsupported,
        ClientError::Timeout,
    ] {
        let ticket = app
            .operations
            .begin_storage()
            .ok_or("Missing storage slot")?;
        app.profile_save = Some(ticket);
        let _ = app.update(Message::Profile(super::profile_editor::Action::Saved(
            ticket,
            Err(error),
        )));
        assert!(!app.operations.busy());
        assert!(app.sources.review.is_none());
        assert_eq!(app.catalog.selected, Some(0));
        assert_eq!(
            app.catalog
                .subscription
                .as_ref()
                .ok_or("Lost source")?
                .entries()
                .len(),
            2
        );
        assert_eq!(
            app.catalog.added.get(&0).map(String::as_str),
            Some("previously-saved-independent-id")
        );
        assert_eq!(app.operations.uncertain(), error == ClientError::Timeout);
    }
    let reads = app.reads.clone();
    app.catalog.added.clear();
    for message in [
        Message::Profile(super::profile_editor::Action::Edit(
            "unobserved-target".into(),
        )),
        Message::Profile(super::profile_editor::Action::Save),
        Message::Subscription(super::subscriptions::Action::Apply),
        Message::AddProfile(0),
        Message::Prepare,
    ] {
        let _ = app.update(message);
        assert!(!app.operations.busy());
        assert_eq!(app.reads, reads);
    }
    assert!(app.operations.uncertain() && app.catalog.added.is_empty());
    Ok(())
}

#[test]
fn dns_choices_affect_only_new_profile_copies_and_reject_bad_manual_values_before_nm_io()
-> Result<(), Box<dyn std::error::Error>> {
    use nm_tunnel_profile::{DnsOverride, TcpDomainPolicy};
    let (mut app, _) = App::init(Core::default(), Flags::default());
    loaded(&mut app, Ok(parse_subscription(LIST.as_bytes())?));
    let source = app
        .catalog
        .subscription
        .as_ref()
        .ok_or("missing fixture")?
        .entries()[0]
        .profile()
        .map_err(|_| "unsupported fixture")?
        .clone();
    let mut draft = source.to_draft();
    draft.tcp_domain_policy = Some(TcpDomainPolicy::from_json(
        r#"{"version":1,"rules":[{"domain_suffix":["example"],"action":"block"}]}"#,
    )?);
    draft.dns_interception = true;
    let routed = draft.validate().map_err(|_| "bad route fixture")?;
    let _ = app.update(Message::DnsChoice(super::DnsChoice::CurrentNetwork));
    assert!(!app.options.lan_bypass);
    let preserved = app.profile_with_dns(&routed)?;
    let _ = app.update(Message::LanBypass(true));
    // Broad physical bypass must reject conflicting hostname policy, not erase it.
    assert!(app.profile_with_dns(&routed).is_err());
    let mut plain = source.to_draft();
    plain.dns_interception = true;
    let plain = plain.validate().map_err(|_| "bad private-LAN fixture")?;
    let changed = app.profile_with_dns(&plain)?;
    assert_eq!(changed.lan_bypass(), nm_tunnel_profile::LanBypass::Private);
    assert!(changed.network().intercepts_dns());
    assert_eq!(source.lan_bypass(), nm_tunnel_profile::LanBypass::None);
    assert_eq!(
        changed.network().dns_override(),
        DnsOverride::CurrentNetwork
    );
    assert_eq!(
        preserved
            .network()
            .tcp_domains()
            .map(|policy| policy.as_json()),
        routed
            .network()
            .tcp_domains()
            .map(|policy| policy.as_json())
    );
    assert_eq!(source.network().dns_override(), DnsOverride::Inherit);
    let _ = app.update(Message::DnsChoice(super::DnsChoice::Manual));
    let _ = app.update(Message::ManualDns("private-invalid-address".into()));
    let reads = app.reads.clone();
    let _ = app.update(Message::Prepare);
    assert!(!app.operations.busy() && app.catalog.added.is_empty());
    assert_eq!(app.reads, reads);
    assert!(!app.status.contains("private-invalid-address"));
    let _ = app.update(Message::ManualDns(" 8.8.8.8 ".into()));
    assert_eq!(
        app.profile_with_dns(&plain)?.network().dns_override(),
        DnsOverride::ProxyIpv4("8.8.8.8".parse()?)
    );
    assert!(app.operations.begin_add(0));
    let _ = app.update(Message::LanBypass(false));
    assert!(app.options.lan_bypass);
    let _ = app.update(Message::DnsChoice(super::DnsChoice::CurrentNetwork));
    let _ = app.update(Message::ManualDns("9.9.9.9".into()));
    assert_eq!(app.options.dns_choice, super::DnsChoice::Manual);
    assert_eq!(app.options.manual_dns, " 8.8.8.8 ");
    assert_eq!(source.network().dns_override(), DnsOverride::Inherit);
    Ok(())
}

#[test]
fn source_format_and_failed_admission_cannot_add_retained_nodes()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    assert_eq!(
        app.download.format(),
        nm_tunnel_subscription::SubscriptionFormat::Complete
    );
    assert!(!app.catalog.admitted);
    let _ = app.update(Message::FetchComplete(false));
    loaded(&mut app, Ok(parse_subscription(LIST.as_bytes())?));
    assert!(app.catalog.admitted);
    let selected = app.catalog.selected;
    let names: Vec<_> = app
        .catalog
        .subscription
        .as_ref()
        .ok_or("missing fixture")?
        .entries()
        .iter()
        .map(|entry| entry.name().to_owned())
        .collect();
    let _ = app.update(Message::FetchComplete(true));
    assert!(!app.catalog.admitted);
    let _ = app.update(Message::AddProfile(0));
    let _ = app.update(Message::Prepare);
    assert!(!app.operations.busy());
    loaded(
        &mut app,
        Err(SubscriptionError::UnsupportedPolicy(
            nm_tunnel_subscription::PolicyIssue::FakeIp,
        )),
    );
    let _ = app.update(Message::LanBypass(true));
    let _ = app.update(Message::DnsChoice(super::DnsChoice::CurrentNetwork));
    let _ = app.update(Message::AddProfile(0));
    assert!(
        !app.catalog.admitted && !app.operations.busy(),
        "DNS override cannot discard required source FakeIP policy"
    );
    assert_eq!(app.catalog.selected, selected);
    assert_eq!(
        app.catalog
            .subscription
            .as_ref()
            .ok_or("lost retained nodes")?
            .entries()
            .iter()
            .map(|entry| entry.name().to_owned())
            .collect::<Vec<_>>(),
        names
    );
    let _ = app.update(Message::DismissNotice);
    let _ = app.update(Message::FetchComplete(false));
    let _ = app.update(Message::AddProfile(0));
    let _ = app.update(Message::Prepare);
    assert!(
        !app.operations.busy(),
        "changing mode or dismissing an error cannot approve old nodes"
    );
    assert!(!app.catalog.admitted);
    assert!(app.catalog.added.is_empty());
    assert!(app.operations.control().is_none());
    loaded(&mut app, Ok(parse_subscription(LIST.as_bytes())?));
    assert!(app.catalog.admitted);
    let _ = app.update(Message::Source(
        "https://example.com/changed-private-source".into(),
    ));
    let _ = app.update(Message::AddProfile(0));
    assert!(!app.catalog.admitted && !app.operations.busy());
    Ok(())
}

#[test]
fn in_flight_download_or_save_keeps_the_selected_format_immutable() {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    let ticket = begin_download(&mut app);
    let _ = app.update(Message::FetchComplete(false));
    assert_eq!(
        app.download.format(),
        nm_tunnel_subscription::SubscriptionFormat::Complete
    );
    let _ = app
        .download
        .finish(ticket, Err(SubscriptionError::Download));
    assert!(app.operations.begin_add(0));
    let _ = app.update(Message::FetchComplete(false));
    assert_eq!(
        app.download.format(),
        nm_tunnel_subscription::SubscriptionFormat::Complete
    );
    assert!(app.operations.busy());
}

#[test]
fn local_search_preserves_entry_identity_and_remains_available_during_io()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    loaded(&mut app, Ok(parse_subscription(LIST.as_bytes())?));
    let selected = app.catalog.selected;
    assert!(app.operations.begin_add(0));
    begin_download(&mut app);
    let _ = app.update(Message::SearchProfiles("  NOT SUPPORTED ".into()));
    assert_eq!(
        app.matching_profiles(),
        [1],
        "unsupported entries remain discoverable with original identity"
    );
    assert_eq!(app.catalog.selected, selected);
    let _ = app.update(Message::SearchProfiles("private-token-no-match".into()));
    assert!(app.matching_profiles().is_empty());
    assert_eq!(
        app.catalog.selected, selected,
        "filtering never chooses or activates another profile"
    );
    assert!(
        app.operations.busy() && app.download.pending().is_some(),
        "local actions must not finish an unrelated I/O operation"
    );
    let _ = app.update(Message::SearchProfiles(String::new()));
    assert_eq!(app.matching_profiles(), [0, 1]);
    app.notice = Some(Notice::Error);
    assert_eq!(
        app.operations.finish_add(Some(ClientError::Timeout)),
        Some(0)
    );
    let _ = app.update(Message::DismissNotice);
    assert!(app.notice.is_none());
    assert!(
        app.operations.uncertain(),
        "dismissing feedback must not permit retry of an ambiguous save"
    );
    Ok(())
}

#[test]
fn search_is_bounded_and_does_not_search_endpoint_or_credentials()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    loaded(&mut app, Ok(parse_subscription(LIST.as_bytes())?));
    let _ = app.update(Message::SearchProfiles("proxy.example".into()));
    assert!(app.matching_profiles().is_empty());
    let _ = app.update(Message::SearchProfiles("12345678".into()));
    assert!(app.matching_profiles().is_empty());
    let _ = app.update(Message::SearchProfiles("я".repeat(200)));
    assert_eq!(app.catalog.search.chars().count(), 128);
    assert_eq!(app.catalog.page, 0);
    Ok(())
}

#[test]
fn large_subscription_paging_preserves_selection_and_rejects_out_of_range_pages()
-> Result<(), Box<dyn std::error::Error>> {
    let body = (0..512).map(|i| format!(
        "vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=www.example.com#Node{i}"
    )).collect::<Vec<_>>().join("\n");
    let (mut app, _) = App::init(Core::default(), Flags::default());
    loaded(&mut app, Ok(parse_subscription(body.as_bytes())?));
    let last = 511 / super::view::PAGE_SIZE;
    let _ = app.update(Message::ProfilePage(last));
    assert_eq!(app.catalog.page, last);
    let _ = app.update(Message::Select(511));
    let _ = app.update(Message::ProfilePage(0));
    assert_eq!(
        app.catalog.selected,
        Some(511),
        "paging never changes or activates the selected node"
    );
    let _ = app.update(Message::ProfilePage(usize::MAX));
    assert_eq!(app.catalog.page, 0);
    let _ = app.update(Message::ProfilePage(last));
    loaded(&mut app, Err(SubscriptionError::Download));
    assert_eq!(
        app.catalog.page, last,
        "failed refresh keeps page and profiles"
    );
    assert_eq!(app.catalog.selected, Some(511));
    loaded(&mut app, Ok(parse_subscription(LIST.as_bytes())?));
    assert_eq!(
        app.catalog.page, 0,
        "a shorter list cannot leave the view on an invalid page"
    );
    assert!(!app.operations.busy());
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
    loaded(&mut app, Ok(parse_subscription(LIST.as_bytes())?));
    loaded(&mut app, Err(SubscriptionError::Download));
    assert_eq!(app.catalog.selected, Some(0));
    assert_eq!(
        app.catalog
            .subscription
            .as_ref()
            .map(|list| list.entries()[0].name()),
        Some("Imported")
    );
    assert!(!app.operations.busy());
    Ok(())
}

#[test]
fn loading_selects_only_supported_entries_without_nm_writes()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    loaded(&mut app, Ok(parse_subscription(LIST.as_bytes())?));
    assert_eq!(app.catalog.selected, Some(0));
    assert!(app.catalog.added.is_empty());
    assert!(!app.operations.busy());
    let _ = app.update(Message::Select(1));
    assert_eq!(
        app.catalog.selected,
        Some(0),
        "unsupported record must not be selectable"
    );
    assert!(app.operations.control().is_none());
    Ok(())
}

#[test]
fn connection_control_requires_observed_backend_and_profile_and_never_claims_readiness() {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    let _ = app.update(Message::Connect);
    let _ = app.update(Message::Disconnect);
    assert!(!app.operations.busy());
    assert!(!app.can_connect());
    observe_nm(
        &mut app,
        Ok(nm_tunnel_client::Snapshot {
            profiles: vec![],
            active: vec![],
            backend_registered: false,
        }),
    );
    assert!(!app.can_connect());
    assert!(
        app.operations
            .begin_control(super::connection::Intent::Connect("target".into()))
    );
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
    let _ = app.update(Message::Poll);
    let Some(old) = app.reads.nm.pending() else {
        panic!("No NM read");
    };
    app.reads.invalidate();
    let _ = app.update(Message::Observed(
        old,
        Ok(nm_tunnel_client::Snapshot {
            profiles: vec![],
            active: vec![],
            backend_registered: true,
        }),
    ));
    assert!(app.snapshot.is_none());
    assert!(app.reads.nm.pending().is_none());
    observe_nm(&mut app, Err(ClientError::Unavailable));
    assert_eq!(app.connection_title(), "NetworkManager unavailable");
    assert!(!app.can_connect());
}

#[test]
fn accepted_activation_that_disappears_reports_failure_without_frontend_network_mutation() {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    assert!(
        app.operations
            .begin_control(super::connection::Intent::Connect(
                "requested-profile".into(),
            ))
    );
    let _ = app.update(Message::Controlled(Ok(())));
    observe_nm(
        &mut app,
        Ok(nm_tunnel_client::Snapshot {
            profiles: vec![],
            active: vec![],
            backend_registered: true,
        }),
    );
    assert!(matches!(app.notice, Some(Notice::Error)));
    assert!(app.status.contains("automatic network cleanup"));
    assert!(app.operations.control().is_none());
    assert!(!app.operations.busy());
    assert!(!app.can_connect());
}

#[test]
fn invalid_source_and_empty_selection_never_start_io() {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    let _ = app.update(Message::Load);
    assert!(!app.operations.busy());
    let _ = app.update(Message::Prepare);
    assert!(!app.operations.busy());
}

#[test]
fn ambiguous_nm_save_is_not_retried_by_subscription_refresh()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    assert!(app.operations.begin_add(0));
    let _ = app.update(Message::Prepared(Err(ClientError::Timeout)));
    loaded(&mut app, Ok(parse_subscription(LIST.as_bytes())?));
    let _ = app.update(Message::Prepare);
    assert!(app.operations.uncertain());
    assert!(!app.operations.busy());
    Ok(())
}

#[test]
fn feedback_is_reserved_for_errors_and_action_results() -> Result<(), Box<dyn std::error::Error>> {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    assert!(app.notice.is_none());
    let _ = app.update(Message::Load);
    assert!(app.download.error().is_some());
    let _ = app.update(Message::Source("https://subscription.example/list".into()));
    assert!(app.notice.is_none());
    assert!(app.download.error().is_none());
    loaded(&mut app, Ok(parse_subscription(LIST.as_bytes())?));
    assert!(app.notice.is_none());
    assert!(
        app.operations
            .begin_control(super::connection::Intent::Connect("target".into()))
    );
    let _ = app.update(Message::Controlled(Ok(())));
    assert!(
        app.notice.is_none(),
        "request acceptance is not a completed action"
    );
    Ok(())
}

#[test]
fn fetching_keeps_nm_monitoring_live_and_coalesced() {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    let _ = app.update(Message::Source("https://subscription.example/list".into()));
    let _ = app.update(Message::Load);
    assert!(app.download.pending().is_some());
    assert!(
        !app.operations.busy(),
        "HTTP must not own the NM mutation lock"
    );
    let _ = app.update(Message::Poll);
    let Some(ticket) = app.reads.nm.pending() else {
        panic!("No NM read");
    };
    let reads = app.reads.clone();
    let _ = app.update(Message::Poll);
    assert_eq!(app.reads, reads);
    let _ = app.update(Message::Observed(ticket, Err(ClientError::Unavailable)));
    assert!(app.reads.nm.pending().is_none());
    assert!(app.download.pending().is_some());
    assert_eq!(app.connection_title(), "NetworkManager unavailable");
    let _ = app.update(Message::Poll);
    assert!(app.reads.nm.pending().is_some());
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
        begin_download(&mut app);
        let _ = app.update(Message::Poll);
        let old = app.reads.nm.pending().ok_or("No NM read")?;
        app.begin_control(
            Intent::Disconnect("requested-profile".into()),
            "Disconnecting target",
        );
        let _ = app.update(Message::Observed(
            old,
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
        loaded(&mut app, result);
        assert!(app.download.pending().is_none());
        assert!(
            app.operations.busy(),
            "HTTP completion must not release the NM mutation lock"
        );
        assert_eq!(app.status, "Disconnecting target");
        assert!(app.operations.control().is_some());
        let _ = app.update(Message::Controlled(Ok(())));
        assert!(!app.operations.busy());
        assert!(app.reads.nm.pending().is_some());
        observe_nm(
            &mut app,
            Ok(nm_tunnel_client::Snapshot {
                profiles: vec![],
                active: vec![],
                backend_registered: true,
            }),
        );
        assert!(app.operations.control().is_none());
        assert!(app.status.contains("VPN disconnected"));
    }
    Ok(())
}

#[test]
fn nm_completion_does_not_finish_http_and_http_failure_preserves_nm_notice() {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    begin_download(&mut app);
    app.begin_control(
        super::connection::Intent::Disconnect("target".into()),
        "Disconnecting",
    );
    let _ = app.update(Message::Controlled(Err(ClientError::ControlTimeout)));
    assert!(app.download.pending().is_some());
    assert!(!app.operations.busy());
    let status = app.status.clone();
    loaded(&mut app, Err(SubscriptionError::Download));
    assert_eq!(app.status, status);
    assert!(matches!(app.notice, Some(Notice::Error)));
    assert!(app.download.error().is_some());
}

#[test]
fn added_rows_survive_other_additions_and_only_successful_nm_reads_reconcile_them()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    let body = LIST.replace("trojan://secret@proxy.example:443#Not%20supported", "vless://12345678-1234-4234-8234-123456789abd@proxy.example:443?security=tls&sni=www.example.com#Second");
    loaded(&mut app, Ok(parse_subscription(body.as_bytes())?));
    app.catalog.added.insert(0, "nm-a".into());
    app.catalog.added.insert(1, "nm-b".into());
    for index in [0, 1, 0] {
        let _ = app.update(Message::Select(index));
        assert!(app.selected_added());
        let _ = app.update(Message::Prepare);
        assert!(
            !app.operations.busy(),
            "a previously added row cannot create another profile"
        );
    }
    observe_nm(&mut app, Err(ClientError::Unavailable));
    assert_eq!(
        app.catalog.added.len(),
        2,
        "a failed read proves no removal"
    );
    app.reconcile_added(["nm-b"].into_iter());
    assert!(
        !app.selected_added(),
        "externally removed A is addable again"
    );
    assert!(app.catalog.added.contains_key(&1));
    observe_nm(
        &mut app,
        Ok(nm_tunnel_client::Snapshot {
            profiles: vec![],
            active: vec![],
            backend_registered: true,
        }),
    );
    assert!(
        app.catalog.added.is_empty(),
        "successful empty observation confirms removal"
    );
    app.catalog.added.insert(0, "nm-a".into());
    loaded(&mut app, Err(SubscriptionError::Download));
    assert!(
        app.selected_added(),
        "failed HTTP refresh preserves row identities"
    );
    loaded(&mut app, Ok(parse_subscription(LIST.as_bytes())?));
    assert!(
        app.catalog.added.is_empty(),
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
    assert!(app.operations.begin_add(0));
    begin_download(&mut app);
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
    assert_eq!(app.page, super::Page::Import);
    assert!(app.operations.busy() && app.download.pending().is_some());
    assert_eq!(app.traffic.snapshot.as_ref().map(|s| s.generation), Some(3));
    assert!(app.operations.control().is_none());
}

#[test]
fn native_navigation_owns_primary_selection_without_csd_back_or_page_actions() {
    assert!(
        Flags::default().theme_override().is_none(),
        "ordinary launches must use the toolkit's live system theme and geometry"
    );
    let (mut app, _) = App::init(Core::default(), Flags::default());
    assert_eq!(app.header_start().len(), 1);
    assert!(app.header_center().is_empty());
    assert!(app.header_end().is_empty());
    assert!(app.core.window.header_title.is_empty());
    assert!(!app.core.window.context_is_overlay);
    assert_eq!(
        app.navigation.page(app.navigation.model.active()),
        Some(super::Page::Connections)
    );
    let _ = app.update(Message::Navigate(super::Page::Import));
    assert_eq!(app.header_start().len(), 1);
    assert!(app.header_center().is_empty());
    assert!(app.header_end().is_empty());
    assert!(app.core.window.header_title.is_empty());
    assert_eq!(
        app.navigation.page(app.navigation.model.active()),
        Some(super::Page::Import)
    );
    let _ = app.on_escape();
    assert_eq!(
        app.page,
        super::Page::Import,
        "Escape does not leave a primary section"
    );
    assert_eq!(app.header_start().len(), 1);
    assert!(app.core.window.header_title.is_empty());
    assert!(app.header_end().is_empty());
    assert!(app.operations.control().is_none());
    assert!(!app.operations.busy() && app.download.pending().is_none());
}

#[test]
fn primary_navigation_retains_viewports_drafts_and_the_uncertain_storage_barrier() {
    use cosmic::iced::widget::scrollable::AbsoluteOffset;
    let (mut app, _) = App::init(Core::default(), Flags::default());
    let source = "https://subscriptions.example/synthetic-private-token";
    let _ = app.update(Message::Source(source.into()));
    let _ = app.update(Message::SearchSaved("Home".into()));
    let _ = app.update(Message::ManualDns("invalid-draft".into()));
    assert!(app.operations.begin_add(0));
    assert_eq!(
        app.operations.finish_add(Some(ClientError::Timeout)),
        Some(0)
    );
    let _ = app.update(Message::PageScrolled(
        super::Page::Connections,
        AbsoluteOffset { x: 0.0, y: 240.0 },
    ));
    let _ = app.update(Message::PageScrolled(
        super::Page::Import,
        AbsoluteOffset { x: 0.0, y: 560.0 },
    ));
    let _ = app.update(Message::Navigate(super::Page::Import));
    let _ = app.update(Message::DismissNotice);
    let _ = app.update(Message::Navigate(super::Page::Connections));
    assert_eq!(app.navigation.scroll(super::Page::Connections).y, 240.0);
    assert_eq!(app.navigation.scroll(super::Page::Import).y, 560.0);
    assert_eq!(app.saved_search, "Home");
    assert_eq!(app.options.manual_dns, "invalid-draft");
    assert!(app.operations.uncertain());
    assert!(app.operations.control().is_none());
    assert!(app.download.pending().is_none());
    use secrecy::ExposeSecret;
    assert_eq!(app.download.source().expose_secret(), source);
}

#[test]
fn stale_navigation_entities_cannot_select_a_page_or_finish_work() {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    let mut model = cosmic::widget::nav_bar::Model::default();
    // A removed key's generation is never a valid key in this model.
    let stale = model.insert().text("Removed").id();
    model.remove(stale);
    let stale = model.insert().text("Foreign generation").id();
    assert!(app.operations.begin_add(0));
    let _ = app.on_nav_select(stale);
    assert_eq!(app.page, super::Page::Connections);
    assert!(app.operations.busy());
    assert!(app.operations.control().is_none());
}

#[test]
fn compact_profile_inspection_keeps_parent_selection_and_restores_it_on_close() {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    let _ = app.update(Message::Navigate(super::Page::Import));
    let _ = app.update(Message::ShowDetails(Some("missing-profile".into())));
    // A default Core has no allocated width; opening context takes its compact path.
    assert!(app.core.is_condensed());
    assert!(
        app.details_drawer().is_none(),
        "compact context is a secondary page, not a narrow drawer"
    );
    let _ = app.view();
    let _ = app.on_escape();
    assert!(app.details.is_none());
    assert!(!app.core.window.show_context);
    assert_eq!(app.page, super::Page::Import);
    assert_eq!(
        app.navigation.page(app.navigation.model.active()),
        Some(super::Page::Import)
    );
    assert!(!app.operations.busy());
    assert!(app.download.pending().is_none());
}

#[test]
fn disconnected_or_unknown_nm_never_centers_a_last_attempt_chart() {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    app.traffic.observe(Ok(Some(usage())));
    assert!(!app.show_traffic_chart());
    observe_nm(
        &mut app,
        Ok(nm_tunnel_client::Snapshot {
            profiles: vec![],
            active: vec![],
            backend_registered: true,
        }),
    );
    assert!(!app.show_traffic_chart());
    assert!(
        app.traffic.snapshot.is_some(),
        "last-attempt statistics remain available"
    );
    observe_nm(&mut app, Err(ClientError::Unavailable));
    assert!(!app.show_traffic_chart());
}

#[test]
fn telemetry_updates_are_coalesced_and_do_not_own_nm_or_http_operations() {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    assert!(app.operations.begin_add(0));
    begin_download(&mut app);
    let _ = app.update(Message::Tick);
    let Some(ticket) = app.reads.usage.pending() else {
        panic!("No usage read");
    };
    assert!(app.reads.nm.pending().is_none());
    let _ = app.update(Message::Tick);
    assert_eq!(app.reads.usage.pending(), Some(ticket));
    let _ = app.update(Message::UsageObserved(ticket, Ok(Some(usage()))));
    assert!(app.reads.usage.pending().is_none());
    assert!(app.traffic.live());
    assert!(app.operations.busy() && app.download.pending().is_some());
    let _ = app.poll_usage();
    let Some(old) = app.reads.usage.pending() else {
        panic!("No usage read");
    };
    app.reads.invalidate();
    let _ = app.update(Message::UsageObserved(old, Ok(None)));
    assert!(
        app.traffic.snapshot.is_some(),
        "Stale pre-mutation results do not replace the current observation"
    );
    let _ = app.poll_usage();
    let Some(current) = app.reads.usage.pending() else {
        panic!("No usage read");
    };
    let before = app.reads.clone();
    let _ = app.update(Message::UsageObserved(old, Ok(None)));
    assert_eq!(app.reads, before, "a duplicate cannot release a newer read");
    let _ = app.update(Message::UsageObserved(
        current,
        Err(nm_tunnel_client::UsageError::Unavailable),
    ));
    assert!(!app.traffic.live());
    assert!(
        app.traffic.snapshot.is_none(),
        "Unavailable is not zero usage or old-owner data"
    );
    assert!(app.operations.busy() && app.download.pending().is_some());
    let mut stopped = usage();
    stopped.live = false;
    let _ = app.poll_usage();
    let Some(current) = app.reads.usage.pending() else {
        panic!("No usage read");
    };
    let _ = app.update(Message::UsageObserved(current, Ok(Some(stopped))));
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
    loaded(&mut app, Ok(parse_subscription(LIST.as_bytes())?));
    for index in [1, usize::MAX] {
        let _ = app.update(Message::AddProfile(index));
        assert_eq!(app.catalog.selected, Some(0));
        assert!(!app.operations.busy());
    }
    app.catalog.added.insert(0, "already-added".into());
    let _ = app.update(Message::AddProfile(0));
    assert!(!app.operations.busy());
    let _ = app.update(Message::ConnectProfile("not-an-observed-profile".into()));
    assert!(!app.operations.busy());
    assert!(app.operations.control().is_none());
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
        loaded(&mut app, Ok(parse_subscription(LIST.as_bytes())?));
        assert!(
            app.operations
                .begin_control(super::connection::Intent::Connect(
                    "previous-control".into(),
                ))
        );
        assert!(app.operations.finish_control(true));
        let _ = app.update(Message::Prepare);
        assert!(app.operations.busy());
        assert!(app.operations.control().is_none());
        let _ = app.update(Message::Prepared(Err(error)));
        let failure = app.status.clone();
        observe_nm(
            &mut app,
            Ok(nm_tunnel_client::Snapshot {
                profiles: vec![],
                active: vec![],
                backend_registered: true,
            }),
        );
        assert_eq!(app.status, failure);
        assert_eq!(app.notice.is_none(), error == ClientError::Timeout);
        assert_eq!(app.operations.uncertain(), error == ClientError::Timeout);
    }
    Ok(())
}

#[test]
fn unrelated_nm_completions_preserve_the_dispatched_operation_and_feedback() {
    use super::connection::Intent;
    for phase in ["add", "replace", "control"] {
        let (mut app, _) = App::init(Core::default(), Flags::default());
        match phase {
            "add" => assert!(app.operations.begin_add(3)),
            "replace" => {
                assert!(app.operations.begin_storage().is_some());
            }
            _ => assert!(
                app.operations
                    .begin_control(Intent::Disconnect("target".into()))
            ),
        }
        begin_download(&mut app);
        app.status = "The dispatched action owns this feedback".into();
        app.notice = Some(Notice::Info);
        let reads = app.reads.clone();
        let completions = match phase {
            "add" => vec![
                Message::Profile(super::profile_editor::Action::Saved(
                    super::operations::StorageTicket::test_foreign(),
                    Err(ClientError::Timeout),
                )),
                Message::Controlled(Ok(())),
            ],
            "replace" => vec![
                Message::Prepared(Err(ClientError::Timeout)),
                Message::Controlled(Ok(())),
            ],
            _ => vec![
                Message::Prepared(Err(ClientError::Timeout)),
                Message::Profile(super::profile_editor::Action::Saved(
                    super::operations::StorageTicket::test_foreign(),
                    Err(ClientError::Timeout),
                )),
            ],
        };
        for completion in completions {
            let _ = app.update(completion);
            assert!(app.operations.busy());
            assert!(!app.operations.uncertain());
            assert_eq!(app.operations.control().is_some(), phase == "control");
            assert_eq!(app.status, "The dispatched action owns this feedback");
            assert!(matches!(app.notice, Some(Notice::Info)));
            assert!(app.download.pending().is_some());
            assert!(app.reads.nm.pending().is_none());
            assert_eq!(app.reads, reads);
            assert!(app.catalog.added.is_empty());
        }
    }
}

#[test]
fn unsolicited_nm_completions_cannot_create_feedback_or_storage_uncertainty() {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    let status = app.status.clone();
    for completion in [
        Message::Prepared(Err(ClientError::Timeout)),
        Message::Profile(super::profile_editor::Action::Saved(
            super::operations::StorageTicket::test_foreign(),
            Err(ClientError::Timeout),
        )),
        Message::Controlled(Ok(())),
    ] {
        let _ = app.update(completion);
        assert!(!app.operations.busy());
        assert!(!app.operations.uncertain());
        assert!(app.operations.control().is_none());
        assert!(app.notice.is_none());
        assert_eq!(app.status, status);
        assert!(app.reads.nm.pending().is_none());
        assert!(app.catalog.added.is_empty());
    }
}

#[test]
fn independent_recovery_progress_cannot_complete_nm_http_or_another_read() {
    use nm_tunnel_client::RecoveryStatus;
    let (mut app, _) = App::init(Core::default(), Flags::default());
    assert!(app.operations.begin_add(0));
    begin_download(&mut app);
    let _ = app.poll_usage();
    let _ = app.poll_recovery();
    let Some(usage) = app.reads.usage.pending() else {
        panic!("Missing usage read");
    };
    let Some(recovery) = app.reads.recovery.pending() else {
        panic!("Missing recovery read");
    };
    let reads = app.reads.clone();
    let _ = app.poll_recovery();
    assert_eq!(app.reads, reads);
    let _ = app.update(Message::RecoveryObserved(
        usage,
        Ok(Some(RecoveryStatus::Cleaned)),
    ));
    assert_eq!(app.reads, reads);
    assert!(app.recovery.hint().is_none());
    let _ = app.update(Message::RecoveryObserved(
        recovery,
        Ok(Some(RecoveryStatus::Cleaning)),
    ));
    assert!(
        app.recovery
            .hint()
            .is_some_and(|hint| hint.contains("in progress"))
    );
    assert!(app.operations.busy() && app.download.pending().is_some());
    assert_eq!(app.reads.usage.pending(), Some(usage));
    let _ = app.poll_recovery();
    let Some(old) = app.reads.recovery.pending() else {
        panic!("Missing recovery read");
    };
    app.reads.invalidate();
    let _ = app.update(Message::RecoveryObserved(
        old,
        Ok(Some(RecoveryStatus::Cleaned)),
    ));
    assert!(
        app.recovery
            .hint()
            .is_some_and(|hint| hint.contains("in progress"))
    );
    assert!(app.reads.recovery.pending().is_none());
    assert!(app.operations.busy() && app.download.pending().is_some());
}

#[test]
fn duplicate_download_results_cannot_readmit_old_nodes_or_finish_a_new_download()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut app, _) = App::init(Core::default(), Flags::default());
    let old = begin_download(&mut app);
    let _ = app.update(Message::Loaded(
        old,
        Ok(parse_subscription(LIST.as_bytes())?),
    ));
    assert!(app.catalog.admitted);
    let _ = app.update(Message::Source(
        "https://subscription.example/next-fixture".into(),
    ));
    let _ = app.update(Message::Load);
    let current = app.download.pending().ok_or("No current download")?;
    assert_ne!(old, current);
    assert!(!app.catalog.admitted);
    let status = app.status.clone();
    for result in [
        Ok(parse_subscription(LIST.as_bytes())?),
        Err(SubscriptionError::Download),
    ] {
        let _ = app.update(Message::Loaded(old, result));
        assert_eq!(app.download.pending(), Some(current));
        assert!(!app.catalog.admitted);
        assert!(app.download.error().is_none());
        assert_eq!(app.status, status);
        assert!(app.catalog.added.is_empty());
        assert!(!app.operations.busy());
    }
    let _ = app.update(Message::Loaded(current, Err(SubscriptionError::Download)));
    assert!(app.download.pending().is_none());
    assert_eq!(app.download.error(), Some(SubscriptionError::Download));
    assert!(!app.catalog.admitted);
    assert!(app.catalog.subscription.is_some());
    Ok(())
}
