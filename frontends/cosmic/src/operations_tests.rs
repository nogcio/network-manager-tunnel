use super::*;

#[test]
fn only_the_matching_completion_releases_a_dispatched_operation() {
    let mut operations = Operations::default();
    assert!(operations.begin_add(7));
    assert!(!operations.begin_add(8));
    assert!(operations.begin_storage().is_none());
    assert!(!operations.begin_control(Intent::Connect("other".into())));
    assert!(!operations.finish_storage(StorageTicket(999), Some(ClientError::Timeout)));
    assert!(!operations.finish_control(true));
    assert!(operations.busy());
    assert!(!operations.uncertain());
    assert_eq!(operations.finish_add(None), Some(7));
    assert!(!operations.busy());
    assert_eq!(operations.finish_add(Some(ClientError::Timeout)), None);
    assert!(!operations.uncertain());

    let Some(ticket) = operations.begin_storage() else {
        panic!("Missing storage slot");
    };
    assert_eq!(operations.finish_add(Some(ClientError::Timeout)), None);
    assert!(!operations.finish_control(false));
    assert!(operations.busy());
    assert!(operations.finish_storage(ticket, Some(ClientError::Rejected)));
    assert!(!operations.busy());
    assert!(!operations.uncertain());
}

#[test]
fn control_waits_for_acceptance_then_observation_and_never_claims_optimistic_success() {
    let mut operations = Operations::default();
    assert!(operations.begin_control(Intent::Connect("target".into())));
    assert_eq!(
        operations.observe([("target", ConnectionState::Connected)].into_iter()),
        None
    );
    assert!(operations.busy());
    assert!(!operations.finish_storage(StorageTicket(999), None));
    assert_eq!(operations.finish_add(None), None);
    assert!(operations.finish_control(true));
    assert!(!operations.busy());
    assert!(!operations.finish_control(false));
    assert!(operations.control().is_some());
    assert_eq!(
        operations.observe([("target", ConnectionState::Connecting)].into_iter()),
        None
    );
    assert_eq!(
        operations.observe([("target", ConnectionState::Connected)].into_iter()),
        Some(Outcome::Connected)
    );
    assert!(operations.control().is_none());
}

#[test]
fn indeterminate_storage_blocks_all_storage_but_not_explicit_control() {
    for replace in [false, true] {
        let mut operations = Operations::default();
        if replace {
            let Some(ticket) = operations.begin_storage() else {
                panic!("Missing storage slot");
            };
            assert!(operations.finish_storage(ticket, Some(ClientError::Timeout)));
        } else {
            assert!(operations.begin_add(2));
            assert_eq!(operations.finish_add(Some(ClientError::Timeout)), Some(2));
        }
        assert!(operations.uncertain());
        assert!(!operations.begin_add(3));
        assert!(operations.begin_storage().is_none());
        assert!(operations.begin_control(Intent::Disconnect("target".into())));
        assert!(operations.finish_control(false));
        assert!(operations.uncertain());
        assert!(!operations.busy());
        // Unsolicited completions cannot clear uncertainty either.
        assert!(!operations.finish_storage(StorageTicket(999), None));
        assert_eq!(operations.finish_add(None), None);
        assert!(operations.uncertain());
    }
}

#[test]
fn a_new_explicit_action_supersedes_only_accepted_control_feedback() {
    let mut operations = Operations::default();
    assert!(operations.begin_control(Intent::Connect("old".into())));
    assert!(!operations.begin_add(1));
    assert!(operations.finish_control(true));
    assert!(operations.begin_add(1));
    assert!(operations.control().is_none());
    assert_eq!(operations.observe(std::iter::empty()), None);
    assert_eq!(operations.finish_add(Some(ClientError::Rejected)), Some(1));
    assert!(operations.control().is_none());
    assert!(!operations.uncertain());
}
