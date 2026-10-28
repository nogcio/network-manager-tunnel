use nm_tunnel_engine::QuicHostname;

fn initial() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let hex: String = include_str!("../fixtures/rfc9001-client-initial.hex")
        .split_whitespace()
        .collect();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(Into::into))
        .collect()
}

#[test]
fn public_initial_is_inspected_without_modifying_replay_bytes_or_exposing_state()
-> Result<(), Box<dyn std::error::Error>> {
    let bytes = initial()?;
    let before = bytes.clone();
    let mut inspector = QuicHostname::default();
    assert!(QuicHostname::initial(&bytes));
    assert_eq!(inspector.inspect(&bytes).as_deref(), Some("example.com"));
    assert_eq!(bytes, before);
    assert!(!format!("{inspector:?}").contains("example.com"));
    Ok(())
}

#[test]
fn malformed_unknown_version_changed_dcid_and_datagram_budget_never_yield_a_name()
-> Result<(), Box<dyn std::error::Error>> {
    let bytes = initial()?;
    for length in [0, 1, 5, 17, 100, bytes.len() - 1] {
        assert!(QuicHostname::default().inspect(&bytes[..length]).is_none());
    }
    let mut corrupt = bytes.clone();
    let last = corrupt.last_mut().ok_or("Empty fixture")?;
    *last ^= 1;
    assert!(QuicHostname::default().inspect(&corrupt).is_none());
    let mut unknown = bytes.clone();
    unknown[1..5].copy_from_slice(&[0xff; 4]);
    assert!(!QuicHostname::initial(&unknown));
    assert!(QuicHostname::default().inspect(&unknown).is_none());
    let mut exhausted = QuicHostname::default();
    for _ in 0..4 {
        assert!(exhausted.inspect(&[]).is_none());
    }
    assert!(exhausted.inspect(&bytes).is_none());
    let mut other_dcid = bytes.clone();
    other_dcid[6] ^= 1;
    let mut inspector = QuicHostname::default();
    assert!(inspector.inspect(&other_dcid).is_none());
    assert!(inspector.inspect(&bytes).is_none());
    Ok(())
}
