use super::*;

#[test]
fn failed_or_malformed_guard_observations_cannot_claim_absent_protection() -> io::Result<()> {
    assert!(listed_table(b"permission denied", "nm_tunnel").is_err());
    for bytes in [
        b"{}".as_slice(),
        br#"{"nftables":[{"table":{"name":"nm_tunnel"}}]}"#.as_slice(),
        br#"{"nftables":[{"unknown":{}}]}"#.as_slice(),
    ] {
        assert!(listed_table(bytes, "nm_tunnel").is_err());
    }
    assert!(!listed_table(br#"{"nftables":[]}"#, "nm_tunnel")?);
    assert!(listed_table(
        br#"{"nftables":[{"table":{"family":"inet","name":"nm_tunnel"}}]}"#,
        "nm_tunnel"
    )?);
    assert!(!listed_table(
        br#"{"nftables":[{"table":{"family":"ip","name":"nm_tunnel"}}]}"#,
        "nm_tunnel"
    )?);
    Ok(())
}

#[test]
fn private_dns_redirect_and_physical_exception_are_installed_in_one_owned_table() -> io::Result<()>
{
    let plan = crate::lan::Plan::private()?;
    let rules = guard_program(false, &plan.guard_rule("enp1s0")?, true);
    assert_eq!(rules.matches("table inet nm_tunnel {").count(), 1);
    assert!(rules.contains("type nat hook output priority dstnat"));
    assert!(rules.contains(&format!("meta mark {MARK} return")));
    assert!(rules.contains("udp dport 53 counter dnat ip to 198.18.0.2"));
    assert!(rules.contains("tcp dport 53 counter dnat ip to 198.18.0.2"));
    assert!(rules.contains("meta nfproto ipv6 counter drop"));
    assert!(!guard_program(false, &plan.guard_rule("enp1s0")?, false).contains("dnat"));
    // Input for the explicit isolated kernel adapter probe, never loaded on the host here.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/private-lan");
    std::fs::create_dir_all(&path)?;
    std::fs::write(path.join("guard.nft"), rules + &fakeip_guard_program(false))?;
    Ok(())
}

#[test]
fn session_teardown_is_one_transaction_scoped_to_the_two_owned_tables() {
    assert!(session_teardown_program(false, false).is_empty());
    assert_eq!(
        session_teardown_program(true, false),
        "delete table inet nm_tunnel\n"
    );
    assert_eq!(
        session_teardown_program(false, true),
        "delete table inet nm_tunnel_fakeip\n"
    );
    assert_eq!(
        session_teardown_program(true, true),
        "delete table inet nm_tunnel_fakeip\ndelete table inet nm_tunnel\n"
    );
}

#[test]
fn fakeip_session_guard_blocks_reserved_physical_destinations_not_normal_networking() {
    let rules = fakeip_guard_program(false);
    assert!(rules.contains("policy accept"));
    assert!(rules.contains("ip daddr 198.18.0.0/15 oifname != nmtun0 counter drop"));
    assert!(!rules.contains("meta mark"));
    assert!(!rules.contains("nm_tunnel {"));
    assert!(fakeip_guard_program(true).starts_with("delete table inet nm_tunnel_fakeip\n"));
}

#[test]
fn guard_blocks_tun_injection_into_forwarding_without_restricting_unrelated_interfaces() {
    let rules = guard_program(false, "", false);
    assert!(rules.contains(
        "type filter hook forward priority 0; policy accept;\n  iifname nmtun0 counter drop"
    ));
    assert!(rules.contains("oifname nmtun0 accept"));
    assert!(rules.contains("meta nfproto ipv6 counter drop"));
    assert!(!rules.contains("delete table"));
    assert!(guard_program(true, "", false).starts_with("delete table inet nm_tunnel\n"));
}
