use nm_tunnel_profile::{DnsHandling, LanBypass, PeerSecurity, UdpMode, import_vless};

#[test]
fn executable_components_are_typed_owned_and_redacted() -> Result<(), Box<dyn std::error::Error>> {
    let mut draft = import_vless(
        "vless://12345678-1234-4234-8234-123456789ABC@192.0.2.1:443?security=reality&sni=Peer.Example&pbk=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE&sid=AABB&alpn=h2%2Chttp%2F1.1",
    )?;
    draft.port = "00443".into();
    draft.dns_interception = true;
    draft.fake_ip = true;
    let profile = draft.validate().map_err(|_| "Invalid fixture")?;
    let node = profile.node();
    assert_eq!(node.endpoint().port(), 443);
    assert_eq!(node.endpoint().ipv4(), Some("192.0.2.1".parse()?));
    assert_eq!(node.server_name(), "Peer.Example");
    assert_eq!(node.alpn(), &["h2", "http/1.1"]);
    assert_eq!(node.udp_mode(), UdpMode::Bound);
    let PeerSecurity::Reality(reality) = node.security() else {
        return Err("REALITY lost".into());
    };
    assert_eq!(reality.public_key(), &[1; 32]);
    assert_eq!(reality.short_id(), &[0xaa, 0xbb]);
    assert_eq!(profile.network().dns_handling(), DnsHandling::FakeIp);
    assert_eq!(profile.lan_bypass(), LanBypass::None);
    let cloned = profile.clone();
    drop(profile);
    assert_eq!(
        cloned.credential().expose_uuid(),
        uuid::Uuid::parse_str("12345678-1234-4234-8234-123456789abc")?.as_bytes()
    );
    for debug in [
        format!("{cloned:?}"),
        format!("{:?}", cloned.node()),
        format!("{:?}", cloned.credential()),
        format!("{:?}", cloned.network()),
    ] {
        for sensitive in ["192.0.2.1", "Peer.Example", "12345678", "aabb", "AABB"] {
            assert!(!debug.contains(sensitive));
        }
    }
    let editable = cloned.to_draft();
    assert_eq!(editable.port, "443");
    assert_eq!(editable.short_id, "aabb");
    assert!(editable.validate().is_ok());
    Ok(())
}

#[test]
fn rejected_edits_do_not_mutate_a_compiled_profile_or_its_policy()
-> Result<(), Box<dyn std::error::Error>> {
    let profile = import_vless("vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example")?.validate().map_err(|_| "Invalid fixture")?;
    let mut edited = profile.to_draft();
    edited.fake_ip = true;
    assert!(edited.validate().is_err());
    assert_eq!(profile.network().dns_handling(), DnsHandling::Passthrough);
    edited.fake_ip = false;
    edited.lan_bypass = true;
    edited.private_lan_bypass = true;
    assert!(edited.validate().is_err());
    assert_eq!(profile.network().lan_bypass(), LanBypass::None);
    assert_eq!(profile.node().endpoint().port(), 443);
    assert!(matches!(profile.node().security(), PeerSecurity::Tls));
    Ok(())
}
