//! Real private-bus edit/delete requests and failure paths, never host NM.
use super::*;

fn changes(name: &str) -> crate::ProfileChanges {
    crate::ProfileChanges {
        name: name.into(),
        dns: nm_tunnel_profile::DnsOverride::CurrentNetwork,
        lan: crate::LanBypass::Connected,
        intercept: true,
        fake_ip: false,
    }
}

#[tokio::test]
async fn source_refresh_preserves_user_overrides_and_rejects_conflicts_without_reconnecting()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let (mut daemon, address) = private_bus().await?;
        let server = zbus::connection::Builder::address(address.as_str())?.build().await?;
        let client = zbus::connection::Builder::address(address.as_str())?.build().await?;
        let state = Shared::default(); serve(&server, &state).await?;
        let bus = Bus::on(client).await?;
        let mut original = nm_tunnel_profile::import_vless("vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example#CustomName")?;
        original.private_lan_bypass = true; original.dns_interception = true; original.dns_override = nm_tunnel_profile::DnsOverride::CurrentNetwork;
        let original = original.validate().map_err(|_| "Invalid fixture")?;
        Mutation::new(&bus).save(&original).await?;
        lock(&state)?.active = true;
        let observed = Observation::new(&bus).snapshot().await?.profiles.remove(0);
        let before = lock(&state)?.settings.clone();
        let candidate = nm_tunnel_profile::import_vless("vless://12345678-1234-4234-8234-123456789abd@updated.example:443?security=tls&sni=peer.example#ProviderName")?.validate().map_err(|_| "Invalid candidate")?;
        Mutation::new(&bus).source_update(&observed, &candidate).await?;
        {
            let s = lock(&state)?;
            assert_eq!(s.settings["connection"], before["connection"]);
            assert_eq!(s.settings["ipv4"], before["ipv4"]);
            assert_eq!(s.settings["ipv6"], before["ipv6"]);
            let data = HashMap::<String, String>::try_from(s.settings["vpn"]["data"].try_clone()?)?;
            assert_eq!(data["server"], "updated.example"); assert_eq!(data["dns-override"], "current-network"); assert_eq!(data["lan-bypass"], "private-rfc1918"); assert_eq!(data["dns-interception"], "tun-port53");
            let secrets = HashMap::<String, String>::try_from(s.settings["vpn"]["secrets"].try_clone()?)?;
            assert_eq!(secrets["uuid"], "12345678-1234-4234-8234-123456789abd");
            assert!(s.active); assert_eq!((s.activations, s.deactivations), (0, 0));
        }
        let observed = Observation::new(&bus).snapshot().await?.profiles.remove(0);
        let before = lock(&state)?.settings.clone();
        let mut incompatible = candidate.to_draft(); incompatible.tcp_domain_policy = Some(nm_tunnel_profile::TcpDomainPolicy::from_json(r#"{"version":1,"rules":[{"domain":["blocked.example"],"action":"block"}]}"#)?);
        let incompatible = incompatible.validate().map_err(|_| "Invalid candidate")?;
        assert!(matches!(Mutation::new(&bus).source_update(&observed, &incompatible).await, Err(ClientError::Rejected)));
        assert_eq!(lock(&state)?.settings, before); assert_eq!(lock(&state)?.updates.len(), 1);
        {
            let mut s = lock(&state)?;
            s.settings.get_mut("ipv4").ok_or("Missing IPv4")?.insert("never-default".into(), OwnedValue::from(true));
            s.version_id += 1;
        }
        let observed = Observation::new(&bus).snapshot().await?.profiles.remove(0);
        let unsupported = lock(&state)?.settings.clone();
        assert!(matches!(Mutation::new(&bus).source_update(&observed, &candidate).await, Err(ClientError::Rejected)));
        assert_eq!(lock(&state)?.settings, unsupported); assert_eq!(lock(&state)?.updates.len(), 1);
        daemon.kill().await?; daemon.wait().await?; Ok::<_, Box<dyn std::error::Error>>(())
    }).await?
}

#[tokio::test]
async fn edits_are_narrow_version_checked_nonsecret_and_never_reapply_or_reconnect()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let (mut daemon, address) = private_bus().await?;
        let server = zbus::connection::Builder::address(address.as_str())?.build().await?;
        let client = zbus::connection::Builder::address(address.as_str())?.build().await?;
        let state = Shared::default(); serve(&server, &state).await?;
        let bus = Bus::on(client).await?;
        let profile = nm_tunnel_profile::import_vless("vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example#Original")?.validate().map_err(|_| "Invalid fixture")?;
        Mutation::new(&bus).save(&profile).await?;
        {
            let mut s = lock(&state)?;
            s.active = true;
            s.settings.get_mut("connection").ok_or("Missing connection")?.insert("permissions".into(), zbus::zvariant::Value::from(vec!["user:synthetic:".to_owned()]).try_to_owned()?);
            s.settings.get_mut("ipv4").ok_or("Missing IPv4")?.insert("route-metric".into(), OwnedValue::from(321_i64));
        }
        let observed = Observation::new(&bus).snapshot().await?.profiles.remove(0);
        let before = lock(&state)?.settings.clone();
        let mut invalid = changes("");
        assert!(matches!(Mutation::new(&bus).edit(&observed, &invalid).await, Err(ClientError::Rejected)));
        invalid = changes("Renamed"); invalid.fake_ip = true; invalid.intercept = false;
        assert!(matches!(Mutation::new(&bus).edit(&observed, &invalid).await, Err(ClientError::Rejected)));
        assert_eq!(lock(&state)?.settings, before);
        assert!(lock(&state)?.updates.is_empty());
        Mutation::new(&bus).edit(&observed, &changes("Renamed")).await?;
        {
            let s = lock(&state)?;
            let payload = s.update_payload.as_ref().ok_or("No update payload")?;
            assert!(!payload.values().any(|section| section.contains_key("secrets")));
            assert_eq!(s.settings["vpn"]["secrets"], before["vpn"]["secrets"]);
            assert_eq!(payload["connection"]["uuid"], before["connection"]["uuid"]);
            assert_eq!(payload["connection"]["permissions"], before["connection"]["permissions"]);
            assert_eq!(payload["ipv4"], before["ipv4"]);
            assert_eq!(payload["ipv6"], before["ipv6"]);
            assert_eq!(<&str>::try_from(&payload["connection"]["id"])?, "Renamed");
            let data = HashMap::<String, String>::try_from(payload["vpn"]["data"].try_clone()?)?;
            assert_eq!(data["server"], "proxy.example"); assert_eq!(data["dns-override"], "current-network");
            assert_eq!(s.updates, [0x61]); assert!(s.active);
            assert_eq!((s.activations, s.deactivations), (0, 0));
        }
        assert!(matches!(Mutation::new(&bus).edit(&observed, &changes("Stale")).await, Err(ClientError::Stale)));
        let fresh = Observation::new(&bus).snapshot().await?.profiles.remove(0);
        let before = lock(&state)?.settings.clone(); lock(&state)?.reject_update = true;
        assert!(matches!(Mutation::new(&bus).edit(&fresh, &changes("Refused")).await, Err(ClientError::Rejected)));
        assert_eq!(lock(&state)?.settings, before);
        lock(&state)?.reject_update = false; lock(&state)?.reply_lost = true;
        assert!(matches!(Mutation::new(&bus).edit(&fresh, &changes("Unknown")).await, Err(ClientError::Timeout)));
        assert_eq!(lock(&state)?.updates.len(), 3);
        assert_eq!(<&str>::try_from(&lock(&state)?.settings["connection"]["id"])?, "Unknown");
        daemon.kill().await?; daemon.wait().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    }).await?
}

#[tokio::test]
async fn delete_refuses_active_stale_and_unversioned_handles_and_never_retries_unknown_results()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let (mut daemon, address) = private_bus().await?;
        let server = zbus::connection::Builder::address(address.as_str())?.build().await?;
        let client = zbus::connection::Builder::address(address.as_str())?.build().await?;
        let state = Shared::default(); serve(&server, &state).await?;
        let bus = Bus::on(client).await?;
        let profile = nm_tunnel_profile::import_vless("vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example#Synthetic")?.validate().map_err(|_| "Invalid fixture")?;
        let saved = Mutation::new(&bus).save(&profile).await?;
        assert!(matches!(Mutation::new(&bus).delete(&saved).await, Err(ClientError::UpdateUnsupported)));
        let observed = Observation::new(&bus).snapshot().await?.profiles.remove(0);
        let before = lock(&state)?.settings.clone(); lock(&state)?.active = true;
        assert!(matches!(Mutation::new(&bus).delete(&observed).await, Err(ClientError::Stale)));
        assert_eq!(lock(&state)?.deletes, 0); assert_eq!(lock(&state)?.settings, before);
        lock(&state)?.active = false; lock(&state)?.version_id += 1;
        assert!(matches!(Mutation::new(&bus).delete(&observed).await, Err(ClientError::Stale)));
        let fresh = Observation::new(&bus).snapshot().await?.profiles.remove(0);
        lock(&state)?.reject_delete = true;
        assert!(matches!(Mutation::new(&bus).delete(&fresh).await, Err(ClientError::Rejected)));
        assert_eq!(lock(&state)?.settings, before);
        lock(&state)?.reject_delete = false; lock(&state)?.reply_lost = true;
        assert!(matches!(Mutation::new(&bus).delete(&fresh).await, Err(ClientError::Timeout)));
        assert_eq!(lock(&state)?.deletes, 2); assert!(lock(&state)?.settings.is_empty());
        { let state = lock(&state)?; assert_eq!((state.activations, state.deactivations), (0, 0)); }
        daemon.kill().await?; daemon.wait().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    }).await?
}
