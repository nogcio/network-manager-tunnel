//! Checked replacement preserves NM identity; the shared schema owns encoding.
use crate::ClientError;
use nm_tunnel_profile::Profile;
use nm_tunnel_schema::{Settings, encode_profile};

/// Source refresh preserves existing non-secret user overrides and IP settings.
/// A conflict with new mandatory source policy rejects before any NM mutation.
pub(crate) fn source_update_settings(
    mut current: Settings,
    profile: &Profile,
) -> Result<Settings, ClientError> {
    nm_tunnel_schema::ip_policy(&current).map_err(|_| ClientError::Rejected)?;
    let (name, data, _) = nm_tunnel_schema::data(&current).map_err(|_| ClientError::Stale)?;
    let policy = nm_tunnel_schema::decode_policy(&data).map_err(|_| ClientError::Stale)?;
    let mut draft = profile.to_draft();
    draft.name = name;
    if policy.dns_override() != nm_tunnel_profile::DnsOverride::Inherit {
        draft.dns_override = policy.dns_override();
    }
    match policy.lan_bypass() {
        nm_tunnel_profile::LanBypass::None => {}
        nm_tunnel_profile::LanBypass::Connected => {
            draft.lan_bypass = true;
            draft.private_lan_bypass = false;
        }
        nm_tunnel_profile::LanBypass::Private => {
            draft.lan_bypass = false;
            draft.private_lan_bypass = true;
        }
    }
    draft.dns_interception |= policy.intercepts_dns();
    draft.fake_ip |= policy.fake_ip();
    let updated = draft.validate().map_err(|_| ClientError::Rejected)?;
    let encoded = encode_profile(&updated);
    let vpn = encoded
        .values()
        .get("vpn")
        .ok_or(ClientError::Rejected)?
        .iter()
        .map(|(key, value)| {
            value
                .try_to_owned()
                .map(|value| (key.clone(), value))
                .map_err(|_| ClientError::Rejected)
        })
        .collect::<Result<_, _>>()?;
    current.insert("vpn".into(), vpn);
    current
        .get_mut("connection")
        .ok_or(ClientError::Stale)?
        .insert(
            "autoconnect".into(),
            zbus::zvariant::OwnedValue::from(false),
        );
    Ok(current)
}

/// Replace only reviewed VPN/IP sections, keeping connection identity and ACLs.
pub(crate) fn replacement_settings(
    mut current: Settings,
    profile: &Profile,
) -> Result<Settings, ClientError> {
    let encoded = encode_profile(profile);
    for section in ["vpn", "ipv4", "ipv6"] {
        let values = encoded.values().get(section).ok_or(ClientError::Rejected)?;
        let values = values
            .iter()
            .map(|(key, value)| {
                value
                    .try_to_owned()
                    .map(|value| (key.clone(), value))
                    .map_err(|_| ClientError::Rejected)
            })
            .collect::<Result<_, _>>()?;
        current.insert(section.into(), values);
    }
    current
        .get_mut("connection")
        .ok_or(ClientError::Stale)?
        .insert(
            "autoconnect".into(),
            zbus::zvariant::OwnedValue::from(false),
        );
    Ok(current)
}
