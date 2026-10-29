//! Checked replacement preserves NM identity; the shared schema owns encoding.
use crate::ClientError;
use nm_tunnel_profile::Profile;
use nm_tunnel_schema::{Settings, encode_profile_with_options};

pub(crate) fn options(settings: &Settings) -> Result<crate::ProfileOptions, ClientError> {
    let (_, data, _) = nm_tunnel_schema::data(settings).map_err(|_| ClientError::Stale)?;
    let credentials = match data.get("uuid-flags").map(String::as_str) {
        Some("0") => crate::CredentialStorage::System,
        Some("1") => crate::CredentialStorage::Agent,
        Some("2") => crate::CredentialStorage::Ask,
        _ => return Err(ClientError::Stale),
    };
    let persistent = settings
        .get("vpn")
        .and_then(|s| s.get("persistent"))
        .map(|v| bool::try_from(v).map_err(|_| ClientError::Stale))
        .transpose()?
        .unwrap_or(false);
    Ok(crate::ProfileOptions {
        credentials,
        persistent,
    })
}

/// Source refresh preserves existing non-secret user overrides and IP settings.
/// A conflict with new mandatory source policy rejects before any NM mutation.
pub(crate) fn source_update_settings(
    mut current: Settings,
    profile: &Profile,
) -> Result<Settings, ClientError> {
    nm_tunnel_schema::ip_policy(&current).map_err(|_| ClientError::Rejected)?;
    let (name, data, _) = nm_tunnel_schema::data(&current).map_err(|_| ClientError::Stale)?;
    let policy = nm_tunnel_schema::decode_policy(&data).map_err(|_| ClientError::Stale)?;
    let options = options(&current)?;
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
    let encoded = encode_profile_with_options(&updated, options);
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
    let encoded = encode_profile_with_options(profile, options(&current)?);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_updates_and_replacements_never_downgrade_credential_or_recovery_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        let profile = nm_tunnel_profile::import_vless("vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example")?.validate().map_err(|_| "Invalid fixture")?;
        for credentials in [
            crate::CredentialStorage::System,
            crate::CredentialStorage::Agent,
            crate::CredentialStorage::Ask,
        ] {
            let expected = crate::ProfileOptions {
                credentials,
                persistent: true,
            };
            let encoded = encode_profile_with_options(&profile, expected);
            let settings: Settings = encoded
                .values()
                .iter()
                .map(|(section, values)| {
                    let values = values
                        .iter()
                        .map(|(key, value)| Ok((key.clone(), value.try_to_owned()?)))
                        .collect::<Result<_, zbus::zvariant::Error>>()?;
                    Ok((section.clone(), values))
                })
                .collect::<Result<_, zbus::zvariant::Error>>()?;
            let source = source_update_settings(settings.clone(), &profile)?;
            let replacement = replacement_settings(settings, &profile)?;
            assert_eq!(options(&source)?, expected);
            assert_eq!(options(&replacement)?, expected);
        }
        Ok(())
    }
}
