//! Narrow non-secret profile edits; transport, identity and credentials are not editable.
use crate::{LanBypass, Settings, data, decode_configuration};
use nm_tunnel_profile::DnsOverride;
use zbus::zvariant::{OwnedValue, Value};

/// User-editable saved settings, not an executable profile or a secret container.
/// Applied only to freshly revalidated NM settings. Source requirements cannot be
/// disabled; errors leave the supplied dictionary unchanged by taking ownership.
#[derive(Clone, PartialEq, Eq)]
pub struct ProfileChanges {
    /// Display name, checked with the shared configuration validator.
    pub name: String,
    /// Resolver selection; never stores a DHCP resolver snapshot.
    pub dns: DnsOverride,
    /// Keep old connected-only mode distinct from explicit broad private bypass.
    pub lan: LanBypass,
    /// Optional interception, or required by the admitted source policy.
    pub intercept: bool,
    /// Persistent IPv4 identities; requires interception.
    pub fake_ip: bool,
}

impl std::fmt::Debug for ProfileChanges {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProfileChanges([redacted])")
    }
}

impl ProfileChanges {
    /// Validate and patch only the display name and reviewed network policy keys.
    /// No credentials are required or manufactured. Returned settings have no
    /// secrets, so NM retains its existing secrets according to Update2 semantics.
    /// Unrelated settings, permissions and UUID are preserved. Autoconnect is off.
    pub fn apply(&self, mut current: Settings) -> Result<Settings, &'static str> {
        let (name, mut values, secrets) = data(&current)?;
        if !secrets.is_empty()
            || current
                .values()
                .any(|section| section.contains_key("secrets"))
        {
            return Err("Profile editing requires a non-secret NM observation.");
        }
        let configuration = decode_configuration(name, &values)?;
        let fields = configuration.fields();
        if fields.source_policy.is_some()
            && ((fields.dns_interception && !self.intercept) || (fields.fake_ip && !self.fake_ip))
        {
            return Err("Required source DNS interception and FakeIP cannot be disabled.");
        }
        for key in [
            "dns-override",
            "lan-bypass",
            "dns-interception",
            "dns-fakeip",
        ] {
            values.remove(key);
        }
        if let Some(dns) = self.dns.to_nm() {
            values.insert("dns-override".into(), dns);
        }
        match self.lan {
            LanBypass::None => {}
            LanBypass::Connected => {
                values.insert("lan-bypass".into(), "connected-rfc1918".into());
            }
            LanBypass::Private => {
                values.insert("lan-bypass".into(), "private-rfc1918".into());
            }
        }
        if self.intercept {
            values.insert("dns-interception".into(), "tun-port53".into());
        }
        if self.fake_ip {
            values.insert("dns-fakeip".into(), "persistent-ipv4-v1".into());
        }
        values.insert(
            "schema-version".into(),
            if values.keys().any(|key| {
                matches!(
                    key.as_str(),
                    "tcp-domain-policy"
                        | "dns-override"
                        | "lan-bypass"
                        | "dns-interception"
                        | "dns-fakeip"
                        | "source-policy"
                )
            }) {
                "2"
            } else {
                "1"
            }
            .into(),
        );
        decode_configuration(self.name.clone(), &values)?;
        let connection = current
            .get_mut("connection")
            .ok_or("Missing connection settings.")?;
        connection.insert(
            "id".into(),
            Value::from(self.name.clone())
                .try_to_owned()
                .map_err(|_| "Invalid name.")?,
        );
        connection.insert("autoconnect".into(), OwnedValue::from(false));
        current
            .get_mut("vpn")
            .ok_or("Missing VPN settings.")?
            .insert(
                "data".into(),
                Value::from(values)
                    .try_to_owned()
                    .map_err(|_| "Invalid VPN data.")?,
            );
        Ok(current)
    }
}
