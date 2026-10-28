//! NM owns all saved/active state. Handles are pinned to its bus ID and unique owner.
use crate::{ClientError, TIMEOUT, transport::Bus};
use nm_tunnel_profile::Profile;
use zbus::zvariant::OwnedObjectPath;

mod mutation;
mod observation;
use mutation::Mutation;
use observation::Observation;

/// Non-secret profile identity obtained from NM, not an app-side profile database.
/// Invalid after bus restart or NM owner replacement; no arbitrary-path constructor exists.
#[derive(Clone, PartialEq, Eq)]
pub struct SavedProfile {
    bus_id: String,
    owner: String,
    path: OwnedObjectPath,
    uuid: String,
    name: String,
    persistent: bool,
    dns_override: nm_tunnel_profile::DnsOverride,
    lan_bypass: bool,
    private_lan_bypass: bool,
    dns_interception: bool,
    fake_ip: bool,
    // None for a newly saved/replaced handle or older NM. Replacement requires a
    // fresh, versioned observation; never guess the server's next version ID.
    version_id: Option<u64>,
    source_policy: bool,
}
impl std::fmt::Debug for SavedProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SavedProfile([redacted])")
    }
}
impl SavedProfile {
    /// Independent NM connection UUID, not the authentication UUID.
    pub fn id(&self) -> &str {
        &self.uuid
    }
    /// User-visible NM profile name. Never log it as diagnostic context.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Whether NM reports this profile as saved to its backing storage.
    pub fn persistent(&self) -> bool {
        self.persistent
    }
    /// Last observed per-profile override, without secrets or live DHCP lookup.
    /// CurrentNetwork names the policy, not a persisted resolver address.
    pub fn dns_override(&self) -> nm_tunnel_profile::DnsOverride {
        self.dns_override
    }
    /// Whether this saved profile requests connected RFC1918 uplink bypass.
    /// Does not certify active routes or imply all private-address matching.
    pub fn lan_bypass(&self) -> bool {
        self.lan_bypass
    }
    /// Explicit all-RFC1918 physical bypass, not connected-only metadata or proof
    /// of routing reachability. DNS interception remains an independent policy.
    pub fn private_lan_bypass(&self) -> bool {
        self.private_lan_bypass
    }
    /// Last observed explicit IPv4 TUN port-53 interception mode. Not a claim
    /// about host listeners, encrypted DNS, FakeIP or successful live routing.
    pub fn dns_interception(&self) -> bool {
        self.dns_interception
    }
    /// Stored experimental persistent IPv4 FakeIP mode; not live acceptance or
    /// support for source configurations requiring IPv6 FakeIP.
    pub fn fake_ip(&self) -> bool {
        self.fake_ip
    }
    /// Whether this observation includes the nonzero version required for checked
    /// replacement. This is not authorization or a guarantee that it is still current.
    pub fn checked_update_available(&self) -> bool {
        self.version_id.is_some()
    }
    /// Whether the saved profile carries checked complete native IPv4 policy.
    /// Observation does not prove active routes, XUDP or DNS interoperability.
    pub fn native_source_policy(&self) -> bool {
        self.source_policy
    }
}

/// State observed from NM, never inferred from method-call completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    /// NM is still establishing the connection.
    Connecting,
    /// NM reports an activated connection.
    Connected,
    /// NM is tearing the connection down.
    Disconnecting,
    /// NM returned a state not handled by this client.
    Unknown,
}

/// One active NM object belonging to this service. Multiple objects are reported
/// rather than arbitrarily disconnecting another connection on the user's behalf.
#[derive(Clone)]
pub struct ActiveConnection {
    owner: String,
    path: OwnedObjectPath,
    profile: SavedProfile,
    state: ConnectionState,
}
impl std::fmt::Debug for ActiveConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ActiveConnection([redacted])")
    }
}
impl ActiveConnection {
    /// The corresponding saved profile identity.
    pub fn profile(&self) -> &SavedProfile {
        &self.profile
    }
    /// Last state returned by NM. Refresh after control requests and errors.
    pub fn state(&self) -> ConnectionState {
        self.state
    }
}

/// Read-only NM metadata. Contains no secret lookup and performs no activation.
#[derive(Clone, Debug)]
pub struct Snapshot {
    /// Schema-v1/v2 profiles for this service; unrelated VPNs are excluded.
    pub profiles: Vec<SavedProfile>,
    /// Currently active/activating objects for those profiles.
    pub active: Vec<ActiveConnection>,
    /// D-Bus ownership/activation registration only, not runtime readiness or
    /// protocol compatibility. Checking it never starts the VPN service.
    pub backend_registered: bool,
}

/// Create a persistent NM profile with autoconnect disabled, only on explicit action.
/// Callers must explain that NM saves credentials in its system storage, not a
/// desktop keyring. NM owns authorization, file permissions and secret storage;
/// credentials stay in `vpn.secrets`. Never save automatically on startup/import.
/// Rejection never falls back to memory. Cancellation/timeout can leave a completed
/// remote save: the outcome is indeterminate and must never be retried automatically.
pub async fn save_profile(profile: Profile) -> Result<SavedProfile, ClientError> {
    tokio::time::timeout(TIMEOUT, async {
        Mutation::new(&Bus::system().await?).save(&profile).await
    })
    .await
    .map_err(|_| ClientError::Timeout)?
}
/// Explicitly replace the VPN/IPv4/IPv6 settings of a freshly observed saved profile.
/// Keeps its NM UUID, name, permissions and other connection-level settings; replaces
/// transport, credentials, DNS/routing policy and IP overrides with the supplied
/// validated profile. Callers must disclose those replacements and NM disk secret
/// storage before confirmation. No secrets are retrieved, no VPN is reconnected,
/// and no host routes/DNS/firewall are changed by this client.
///
/// Requires a nonzero NM VersionId from `snapshot` and Update2's version-id check
/// (NM 1.44+). Raced/stale handles reject; unsupported NM never falls back to an
/// unconditional write. Autoconnect is disabled. Active sessions need an explicit
/// reconnect to use the saved policy; success is not live application/readiness.
/// Cancellation/timeout may leave a completed remote update. Never retry or roll
/// back automatically. The returned handle needs a fresh snapshot before reuse
/// for another replacement; no fallible post-write read conceals confirmed success.
pub async fn replace_profile(
    saved: &SavedProfile,
    profile: Profile,
) -> Result<SavedProfile, ClientError> {
    tokio::time::timeout(TIMEOUT, async {
        Mutation::new(&Bus::system().await?)
            .replace(saved, &profile)
            .await
    })
    .await
    .map_err(|_| ClientError::Timeout)?
}

/// Apply a narrow non-secret edit to an observed versioned profile (NM 1.44+).
/// UUID, ACL, transport, all unrelated settings and NM-owned credentials survive.
/// Uses checked Update2 with NO_REAPPLY; never reconnects. The returned handle
/// requires refresh before reuse. Cancellation/deadline/lost replies are unknown
/// storage outcomes: do not retry or roll back automatically.
pub async fn edit_profile(
    saved: &SavedProfile,
    changes: crate::ProfileChanges,
) -> Result<(), ClientError> {
    tokio::time::timeout(TIMEOUT, async {
        Mutation::new(&Bus::system().await?)
            .edit(saved, &changes)
            .await
    })
    .await
    .map_err(|_| ClientError::Timeout)?
}

/// Apply one explicitly mapped subscription candidate, preserving NM UUID/name/ACL,
/// IP settings and compatible saved DNS/LAN/interception/FakeIP overrides. Conflicts
/// reject, never weaken the new mandatory source policy. Source credentials replace
/// old credentials in NM system storage; disclose this before explicit confirmation.
/// Version-checked Update2, 20-second deadline, NO_REAPPLY, no reconnect or retries.
/// This is not a cross-profile transaction. On a lost reply, block further storage.
pub async fn update_from_source(saved: &SavedProfile, profile: Profile) -> Result<(), ClientError> {
    tokio::time::timeout(TIMEOUT, async {
        Mutation::new(&Bus::system().await?)
            .source_update(saved, &profile)
            .await
    })
    .await
    .map_err(|_| ClientError::Timeout)?
}

/// Explicitly delete an inactive, revalidated profile through NM, including its
/// NM-owned credentials. No other profile/source is deleted. Checks observed
/// version and inactivity before dispatch; Delete has no atomic version-id or
/// inactivity argument, so concurrent external activation/edit after that check
/// cannot be excluded. No activation/teardown is requested here. UI must await
/// observed disconnection first. Lost reply/cancellation is an unknown write,
/// never an invitation to retry. Ordinary checks use private buses only.
pub async fn delete_profile(saved: &SavedProfile) -> Result<(), ClientError> {
    tokio::time::timeout(TIMEOUT, async {
        Mutation::new(&Bus::system().await?).delete(saved).await
    })
    .await
    .map_err(|_| ClientError::Timeout)?
}
/// Read profile/active metadata, not credentials; never activates a service/profile.
/// Races/removal return an error, not a fabricated disconnected state.
pub async fn snapshot() -> Result<Snapshot, ClientError> {
    tokio::time::timeout(TIMEOUT, async {
        Observation::new(&Bus::system().await?).snapshot().await
    })
    .await
    .map_err(|_| ClientError::Unavailable)?
}
/// Request activation of an NM-issued handle. Success is request acceptance only;
/// observe `snapshot` for Connected. Cancellation/timeout may leave activation running.
pub async fn activate(profile: &SavedProfile) -> Result<(), ClientError> {
    tokio::time::timeout(TIMEOUT, async {
        Mutation::new(&Bus::system().await?).activate(profile).await
    })
    .await
    .map_err(|_| ClientError::ControlTimeout)?
}
/// Explicitly deactivate only this observed active object. Never clears a firewall
/// guard or chooses another VPN. Completion does not prove resource teardown.
pub async fn deactivate(active: &ActiveConnection) -> Result<(), ClientError> {
    tokio::time::timeout(TIMEOUT, async {
        Mutation::new(&Bus::system().await?)
            .deactivate(active)
            .await
    })
    .await
    .map_err(|_| ClientError::ControlTimeout)?
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
