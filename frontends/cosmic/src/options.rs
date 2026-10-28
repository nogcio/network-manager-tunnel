//! Profile-option state and transitions, independent of widgets, NM and async tasks.
use nm_tunnel_profile::{DnsOverride, DnsOverrideError, Profile};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum DnsChoice {
    #[default]
    Inherit,
    CurrentNetwork,
    Manual,
}

#[derive(Default)]
pub(super) struct ProfileOptions {
    pub dns_choice: DnsChoice,
    pub manual_dns: String,
    pub lan_bypass: bool,
    pub dns_interception: bool,
    pub fake_ip: bool,
}

impl ProfileOptions {
    pub fn dns_override(&self) -> Result<DnsOverride, DnsOverrideError> {
        match self.dns_choice {
            DnsChoice::Inherit => Ok(DnsOverride::Inherit),
            DnsChoice::CurrentNetwork => Ok(DnsOverride::CurrentNetwork),
            DnsChoice::Manual => {
                DnsOverride::from_nm(&format!("proxy-ipv4:{}", self.manual_dns.trim()))
            }
        }
    }

    pub fn intercept(&mut self, enabled: bool) {
        if enabled || !self.fake_ip {
            self.dns_interception = enabled;
        }
    }

    pub fn fake_ip(&mut self, enabled: bool) {
        if !enabled || self.dns_interception {
            self.fake_ip = enabled;
        }
    }

    /// Apply additional opt-ins to a copy, never disable source-required protection.
    /// Invalid combinations leave both the imported profile and options unchanged.
    pub fn apply(&self, profile: &Profile) -> Result<Profile, DnsOverrideError> {
        let mut draft = profile.to_draft();
        draft.dns_override = self.dns_override()?;
        if self.lan_bypass {
            draft.lan_bypass = false;
            draft.private_lan_bypass = true;
        }
        draft.dns_interception |= self.dns_interception;
        draft.fake_ip |= self.fake_ip;
        draft
            .validate()
            .map_err(|_| DnsOverrideError::IncompatiblePolicy)
    }
}
