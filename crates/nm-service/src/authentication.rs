//! One NM-owned interactive credential request, without resources or storage.
use crate::wire::WorkerConfig;
use std::time::Duration;
use tokio::time::Instant;

pub(crate) struct Pending {
    id: String,
    config: WorkerConfig,
    pub deadline: Instant,
}

impl Pending {
    pub fn new(id: String, mut config: WorkerConfig) -> Self {
        config.secrets.clear();
        Self {
            id,
            config,
            deadline: Instant::now() + Duration::from_secs(120),
        }
    }

    /// Rejection never replaces the admitted configuration or consumes its slot.
    /// Late replies, other identities and edited configurations cannot start work.
    pub fn complete(
        &self,
        id: &str,
        supplied: &WorkerConfig,
    ) -> Result<WorkerConfig, &'static str> {
        if Instant::now() >= self.deadline
            || self.id != id
            || self.config.name != supplied.name
            || self.config.data != supplied.data
            || self.config.persistent != supplied.persistent
        {
            return Err("Credential reply does not match the pending activation.");
        }
        let profile = crate::schema::decode(
            self.config.name.clone(),
            &self.config.data,
            &supplied.secrets,
        )?;
        nm_tunnel_engine::validate_profile(&profile)
            .map_err(|_| "Unsupported engine configuration.")?;
        let mut config = self.config.clone();
        config.secrets.clone_from(&supplied.secrets);
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn credential_replies_are_identity_configuration_and_deadline_bound()
    -> Result<(), Box<dyn std::error::Error>> {
        let settings = crate::test_support::settings()?;
        let (name, data, secrets) = crate::schema::data(&settings)?;
        let mut config = WorkerConfig {
            name,
            data,
            secrets,
            endpoint: "0.0.0.0:0".parse()?,
            lan: Vec::new(),
            persistent: false,
        };
        let pending = Pending::new("connection-one".into(), config.clone());
        assert!(pending.complete("connection-one", &config).is_err());
        config
            .secrets
            .insert("uuid".into(), "12345678-1234-4234-8234-123456789abc".into());
        assert!(pending.complete("connection-two", &config).is_err());
        let mut edited = config.clone();
        edited.data.insert("server".into(), "other.example".into());
        assert!(pending.complete("connection-one", &edited).is_err());
        edited = config.clone();
        edited.persistent = true;
        assert!(pending.complete("connection-one", &edited).is_err());
        let completed = pending.complete("connection-one", &config)?;
        assert_eq!(completed.data, config.data);
        assert_eq!(completed.secrets, config.secrets);
        assert!(
            pending.config.secrets.is_empty(),
            "rejection/completion never mutates the slot"
        );
        tokio::time::advance(Duration::from_secs(120)).await;
        assert!(pending.complete("connection-one", &config).is_err());
        Ok(())
    }
}
