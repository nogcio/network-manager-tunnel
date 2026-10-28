//! Read-only provider hints using the existing COSMIC settings rows.
use super::{Message, fl};
use cosmic::{Element, widget};
use nm_tunnel_subscription::{MetadataValue, ProviderMetadata};
use std::time::{SystemTime, UNIX_EPOCH};

fn field<T>(value: &MetadataValue<T>, display: impl FnOnce(&T) -> String) -> String {
    match value {
        MetadataValue::Absent => fl!("provider-not-supplied"),
        MetadataValue::Invalid => fl!("provider-invalid"),
        MetadataValue::Value(value) => display(value),
    }
}

fn expiry(value: Option<u64>, now: Option<u64>) -> String {
    match value {
        None => fl!("provider-not-supplied"),
        Some(0) => fl!("provider-no-expiry"),
        Some(deadline) => match now {
            None => fl!("provider-clock-unavailable"),
            Some(now) if now >= deadline => fl!("provider-expired"),
            Some(now) => {
                let seconds = deadline - now;
                if seconds <= 86_400 {
                    fl!("provider-expires-hours", count = seconds.div_ceil(3600))
                } else {
                    fl!("provider-expires-days", count = seconds.div_ceil(86_400))
                }
            }
        },
    }
}

pub(super) fn view(metadata: &ProviderMetadata) -> Element<'_, Message> {
    let usage = field(&metadata.usage, |usage| {
        usage
            .upload
            .zip(usage.download)
            .and_then(|(u, d)| u.checked_add(d))
            .map_or_else(
                || fl!("provider-not-supplied"),
                super::super::traffic::bytes,
            )
    });
    let quota = field(&metadata.usage, |usage| match usage.total {
        None => fl!("provider-not-supplied"),
        Some(0) => fl!("provider-unlimited"),
        Some(bytes) => super::super::traffic::bytes(bytes),
    });
    let expires = field(&metadata.usage, |usage| {
        expiry(
            usage.expire,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs()),
        )
    });
    let title = field(&metadata.title, Clone::clone);
    let interval = field(&metadata.update_interval_hours, |hours| {
        fl!("provider-interval-hours", count = u32::from(*hours))
    });
    let mut section = widget::settings::section().title(fl!("provider-information"));
    for (label, value) in [
        (fl!("provider-suggested-name"), title),
        (fl!("provider-used"), usage),
        (fl!("provider-quota"), quota),
        (fl!("provider-expiry"), expires),
        (fl!("provider-refresh-hint"), interval),
    ] {
        section = section.add(widget::settings::item(label, widget::text::body(value)));
    }
    section
        .add(widget::text::caption(fl!(
            "provider-information-disclosure"
        )))
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_is_unknown_unlimited_or_expired_without_wrapping() {
        assert_eq!(expiry(None, Some(100)), fl!("provider-not-supplied"));
        assert_eq!(expiry(Some(0), Some(100)), fl!("provider-no-expiry"));
        assert_eq!(expiry(Some(100), Some(100)), fl!("provider-expired"));
        assert_eq!(expiry(Some(99), Some(100)), fl!("provider-expired"));
        assert_eq!(
            expiry(Some(101), Some(100)),
            fl!("provider-expires-hours", count = 1u64)
        );
        assert_eq!(
            expiry(Some(86_501), Some(100)),
            fl!("provider-expires-days", count = 2u64)
        );
        assert_eq!(expiry(Some(100), None), fl!("provider-clock-unavailable"));
    }
}
