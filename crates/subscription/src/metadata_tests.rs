use super::*;
use reqwest::header::HeaderValue;

fn metadata(name: &'static str, value: &str) -> ProviderMetadata {
    let mut headers = HeaderMap::new();
    headers.insert(
        name,
        HeaderValue::from_bytes(value.as_bytes())
            .unwrap_or_else(|_| panic!("Synthetic header must be valid HTTP bytes")),
    );
    ProviderMetadata::from_headers(&headers)
}

#[test]
fn omitted_partial_zero_and_exhausted_values_are_distinct() {
    assert_eq!(
        ProviderMetadata::from_headers(&HeaderMap::new()),
        ProviderMetadata::default()
    );
    for (text, expected) in [
        (
            "upload=12; download=23; total=30; expire=1800000000",
            ProviderUsage {
                upload: Some(12),
                download: Some(23),
                total: Some(30),
                expire: Some(1_800_000_000),
            },
        ),
        (
            "total=0; expire=0",
            ProviderUsage {
                upload: None,
                download: None,
                total: Some(0),
                expire: Some(0),
            },
        ),
        (
            "Download = 0",
            ProviderUsage {
                upload: None,
                download: Some(0),
                total: None,
                expire: None,
            },
        ),
    ] {
        assert_eq!(
            metadata("subscription-userinfo", text).usage,
            MetadataValue::Value(expected)
        );
    }
}

#[test]
fn ambiguous_or_malformed_usage_is_not_reported_as_zero() {
    for text in [
        "",
        "upload=-1",
        "upload=+1",
        "upload=1.5",
        "upload=NaN",
        "upload=1e3",
        "upload=18446744073709551616",
        "upload=1;Upload=2",
        "upload=1;",
        "unknown=1",
        "expire=253402300800",
        "upload=18446744073709551615;download=1",
        "upload=12;download=invalid-private-token",
    ] {
        let parsed = metadata("subscription-userinfo", text);
        assert_eq!(parsed.usage, MetadataValue::Invalid, "{text}");
        assert!(!format!("{parsed:?}").contains("private-token"));
    }
}

#[test]
fn header_duplicates_and_limits_do_not_select_an_arbitrary_value() {
    for name in [
        "subscription-userinfo",
        "profile-title",
        "profile-update-interval",
    ] {
        let mut headers = HeaderMap::new();
        headers.append(name, HeaderValue::from_static("1"));
        headers.append(name, HeaderValue::from_static("2"));
        let parsed = ProviderMetadata::from_headers(&headers);
        assert!(format!("{parsed:?}").contains("Invalid"));
        let parsed = metadata(name, &"x".repeat(1025));
        assert!(format!("{parsed:?}").contains("Invalid"));
    }
}

#[test]
fn titles_are_bounded_redacted_and_never_interpreted_as_urls() {
    for title in [
        "Synthetic provider",
        "Провайдер",
        "https://example.invalid/not-fetched",
    ] {
        for value in [
            title.to_owned(),
            format!("base64:{}", STANDARD.encode(title)),
        ] {
            let parsed = metadata("profile-title", &value);
            assert_eq!(parsed.title, MetadataValue::Value(title.to_owned()));
            assert!(!format!("{parsed:?}").contains(title));
        }
    }
    for title in [
        "".into(),
        "x".repeat(129),
        "base64:%%%".into(),
        format!("base64:{}", STANDARD.encode("bad\nname")),
        "bad\u{202e}name".into(),
    ] {
        assert_eq!(
            metadata("profile-title", &title).title,
            MetadataValue::Invalid
        );
    }
}

#[test]
fn refresh_hints_cannot_request_zero_or_unbounded_frequency() {
    for (text, expected) in [("1", 1), ("24", 24), ("720", 720)] {
        assert_eq!(
            metadata("profile-update-interval", text).update_interval_hours,
            MetadataValue::Value(expected)
        );
    }
    for text in ["0", "721", "-1", "1.5", "1,2", "18446744073709551615"] {
        assert_eq!(
            metadata("profile-update-interval", text).update_interval_hours,
            MetadataValue::Invalid
        );
    }
}
