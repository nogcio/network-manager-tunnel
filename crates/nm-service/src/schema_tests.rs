use super::*;

#[test]
fn unsupported_ip_overrides_fail_without_changing_settings()
-> Result<(), Box<dyn std::error::Error>> {
    let mut settings = crate::test_support::settings()?;
    assert!(ip_policy(&settings).is_ok());
    settings
        .get_mut("ipv4")
        .ok_or("Missing IPv4")?
        .insert("dns-priority".into(), OwnedValue::from(0_i32));
    assert!(ip_policy(&settings).is_err());
    settings
        .get_mut("ipv4")
        .ok_or("Missing IPv4")?
        .insert("dns-priority".into(), OwnedValue::from(-100_i32));
    settings
        .get_mut("ipv4")
        .ok_or("Missing IPv4")?
        .insert("never-default".into(), OwnedValue::from(true));
    assert!(ip_policy(&settings).is_err());
    assert_eq!(
        settings
            .get("ipv4")
            .and_then(|v| v.get("never-default"))
            .and_then(|v| bool::try_from(v).ok()),
        Some(true)
    );
    settings
        .get_mut("ipv4")
        .ok_or("Missing IPv4")?
        .remove("never-default");
    settings.get_mut("ipv6").ok_or("Missing IPv6")?.insert(
        "method".into(),
        OwnedValue::from(zbus::zvariant::Str::from("auto")),
    );
    assert!(ip_policy(&settings).is_err());
    Ok(())
}

#[test]
fn missing_secret_is_only_permitted_for_need_secrets_validation()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = crate::test_support::settings()?;
    let (name, data, secrets) = data(&settings)?;
    assert!(decode(name.clone(), &data, &secrets, true).is_ok());
    assert!(decode(name.clone(), &data, &secrets, false).is_err());
    let secrets = Strings::from([("uuid".into(), "12345678-1234-4234-8234-123456789abc".into())]);
    assert!(decode(name, &data, &secrets, false).is_ok());
    Ok(())
}

#[test]
fn unknown_schema_and_credentials_in_data_fail_without_private_diagnostics()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = crate::test_support::settings()?;
    let (name, mut data, secrets) = data(&settings)?;
    let before = data.clone();
    data.insert("schema-version".into(), "999".into());
    assert!(decode(name.clone(), &data, &secrets, true).is_err());
    data = before.clone();
    data.insert("uuid".into(), "private-synthetic-value".into());
    let result = decode(name, &data, &secrets, true);
    assert!(result.is_err());
    assert!(!format!("{result:?}").contains("private-synthetic-value"));
    assert_eq!(data.get("server"), before.get("server"));
    Ok(())
}
