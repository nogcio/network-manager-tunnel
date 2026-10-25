//! Public profile contracts use synthetic reserved domains and non-production credentials.
use nm_tunnel_profile::{Draft, Field, Security, Transport, import_vless};
use secrecy::{ExposeSecret, SecretString};

const CREDENTIAL: &str = "12345678-1234-4234-8234-123456789abc";
const KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

fn link() -> String {
    format!(
        "vless://{CREDENTIAL}@proxy.example:443?security=reality&type=tcp&encryption=none&sni=www.example.com&fp=chrome&pbk={KEY}&sid=aabb&flow=xtls-rprx-vision#Example%20profile"
    )
}

#[test]
fn imports_supported_reality_vision_without_losing_fields() -> Result<(), Box<dyn std::error::Error>>
{
    let draft = import_vless(&link())?;
    let profile = draft
        .validate()
        .map_err(|_| "valid imported draft rejected")?;
    let fields = profile.fields();
    assert_eq!(fields.name, "Example profile");
    assert_eq!(fields.server, "proxy.example");
    assert_eq!(fields.credential.expose_secret(), CREDENTIAL);
    assert_eq!(fields.security, Security::Reality);
    assert_eq!(fields.server_name, "www.example.com");
    assert_eq!(fields.public_key, KEY);
    assert_eq!(fields.short_id, "aabb");
    assert!(fields.vision);
    Ok(())
}

#[test]
fn import_rejects_downgrades_unknown_fields_and_duplicate_security() {
    for suffix in [
        "&allowInsecure=1",
        "&security=tls",
        "&spx=%2F",
        "&headerType=http",
        "&unknown=value",
    ] {
        assert!(
            import_vless(&format!(
                "{}{}",
                link().split('#').next().unwrap_or(""),
                suffix
            ))
            .is_err()
        );
    }
    for (from, to) in [
        ("security=reality", "security=none"),
        ("type=tcp", "type=ws"),
        ("encryption=none", "encryption=other"),
        ("xtls-rprx-vision", "unsupported-flow"),
    ] {
        assert!(import_vless(&link().replace(from, to)).is_err());
    }
    assert!(import_vless(&"x".repeat(8193)).is_err());
    assert!(import_vless("https://subscription.example/private").is_err());
}

#[test]
fn supports_ipv6_and_certificate_verified_tls() -> Result<(), Box<dyn std::error::Error>> {
    let draft = import_vless(&format!(
        "vless://{CREDENTIAL}@[2001:db8::1]:8443?security=tls&sni=www.example.com&alpn=h2%2Chttp%2F1.1"
    ))?;
    assert_eq!(draft.server, "2001:db8::1");
    assert_eq!(draft.port, "8443");
    assert_eq!(draft.alpn, "h2,http/1.1");
    assert_eq!(draft.security, Security::Tls);
    assert!(!draft.vision);
    Ok(())
}

#[test]
fn validation_has_field_errors_without_private_values() -> Result<(), Box<dyn std::error::Error>> {
    let mut draft = import_vless(&link())?;
    draft.credential = SecretString::from("private-invalid-credential".to_owned());
    draft.port = "0".into();
    draft.public_key = "invalid-private-input".into();
    draft.short_id = "a".into();
    let errors = draft.validate().err().ok_or("invalid draft accepted")?;
    for field in [
        Field::Credential,
        Field::Port,
        Field::PublicKey,
        Field::ShortId,
    ] {
        assert!(errors.iter().any(|error| error.field == field));
    }
    let diagnostic = format!("{draft:?} {errors:?}");
    assert!(!diagnostic.contains("private-invalid-credential"));
    assert!(!diagnostic.contains("invalid-private-input"));
    Ok(())
}

#[test]
fn reality_key_short_id_and_tls_parameters_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let good = import_vless(&link())?;
    for key in [
        "",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "not-a-key",
    ] {
        let mut draft = good.clone();
        draft.public_key = key.into();
        assert!(draft.validate().is_err());
    }
    for short_id in ["a", "zz", "001122334455667788"] {
        let mut draft = good.clone();
        draft.short_id = short_id.into();
        assert!(draft.validate().is_err());
    }
    let mut draft = good;
    draft.short_id.clear();
    assert!(draft.validate().is_ok());
    draft.security = Security::Tls;
    assert!(
        draft.validate().is_err(),
        "REALITY data must not silently disappear in TLS mode"
    );
    draft.public_key.clear();
    assert!(draft.validate().is_ok());
    Ok(())
}

#[test]
fn blank_draft_and_unsafe_endpoint_input_cannot_be_saved() -> Result<(), Box<dyn std::error::Error>>
{
    assert!(Draft::default().validate().is_err());
    for server in [
        "https://proxy.example",
        "proxy.example:443",
        "proxy.example/path",
        "host with space",
    ] {
        let mut draft = import_vless(&link())?;
        draft.server = server.into();
        assert!(draft.validate().is_err());
    }
    Ok(())
}

#[test]
fn websocket_preserves_path_host_and_tls_sni_independently()
-> Result<(), Box<dyn std::error::Error>> {
    let draft = import_vless(&format!(
        "vless://{CREDENTIAL}@edge.example:443?encryption=none&type=ws&path=%2Fws%3Fmode%3Dtest&host=cdn.example%3A8443&security=tls&sni=certificate.example&fp=firefox#WebSocket"
    ))?;
    assert_eq!(draft.security, Security::Tls);
    assert_eq!(draft.server_name, "certificate.example");
    assert_eq!(draft.fingerprint, "firefox");
    assert!(!draft.vision);
    assert_eq!(
        draft.transport,
        Transport::WebSocket {
            path: "/ws?mode=test".into(),
            host: Some("cdn.example:8443".into())
        }
    );
    assert!(!format!("{:?}", draft.transport).contains("cdn.example"));
    Ok(())
}

#[test]
fn hostname_validation_rejects_different_url_interpretations_without_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let good = import_vless(&link())?;
    for value in ["%70roxy.example", "proxy%2eexample", "b\u{fc}cher.example"] {
        for field in [Field::Server, Field::ServerName] {
            let mut draft = good.clone();
            match field {
                Field::Server => draft.server = value.into(),
                _ => draft.server_name = value.into(),
            }
            let errors = draft.validate().err().ok_or("unsafe hostname accepted")?;
            assert!(errors.iter().any(|error| error.field == field));
            assert_eq!(
                draft.server,
                if field == Field::Server {
                    value
                } else {
                    &good.server
                }
            );
            assert_eq!(
                draft.server_name,
                if field == Field::ServerName {
                    value
                } else {
                    &good.server_name
                }
            );
            assert!(!format!("{errors:?}").contains(value));
        }
    }
    for value in ["Proxy.Example", "xn--bcher-kva.example"] {
        let mut draft = good.clone();
        draft.server = value.into();
        draft.server_name = value.into();
        let profile = draft
            .validate()
            .map_err(|_| "safe ASCII hostname rejected")?;
        assert_eq!(profile.fields().server, value);
        assert_eq!(profile.fields().server_name, value);
    }
    assert!(import_vless(&link().replace("proxy.example", "%70roxy.example")).is_err());
    assert!(
        import_vless(&link().replace("sni=www.example.com", "sni=%2577ww.example.com")).is_err()
    );
    Ok(())
}

#[test]
fn websocket_rejects_h2_alpn_without_rewriting_the_draft() -> Result<(), Box<dyn std::error::Error>>
{
    let base =
        format!("vless://{CREDENTIAL}@edge.example:443?type=ws&security=tls&sni=www.example.com");
    let mut draft = import_vless(&base)?;
    for alpn in ["h2", "h2,http/1.1", "http/1.1,h2"] {
        draft.alpn = alpn.into();
        let errors = draft.validate().err().ok_or("HTTP/2 WebSocket accepted")?;
        assert!(errors.iter().any(|error| error.field == Field::Alpn));
        assert_eq!(draft.alpn, alpn);
        assert!(import_vless(&format!("{base}&alpn={alpn}")).is_err());
    }
    for alpn in ["", "http/1.1"] {
        draft.alpn = alpn.into();
        let profile = draft
            .validate()
            .map_err(|_| "HTTP/1.1 WebSocket rejected")?;
        assert_eq!(profile.fields().alpn, alpn);
    }
    Ok(())
}

#[test]
fn websocket_defaults_are_explicit_and_incompatible_modes_are_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let base =
        format!("vless://{CREDENTIAL}@edge.example:443?type=ws&security=tls&sni=www.example.com");
    assert_eq!(
        import_vless(&base)?.transport,
        Transport::WebSocket {
            path: "/".into(),
            host: None
        }
    );
    for suffix in [
        "&flow=xtls-rprx-vision",
        "&path=relative",
        "&path=%2Fws%0D%0AX-Injected%3Avalue",
        "&path=%2Fws%23fragment",
        "&path=",
        "&host=",
        "&host=bad%0D%0AX-Injected%3Avalue",
        "&host=user%40cdn.example",
        "&host=cdn.example%2Fpath",
    ] {
        assert!(
            import_vless(&format!("{base}{suffix}")).is_err(),
            "unsupported WebSocket fields were admitted"
        );
    }
    let tcp = base.replace("type=ws", "type=tcp");
    assert!(import_vless(&format!("{tcp}&path=%2Fws")).is_err());
    assert!(import_vless(&format!("{tcp}&host=cdn.example")).is_err());
    Ok(())
}
