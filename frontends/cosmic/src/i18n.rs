//! Native COSMIC/Fluent localization, selected from the desktop's locale preferences.
//! Catalogs are embedded; no network, settings mutation or application language store.
use i18n_embed::{
    DefaultLocalizer, LanguageLoader, Localizer,
    fluent::{FluentLanguageLoader, fluent_language_loader},
};
use rust_embed::RustEmbed;
use std::sync::LazyLock;

#[derive(RustEmbed)]
#[folder = "i18n/"]
struct Localizations;

pub(crate) static LANGUAGE_LOADER: LazyLock<FluentLanguageLoader> = LazyLock::new(|| {
    let loader = fluent_language_loader!();
    loader
        .load_fallback_language(&Localizations)
        .unwrap_or_else(|_| {
            panic!("The embedded English localization must be valid.");
        });
    loader
});

pub(crate) fn init() {
    let languages = i18n_embed::DesktopLanguageRequester::requested_languages();
    let localizer = DefaultLocalizer::new(&*LANGUAGE_LOADER, &Localizations);
    if localizer.select(&languages).is_err() {
        eprintln!("Desktop localization could not be loaded; using the embedded English fallback.");
    }
}

/// Resolve a compile-time checked Fluent message and its named arguments.
macro_rules! fl {
    ($id:literal) => {
        i18n_embed_fl::fl!($crate::i18n::LANGUAGE_LOADER, $id)
    };
    ($id:literal, $($name:ident = $value:expr),* $(,)?) => {
        i18n_embed_fl::fl!($crate::i18n::LANGUAGE_LOADER, $id, $($name = ($value)),*)
    };
}
pub(crate) use fl;

pub(crate) fn usage_error(error: nm_tunnel_client::UsageError) -> String {
    match error {
        nm_tunnel_client::UsageError::Unavailable => fl!("usage-unavailable"),
        nm_tunnel_client::UsageError::Invalid => fl!("usage-invalid"),
    }
}

pub(crate) fn client_error(error: nm_tunnel_client::ClientError) -> String {
    use nm_tunnel_client::ClientError;
    match error {
        ClientError::Unavailable => fl!("error-nm-unavailable"),
        ClientError::Rejected => fl!("error-nm-rejected"),
        ClientError::Timeout => fl!("error-nm-timeout"),
        ClientError::Stale => fl!("error-nm-stale"),
        ClientError::Control => fl!("error-nm-control"),
        ClientError::ControlTimeout => fl!("error-nm-control-timeout"),
        ClientError::UpdateUnsupported => fl!("error-nm-update-unsupported"),
    }
}

pub(crate) fn subscription_error(error: nm_tunnel_subscription::SubscriptionError) -> String {
    use nm_tunnel_subscription::{PolicyIssue, SubscriptionError};
    match error {
        SubscriptionError::InvalidUrl => fl!("error-url"),
        SubscriptionError::Download => fl!("error-download"),
        SubscriptionError::Timeout => fl!("error-download-timeout"),
        SubscriptionError::TooLarge => fl!("error-source-too-large"),
        SubscriptionError::TooManyEntries => fl!("error-source-too-many"),
        SubscriptionError::Format => fl!("error-source-format"),
        SubscriptionError::FullConfigurationRequired => fl!("error-complete-required"),
        SubscriptionError::UnsupportedPolicy(issue) => match issue {
            PolicyIssue::FakeIp => fl!("error-policy-fakeip"),
            PolicyIssue::Dns => fl!("error-policy-dns"),
            PolicyIssue::Routing => fl!("error-policy-routing"),
            PolicyIssue::ClientIntegration => fl!("error-policy-client"),
            PolicyIssue::Configuration => fl!("error-policy-configuration"),
        },
    }
}

pub(crate) fn dns_error(error: nm_tunnel_profile::DnsOverrideError) -> String {
    match error {
        nm_tunnel_profile::DnsOverrideError::InvalidResolver => fl!("error-resolver"),
        nm_tunnel_profile::DnsOverrideError::IncompatiblePolicy => fl!("error-dns-policy"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluent_syntax::{ast, parser};
    use std::collections::{BTreeMap, BTreeSet, HashMap};

    fn pattern_variables(pattern: &ast::Pattern<&str>, variables: &mut BTreeSet<String>) {
        for element in &pattern.elements {
            if let ast::PatternElement::Placeable { expression } = element {
                expression_variables(expression, variables);
            }
        }
    }

    fn inline_variables(
        expression: &ast::InlineExpression<&str>,
        variables: &mut BTreeSet<String>,
    ) {
        match expression {
            ast::InlineExpression::VariableReference { id } => {
                variables.insert(id.name.to_owned());
            }
            ast::InlineExpression::Placeable { expression } => {
                expression_variables(expression, variables)
            }
            ast::InlineExpression::FunctionReference { arguments, .. }
            | ast::InlineExpression::TermReference {
                arguments: Some(arguments),
                ..
            } => {
                for value in &arguments.positional {
                    inline_variables(value, variables);
                }
                for argument in &arguments.named {
                    inline_variables(&argument.value, variables);
                }
            }
            _ => {}
        }
    }

    fn expression_variables(expression: &ast::Expression<&str>, variables: &mut BTreeSet<String>) {
        match expression {
            ast::Expression::Inline(inline) => inline_variables(inline, variables),
            ast::Expression::Select { selector, variants } => {
                inline_variables(selector, variables);
                for variant in variants {
                    pattern_variables(&variant.value, variables);
                }
            }
        }
    }

    fn catalog_contract(text: &str) -> BTreeMap<String, BTreeSet<String>> {
        let resource =
            parser::parse(text).unwrap_or_else(|_| panic!("Embedded Fluent catalog must parse"));
        let mut messages = BTreeMap::new();
        for entry in resource.body {
            if let ast::Entry::Message(message) = entry {
                let mut variables = BTreeSet::new();
                if let Some(value) = &message.value {
                    pattern_variables(value, &mut variables);
                }
                assert!(
                    message.attributes.is_empty(),
                    "Application messages use explicit IDs"
                );
                assert!(
                    messages
                        .insert(message.id.name.to_owned(), variables)
                        .is_none(),
                    "Duplicate localization ID"
                );
            }
        }
        messages
    }

    #[test]
    fn english_and_russian_catalogs_have_matching_messages_and_arguments() {
        let english = catalog_contract(include_str!("../i18n/en/nm-tunnel-cosmic.ftl"));
        let russian = catalog_contract(include_str!("../i18n/ru/nm-tunnel-cosmic.ftl"));
        assert!(!english.is_empty());
        assert_eq!(
            english, russian,
            "Translations must preserve every message and named argument"
        );
    }

    #[test]
    fn desktop_language_negotiation_falls_back_and_russian_counts_use_plural_rules() {
        let loader = FluentLanguageLoader::new(
            "nm-tunnel-cosmic",
            "en".parse().unwrap_or_else(|_| panic!("Static language")),
        );
        for (requested, expected) in [
            ("de-DE", "Subscriptions"),
            ("en-US", "Subscriptions"),
            ("ru-RU", "Подписки"),
        ] {
            let requested = requested
                .parse()
                .unwrap_or_else(|_| panic!("Static language"));
            i18n_embed::select(&loader, &Localizations, &[requested])
                .unwrap_or_else(|_| panic!("Language selection"));
            assert_eq!(loader.get("subscriptions"), expected);
        }
        for (count, expected) in [
            (1, "1 сервер"),
            (2, "2 сервера"),
            (5, "5 серверов"),
            (21, "21 сервер"),
        ] {
            let text = loader
                .get_args("server-count", HashMap::from([("count", count)]))
                .replace(['\u{2068}', '\u{2069}'], "");
            assert_eq!(text, expected);
        }
        let private_name = "North { $not-a-variable }";
        let rendered = loader.get_args("connect-profile", HashMap::from([("name", private_name)]));
        assert!(
            rendered.contains(private_name),
            "User names are values, never Fluent source"
        );
    }
}
