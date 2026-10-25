//! Workspace dependency policy using cargo_metadata, adapted from Kedra.
use cargo_metadata::{DependencyKind, Metadata, MetadataCommand};

const LAYERS: &[&str] = &[
    "model",
    "engine",
    "integration",
    "client",
    "frontend",
    "tooling",
];

fn allowed(from: &str, to: &str) -> bool {
    match from {
        "model" => to == "model",
        "engine" => matches!(to, "model" | "engine"),
        "integration" => matches!(to, "model" | "engine" | "integration"),
        "client" => matches!(to, "model" | "client"),
        "frontend" => matches!(to, "model" | "client" | "frontend"),
        "tooling" => LAYERS.contains(&to),
        _ => false,
    }
}

pub(crate) fn check() -> crate::Result<String> {
    let metadata = MetadataCommand::new()
        .no_deps()
        .other_options(vec!["--locked".into()])
        .exec()?;
    validate_metadata(&metadata)?;
    Ok(format!(
        "Architecture policy passed for {} workspace package(s).",
        metadata.workspace_members.len()
    ))
}

fn validate_metadata(metadata: &Metadata) -> crate::Result<()> {
    let members = metadata.workspace_packages();
    if members.is_empty() {
        return Err("workspace has no packages".into());
    }
    let mut layers = std::collections::BTreeMap::new();
    for package in &members {
        let layer = package.metadata["nm-tunnel"]["layer"]
            .as_str()
            .ok_or_else(|| format!("{}: missing package.metadata.nm-tunnel.layer", package.name))?;
        if !LAYERS.contains(&layer) {
            return Err(format!("{}: unknown layer {layer}", package.name).into());
        }
        if package.license.as_deref() != Some("MIT OR Apache-2.0") {
            return Err(format!("{}: expected MIT OR Apache-2.0", package.name).into());
        }
        let source = std::fs::read_to_string(&package.manifest_path)?;
        let manifest = source.parse::<toml::Table>()?;
        let inherits = manifest
            .get("lints")
            .and_then(toml::Value::as_table)
            .and_then(|lints| lints.get("workspace"))
            .and_then(toml::Value::as_bool);
        if inherits != Some(true) {
            return Err(format!("{}: must inherit workspace lints", package.name).into());
        }
        layers.insert(package.name.as_str(), layer);
    }
    for package in &members {
        for dependency in &package.dependencies {
            if dependency.kind == DependencyKind::Development {
                continue;
            }
            if let Some(to) = layers.get(dependency.name.as_str())
                && !allowed(layers[package.name.as_str()], to)
            {
                return Err(format!(
                    "forbidden dependency: {} -> {}",
                    package.name, dependency.name
                )
                .into());
            }
        }
    }
    Ok(())
}
