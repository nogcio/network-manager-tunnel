//! Exact locked metadata for human source/license review, never policy authority.
use crate::{Result, output::Session};
use cargo_metadata::{CargoOpt, MetadataCommand};
use std::{collections::BTreeMap, fmt::Write as _, fs};

pub(crate) fn inventory(output: &mut Session) -> Result<()> {
    output.message(
        "+ cargo metadata --locked --all-features (all targets; no secret/profile access)",
    )?;
    let metadata = MetadataCommand::new()
        .features(CargoOpt::AllFeatures)
        .other_options(vec!["--locked".into()])
        .exec()?;
    let mut sources: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut packages: Vec<_> = metadata.packages.iter().collect();
    packages.sort_by_key(|p| (p.name.as_str(), p.version.clone()));
    let mut report = String::from("package\tversion\tsource\tdeclared-license\tmanifest\n");
    for package in &packages {
        let source = package
            .source
            .as_ref()
            .map_or("workspace".into(), |s| s.to_string());
        let license = package.license.as_deref().unwrap_or("MISSING");
        let identity = format!("{}@{}", package.name, package.version);
        if source.starts_with("git+") {
            sources.entry(source.clone()).or_default().push(identity);
        }
        for field in [
            package.name.as_str(),
            license,
            &source,
            package.manifest_path.as_str(),
        ] {
            if field.contains(['\n', '\r', '\t']) {
                return Err("Metadata contains unsupported inventory delimiters.".into());
            }
        }
        writeln!(
            report,
            "{}\t{}\t{source}\t{license}\t{}",
            package.name, package.version, package.manifest_path
        )?;
    }
    fs::create_dir_all("target/xtask")?;
    fs::write("target/xtask/dependency-inventory.tsv", report)?;
    output.message(&format!(
        "{} resolved packages; {} distinct Git source specifications:",
        packages.len(),
        sources.len()
    ))?;
    for (source, members) in sources {
        output.message(&format!("{source}\n  {}", members.join(", ")))?;
    }
    output.message("Inventory: target/xtask/dependency-inventory.tsv. Read exact original license/source files before admission; metadata and inventory success are not audit acceptance.")
}
