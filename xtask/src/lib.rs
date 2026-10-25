//! Repository checks adapted from Kedra; see docs/third-party.md.
mod architecture;
mod cli;
mod dependencies;
mod output;

use clap::Parser;
use std::{env, error::Error, path::Path};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// Run explicit repository checks with live diagnostics and retained logs.
///
/// Checks never prompt, install files or change networking.
/// Failed stages stop the plan and return an error; remaining stages are skipped.
pub fn run() -> Result<()> {
    let options = cli::Options::parse();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("workspace root missing")?;
    env::set_current_dir(root)?;
    let stages = options.task.stages();
    let mut output = output::Session::new()?;
    let mut result = Ok(());
    for (index, stage) in stages.iter().enumerate() {
        result = output.stage(
            index + 1,
            stages.len(),
            stage.label(),
            |output| match stage {
                cli::Stage::Dependencies => dependencies::inventory(output),
                cli::Stage::Architecture => output.message(&architecture::check()?),
                cli::Stage::Cargo { args, rustdoc, .. } => output.cargo(args, *rustdoc),
            },
        );
        if result.is_err() {
            break;
        }
    }
    output.finish(stages.len())?;
    result
}
