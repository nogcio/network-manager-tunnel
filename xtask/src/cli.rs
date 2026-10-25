//! Explicit, non-interactive repository checks. Packaging belongs to makepkg.
use clap::{Parser, ValueEnum};

#[derive(Parser)]
#[command(
    name = "cargo xtask",
    about = "NetworkManager Tunnel repository checks"
)]
pub(crate) struct Options {
    #[arg(value_enum)]
    pub task: Task,
    /// Compatibility flag; repository checks are always non-interactive.
    #[arg(long)]
    pub non_interactive: bool,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum Task {
    Check,
    Architecture,
    Fmt,
    Lint,
    Test,
    Doc,
    Features,
    Dependencies,
}

pub(crate) enum Stage {
    Dependencies,
    Architecture,
    Cargo {
        label: &'static str,
        args: &'static [&'static str],
        rustdoc: bool,
    },
}

impl Stage {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Dependencies => "Dependency review inventory (not admission)",
            Self::Architecture => "Dependency architecture",
            Self::Cargo { label, .. } => label,
        }
    }
}

impl Task {
    pub fn stages(self) -> Vec<Stage> {
        match self {
            Self::Dependencies => vec![Stage::Dependencies],
            Self::Check => [
                Self::Architecture,
                Self::Fmt,
                Self::Lint,
                Self::Test,
                Self::Doc,
            ]
            .into_iter()
            .flat_map(Self::stages)
            .collect(),
            Self::Architecture => vec![Stage::Architecture],
            Self::Fmt => vec![Stage::Cargo {
                label: "Rust formatting",
                args: &["fmt", "--all", "--", "--check"],
                rustdoc: false,
            }],
            Self::Lint => vec![Stage::Cargo {
                label: "Clippy",
                args: &[
                    "clippy",
                    "--workspace",
                    "--all-targets",
                    "--all-features",
                    "--locked",
                    "--",
                    "-F",
                    "unsafe_code",
                    "-D",
                    "warnings",
                ],
                rustdoc: false,
            }],
            Self::Test => vec![
                Stage::Cargo {
                    label: "Unit and integration tests",
                    args: &[
                        "test",
                        "--workspace",
                        "--all-targets",
                        "--all-features",
                        "--locked",
                    ],
                    rustdoc: false,
                },
                Stage::Cargo {
                    label: "Documentation tests",
                    args: &["test", "--workspace", "--doc", "--all-features", "--locked"],
                    rustdoc: false,
                },
            ],
            Self::Doc => vec![Stage::Cargo {
                label: "API documentation",
                args: &[
                    "doc",
                    "--workspace",
                    "--no-deps",
                    "--all-features",
                    "--locked",
                ],
                rustdoc: true,
            }],
            Self::Features => vec![Stage::Cargo {
                label: "Default features (no preview)",
                args: &["check", "--workspace", "--all-targets", "--locked"],
                rustdoc: false,
            }],
        }
    }
}
