# Contributing

Read [AGENTS.md](AGENTS.md) and [architecture](docs/architecture.md) before making
changes. [README](README.md) owns current product status and the documentation map.

## Workflow

1. Agree on substantial architecture, dependency, security or permission changes.
2. Make a focused change with behavior-oriented tests and necessary documentation.
3. Run [the applicable checks](docs/quality.md). Report actual results and limitations.
4. Contributors may commit changes in their own forks and submit a pull request.
   Agents need owner inspection and explicit approval before committing in the
   owner's working copy. Publishing or host networking changes need authorization.

Use the pinned Rust toolchain and Cargo.lock; update dependencies deliberately.
Native build prerequisites are in the [frontend guide](frontends/cosmic/README.md).
Test layout and VM/desktop acceptance rules are maintained in [quality](docs/quality.md).

## Reports and licensing

Reports need a revision, environment, expected/actual behavior and a minimal
synthetic reproduction. Never attach real subscription URLs, credentials or private
node details. See [security reporting](SECURITY.md) for sensitive issues.

Review AI-generated code and disclose material AI assistance in public change
requests; no AI service is required for builds or CI. Contributions use
MIT OR Apache-2.0 unless explicitly stated otherwise. Preserve upstream notices;
see [third-party policy](docs/third-party.md). No CLA is established.
