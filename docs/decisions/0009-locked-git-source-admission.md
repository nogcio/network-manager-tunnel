# ADR 0009: Practical locked dependency checks

Status: accepted.
Date: 2026-10-25.

## Decision

- Cargo.lock is the single record of resolved versions, Git commits and registry
  checksums. Build, test, documentation and audit commands use `--locked`.
- Do not require `rev` in transitive upstream manifests, fork toolkits to add it,
  or maintain a second commit allowlist. Review manifest and lockfile changes
  together when updating dependencies. Direct Git dependencies remain pinned.
- Keep cargo-deny's unknown repository/registry rejection and license checks.
  Preserve third-party notices and satisfy applicable distribution conditions;
  passing a scanner is not a replacement for those obligations.
- Duplicate versions are warnings, not automatic blockers. Incompatible version
  lines are normal in a desktop dependency graph; reduce them when it benefits
  compatibility, maintenance or binary size, not just to satisfy a count.
- Invoke `cargo deny --locked check --warn unmaintained` in CI and packaging.
  Abandonment remains visible for risk assessment, but is not itself proof of a
  vulnerability. Known vulnerability findings retain their error severity; do not
  ignore advisory IDs or disable advisory fetching to get a passing audit.
- Retain repository, feature and host-safety checks. Do not equate dependency-check
  success with complete notices, desktop acceptance or safe VPN operation.

## Rationale and limits

Separate Git-commit approval would duplicate Cargo.lock and introduce maintenance
without solving a product problem. Maintenance risks and original license evidence
are described in [dependency review](../dependency-review.md);
updates or replacements require a practical benefit and compatibility assessment.

Cargo-deny 0.19 configures unmaintained scope, not warning severity, so the standard
invocation uses its supported `--warn unmaintained` override. Running cargo-deny
without this flag retains its default error severity for those findings. New
unmaintained diagnostics must be assessed, even when the command exits successfully.

Human review of source changes is the trust boundary. Locked resolution guarantees
identity, not source safety or availability. Complete distribution notices and
runtime/desktop acceptance remain separate requirements before shipping supported
executables, not gates on publishing this project's experimental source.
