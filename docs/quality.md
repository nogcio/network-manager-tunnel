# Quality and test ownership

Checks validate repository policy, shared profile logic and editor state, not a VPN.
No passing unit/build check establishes protocol interoperability or native desktop support.

## Local checks

```sh
cargo xtask check --non-interactive
cargo xtask features --non-interactive
```

`check` runs workspace architecture, rustfmt, Clippy (warnings as
errors with independent `-F unsafe_code`), unit/integration tests, doctests and
rustdoc. Every Cargo child uses locked resolution except formatting. Stages stream
diagnostics to stdout and `target/xtask/logs/`; failure stops the plan and reports
remaining stages as skipped. Commands never prompt, including on a terminal.

`features` checks the ordinary workspace build without the opt-in UI `preview`.
`check` already tests all features. There is no separate no-default-features run:
the current workspace defaults are empty. State tests need native build libraries,
not a running display. Add feature variants only when they exercise different code.

The following tools are pinned in CI and can be installed locally at the same versions:

| Tool | Version | Invocation |
| --- | --- | --- |
| cargo-deny | 0.19.0 | `cargo deny --locked check --warn unmaintained` |
| cargo-llvm-cov | 0.7.1 | `cargo llvm-cov --workspace --all-targets --all-features --locked --lcov --output-path target/coverage.lcov` |
| rumdl | 0.3.0 | `rumdl check .` |
| Lychee | 0.24.2 | `lychee --offline --include-fragments --no-progress --root-dir "$PWD" './*.md' docs crates frontends` |
| Gitleaks | 8.24.2 | `gitleaks git --redact --no-banner .` |
| actionlint | 1.7.12 | `actionlint -color` |
| zizmor | 1.31.1 | `zizmor --offline --no-progress .github/workflows` |

Coverage is an optional, manually dispatched [workflow](../.github/workflows/coverage.yml),
not a dependency of **CI required**. It has no percentage threshold; a measurement
failure still fails that workflow. `llvm-tools-preview` is required.
Gitleaks's Git mode scans history;
for local uncommitted/untracked changes also run `gitleaks dir --redact --no-banner .`
with generated directories excluded by an explicit command if necessary, not by
weakening detector policy. An empty Git history cannot prove historical cleanliness.
Lychee's offline mode checks local links/fragments, not external source availability.

## File and dependency policy

Keep source modules readable and split by responsibility. There is no universal
file-size/line-count gate, asset restriction or Git requirement for source archives.

`cargo_metadata` owns manifest/dependency parsing. All packages inherit workspace
lints, declare an allowed layer and use the project license. Production edges
include build/optional/renamed/inactive target dependencies; development edges are
not runtime boundaries. External toolkit/privilege boundaries require code review.

`deny.toml` has no inherited Kedra exceptions. Original license evidence and
package-scoped license admissions are documented in
[dependency review](dependency-review.md). Cargo.lock owns resolved versions and
commits; there is no separate Git-commit allowlist. Duplicate versions and
unmaintained components produce visible warnings for practical assessment, not
automatic rejection. Known vulnerabilities and license/source failures still
block the standard audit. See [ADR 0009](decisions/0009-locked-git-source-admission.md).
An advisory exception still requires rationale and review, not silent suppression.
`about.toml` is notice-collection policy, not a shipping notice generator.

## Test design

- Private invariants stay with the production owner. Public API contracts use
  `tests/contracts.rs` and named behavioral modules under `tests/contracts/`.
- Fixtures belong in narrow support modules, never another suite; do not widen
  APIs for test convenience or duplicate upstream library behavior.
- Policy tests cover forbidden boundaries and malformed/failure cases.
- Thin orchestration is exercised through real commands, not a parallel test framework.
- Do not add tests of packaging file text or tests of test/probe scripts. Validate
  packaging through makepkg, package inspection and authorized installation.
- No arbitrary coverage/count quotas. Failures must have observable contract impact.
- Negative runtime tests check unchanged state, resource ownership and cleanup.
- Every potentially blocking external probe has a process deadline and readiness check.

Product tests will be added in increasing cost order: pure model tests, isolated
protocol peers, disposable NM VMs and native desktop acceptance. They are not run
implicitly on the contributor's live network. See [roadmap](roadmap.md).

## Review and reporting

Report exact commands, revision/environment, actual outcomes, skips and risks.
Never relabel missing peers, hardware, tools or CI jobs as success. Instructions,
security policy and workflow edits require explicit review. AI review cannot be
the only approver. Hosted results and branch protection must be checked separately.
