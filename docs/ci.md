# CI

[CI](../.github/workflows/ci.yml) runs on pull requests, main pushes, merge groups
and manual dispatch. It validates source/build behavior, not a live VPN or desktop
session. Local commands and tool versions are in [quality](quality.md);
[README](../README.md) owns product status.

## Required jobs

| Job | Checks |
| --- | --- |
| `rust` | Repository policy, formatting, Clippy, tests, docs and ordinary feature build |
| `supply-chain` | Locked advisories, licenses and source policy |
| `repository` | Markdown and offline links |
| `secrets` | Checked-out Git history, with redaction |
| `workflows` | actionlint and offline zizmor |

**CI required** depends on these five jobs. Its inline shell check runs with
`always()` and requires every result to be `success`; failures, cancellations and
skips fail the gate. The workflow `needs` list is the only list of required jobs.
There is no separate Python checker or matching job list to maintain.

[Coverage](../.github/workflows/coverage.yml) is a separate, manually dispatched
workflow. A missing report or failed measurement fails that run, not ordinary CI.

## Security and hosting

Workflows have read-only permissions; checkouts do not persist credentials. No
publishing, privileged networking, private services or secret-bearing test profiles
are configured. Public native build dependencies are installed on disposable runners.
Tools are versioned with checksum verification. Actions use owner-requested major
tags; ref-pin exceptions remain scoped in `.github/zizmor.yml`.

To use **CI required** for branch protection, verify its hosted name/results first.
Hosted CI, branch protection, signing and release hosting have not been verified
here. Protocol/NM VM and native desktop acceptance remain separate from these jobs.
