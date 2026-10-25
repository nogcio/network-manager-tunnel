# Security policy

This project has no supported production release or response-time guarantee.
Current implementation and acceptance limits are in [README](README.md) and the
[service contract](crates/nm-service/README.md); do not assume production privacy guarantees.

## Reporting

A project repository URL and confidential reporting channel have not been
established here. Ask the owner for a verified private channel before sharing
exploit details. Never assume a public issue, chat or CI artifact is confidential.
Include the affected revision, impact and a synthetic minimal reproduction.
Never test against other people's systems or submit real secrets as evidence.

## Trust boundaries

- Imported links, profiles, network peers and D-Bus requests are untrusted inputs.
- GUI/editor code is unprivileged; a desktop toolkit is not a sandbox.
- The service must restrict D-Bus callers, secret access and privileged operations.
- TUN setup is privileged; the protocol worker must not inherit those privileges.
  Ownership and lifecycle are documented in the service contract above.
- Protocol credentials never belong in logs, argv, public fixtures or AI indexes.
- NetworkManager owns normal route/DNS application; the service owns its fail-closed
  guard. A default route is not a kill switch.
- Dependency audits and CI detect some problems; they do not certify security.

See [architecture](docs/architecture.md) and [acceptance plan](docs/roadmap.md).
