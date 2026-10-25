# ADR 0005: NetworkManager Tunnel

Status: accepted owner decision. Date: 2026-10-25.

The product name is **NetworkManager Tunnel**. The technical project name is
`network-manager-tunnel`. The name describes native NetworkManager VPN integration,
without tying the product to one supported protocol or implying an Xray-core backend.
Protocol implementation remains library-first through the maintained meow fork.

Apply the name to the app's window/header/about text, desktop display name,
documentation, repository-check diagnostics and subscription HTTP User-Agent.
This is not a claim of completed VPN functionality or affiliation
with the NetworkManager project.

Use `nm-tunnel-*` Cargo packages, `nm_tunnel_*` Rust imports,
`package.metadata.nm-tunnel`, `NM_TUNNEL_*` preview environment variables,
`io.github.nm_tunnel.Cosmic` as the app ID and
`org.freedesktop.NetworkManager.tunnel` as the experimental service identity.
The owner requested a complete technical rename, without compatibility aliases.
Existing experimental installations require package replacement; profiles created
with a different service identity are not silently rewritten or deleted.

Local directory names and Git remotes are not runtime identifiers. Repository
publication and changes to system-installed components require separate authorization.
