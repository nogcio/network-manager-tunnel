//! Owned nftables session guards, without socket creation, DNS or flow authorization.
use super::MARK;
use crate::dns::INTERNAL_DNS;
use std::{io, time::Duration};
use tokio::{process::Command, time::timeout};

#[cfg(test)]
#[path = "guard_tests.rs"]
mod tests;

pub(crate) async fn guard_present() -> io::Result<bool> {
    table_present("nm_tunnel").await
}

async fn table_present(table: &str) -> io::Result<bool> {
    let mut command = Command::new("/usr/sbin/nft");
    command.args(["-j", "list", "tables"]).kill_on_drop(true);
    let existing = timeout(Duration::from_secs(3), command.output())
        .await
        .map_err(|_| io::Error::other("Guard inspection timeout."))??;
    if !existing.status.success() {
        return Err(io::Error::other("Guard inspection failed."));
    }
    listed_table(&existing.stdout, table)
}

/// A denied/invalid nft observation is not evidence that protection is absent.
fn listed_table(bytes: &[u8], name: &str) -> io::Result<bool> {
    if bytes.len() > 1024 * 1024 {
        return Err(io::Error::other("Oversized guard inspection."));
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| io::Error::other("Invalid guard inspection."))?;
    let entries = value
        .get("nftables")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| io::Error::other("Invalid guard inspection."))?;
    let mut present = false;
    for entry in entries {
        if let Some(table) = entry.get("table") {
            let family = table
                .get("family")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| io::Error::other("Invalid table inspection."))?;
            let table_name = table
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| io::Error::other("Invalid table inspection."))?;
            present |= family == "inet" && table_name == name;
        } else if entry.get("metainfo").is_none() {
            return Err(io::Error::other("Unexpected guard inspection entry."));
        }
    }
    Ok(present)
}

pub(crate) async fn guard_with_lan(
    plan: &crate::lan::Plan,
    interface: &str,
    intercept: bool,
    writer: &mut Option<tokio::process::Child>,
) -> io::Result<()> {
    let rule = plan.guard_rule(interface)?;
    let existing = guard_present().await?;
    let rules = guard_program(existing, &rule, plan.private_bypass() && intercept);
    apply_owned_guard_program(&rules, writer).await
}

async fn apply_guard_program(rules: &str) -> io::Result<()> {
    let mut writer = None;
    let result = apply_owned_guard_program(rules, &mut writer).await;
    if let Some(mut child) = writer {
        crate::task::terminate(&mut child).await?;
    }
    result
}

/// Preparation retains the child outside this cancellable future. A timeout or
/// cancellation is not evidence that an nft writer has exited.
async fn apply_owned_guard_program(
    rules: &str,
    writer: &mut Option<tokio::process::Child>,
) -> io::Result<()> {
    use tokio::io::AsyncWriteExt;
    *writer = Some(
        Command::new("/usr/sbin/nft")
            .args(["-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()?,
    );
    let child = writer
        .as_mut()
        .ok_or_else(|| io::Error::other("Guard writer unavailable."))?;
    let status = timeout(Duration::from_secs(3), async {
        child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("Guard input unavailable."))?
            .write_all(rules.as_bytes())
            .await?;
        child.wait().await
    })
    .await
    .map_err(|_| io::Error::other("Guard update timeout."))??;
    *writer = None;
    if !status.success() {
        return Err(io::Error::other("Guard update failed."));
    }
    Ok(())
}

fn guard_program(existing: bool, lan_rule: &str, private_dns: bool) -> String {
    let mut rules = String::new();
    if existing {
        rules.push_str("delete table inet nm_tunnel\n");
    }
    let dns = if private_dns {
        // Output DNAT reroutes private port-53 queries into our TUN even when NM
        // owns a more-specific physical DNS/gateway host route. Conntrack owns
        // response translation. Root-marked bootstrap/endpoint sockets bypass it.
        format!(
            " chain private_dns {{\n  type nat hook output priority dstnat; policy accept;\n  meta mark {MARK} return\n  ip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }} udp dport 53 counter dnat ip to {INTERNAL_DNS}\n  ip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }} tcp dport 53 counter dnat ip to {INTERNAL_DNS}\n }}\n chain private_dns_egress {{\n  type filter hook postrouting priority 0; policy accept;\n  ct status dnat ip daddr {INTERNAL_DNS} oifname != nmtun0 counter drop\n }}\n"
        )
    } else {
        String::new()
    };
    // Linux can retain the original oif through OUTPUT and reroute only after
    // that hook. Permit only translated DNS here, then check its final egress.
    let translated = if private_dns {
        format!(
            "  ct status dnat ip daddr {INTERNAL_DNS} udp dport 53 accept\n  ct status dnat ip daddr {INTERNAL_DNS} tcp dport 53 accept\n"
        )
    } else {
        String::new()
    };
    rules.push_str(&format!("table inet nm_tunnel {{\n chain output {{\n  type filter hook output priority 0; policy accept;\n  oifname lo accept\n  meta nfproto ipv6 counter drop\n  meta mark {MARK} accept\n  oifname nmtun0 accept\n{translated}{lan_rule}  counter drop\n }}\n chain forward {{\n  type filter hook forward priority 0; policy accept;\n  iifname nmtun0 counter drop\n }}\n{dns}}}\n"));
    rules
}

/// Session-owned synthetic-range protection, removed with the main guard on
/// disconnect or terminal cleanup. No persistence/boot enablement here.
pub(crate) async fn ensure_fakeip_guard() -> io::Result<()> {
    let existing = table_present("nm_tunnel_fakeip").await?;
    apply_guard_program(&fakeip_guard_program(existing)).await
}

pub(crate) async fn ensure_owned_fakeip_guard(
    writer: &mut Option<tokio::process::Child>,
) -> io::Result<()> {
    let existing = table_present("nm_tunnel_fakeip").await?;
    apply_owned_guard_program(&fakeip_guard_program(existing), writer).await
}

fn fakeip_guard_program(existing: bool) -> String {
    let prefix = if existing {
        "delete table inet nm_tunnel_fakeip\n"
    } else {
        ""
    };
    format!(
        "{prefix}table inet nm_tunnel_fakeip {{\n chain output {{\n  type filter hook postrouting priority 0; policy accept;\n  oifname lo accept\n  ip daddr 198.18.0.0/15 oifname != nmtun0 counter drop\n }}\n}}\n"
    )
}

pub(crate) async fn clear_fakeip_guard() -> io::Result<()> {
    if !table_present("nm_tunnel_fakeip").await? {
        return Ok(());
    }
    let status = timeout(
        Duration::from_secs(3),
        Command::new("/usr/sbin/nft")
            .args(["delete", "table", "inet", "nm_tunnel_fakeip"])
            .kill_on_drop(true)
            .status(),
    )
    .await
    .map_err(|_| io::Error::other("FakeIP guard removal deadline."))??;
    if !status.success() {
        return Err(io::Error::other("FakeIP guard removal failed."));
    }
    Ok(())
}

/// Remove both session tables in one nft transaction, after worker/relay teardown.
/// A refused transaction leaves protection intact; no unrelated table is touched.
/// Terminal cleanup and independent orphan recovery use this too. No journal is changed.
pub(crate) async fn clear_session_guards() -> io::Result<()> {
    let main = table_present("nm_tunnel").await?;
    let fakeip = table_present("nm_tunnel_fakeip").await?;
    let rules = session_teardown_program(main, fakeip);
    if !rules.is_empty() {
        apply_guard_program(&rules).await?;
    }
    Ok(())
}

fn session_teardown_program(main: bool, fakeip: bool) -> String {
    let mut rules = String::new();
    if fakeip {
        rules.push_str("delete table inet nm_tunnel_fakeip\n");
    }
    if main {
        rules.push_str("delete table inet nm_tunnel\n");
    }
    rules
}
