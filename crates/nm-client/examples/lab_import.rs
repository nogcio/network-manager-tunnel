//! Explicit live-subscription import for the authorized disposable VM only.
use std::io::Read;
use std::time::Duration;

fn read_source(input: impl Read + Send + 'static, deadline: Duration) -> std::io::Result<String> {
    // A detached std thread, unlike Tokio's blocking stdin reader, does not keep
    // the process alive after main returns on timeout. Never join a blocked read.
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new().spawn(move || {
        let mut source = String::new();
        let result = match input.take(4097).read_to_string(&mut source) {
            Ok(_) if source.len() <= 4096 => Ok(source),
            Ok(_) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Subscription source exceeds the input limit.",
            )),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Subscription source could not be read.",
            )),
        };
        let _ = sender.send(result);
    })?;
    receiver.recv_timeout(deadline).map_err(|error| {
        let kind = match error {
            std::sync::mpsc::RecvTimeoutError::Timeout => std::io::ErrorKind::TimedOut,
            std::sync::mpsc::RecvTimeoutError::Disconnected => std::io::ErrorKind::UnexpectedEof,
        };
        std::io::Error::new(
            kind,
            "Subscription source was not received before the deadline.",
        )
    })?
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !std::path::Path::new("/run/nmt-lab-authorized").is_file() {
        return Err("This command is restricted to the explicitly authorized lab VM.".into());
    }
    let args: Vec<_> = std::env::args().skip(1).collect();
    let (format, remaining) = if args.first().is_some_and(|arg| arg == "--nodes-only") {
        (
            nm_tunnel_subscription::SubscriptionFormat::NodesOnly,
            &args[1..],
        )
    } else {
        (
            nm_tunnel_subscription::SubscriptionFormat::Complete,
            args.as_slice(),
        )
    };
    let replacement = match remaining {
        [] => None,
        [flag, id, entry_flag, entry] if flag == "--replace" && entry_flag == "--entry" => {
            let id = uuid::Uuid::parse_str(id)
                .map_err(|_| "Expected an independent NM connection UUID, not a credential.")?;
            let entry = entry
                .parse::<usize>()
                .ok()
                .filter(|entry| *entry > 0)
                .ok_or("Expected a one-based source entry number.")?;
            Some((id.to_string(), entry - 1))
        }
        _ => {
            return Err(
                "Expected [--nodes-only] [--replace NM_CONNECTION_UUID --entry NUMBER].".into(),
            );
        }
    };
    if format == nm_tunnel_subscription::SubscriptionFormat::NodesOnly {
        println!(
            "Explicit node-only mode does not preserve source DNS/routing. Legacy VPN DNS is 1.1.1.1; domain/LAN exceptions are not imported."
        );
    }
    println!(
        "This import saves profiles and credentials on disk in NetworkManager, not a desktop keyring. Autoconnect is off; the subscription URL is never saved."
    );
    if replacement.is_some() {
        println!(
            "Explicit replacement: VPN transport, credentials, DNS/routing and IPv4/IPv6 overrides will be replaced. The selected NM UUID, name and connection permissions are retained. The running VPN is not reconnected; the new settings apply on next activation."
        );
    }
    let source = read_source(std::io::stdin(), Duration::from_secs(20))?;
    tokio::runtime::Runtime::new()?.block_on(import(source, format, replacement))
}

async fn import(
    source: String,
    format: nm_tunnel_subscription::SubscriptionFormat,
    replacement: Option<(String, usize)>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Loading authorized subscription; source and node details are never printed.");
    let subscription =
        nm_tunnel_subscription::fetch_subscription_format(source.trim().into(), format).await?;
    if let Some(notice) = subscription.native_policy_notice() {
        println!("{notice}");
    }
    if let Some((id, index)) = replacement {
        let profile = subscription
            .entries()
            .get(index)
            .ok_or("Source entry is unavailable; nothing was updated.")?
            .profile()
            .map_err(|_| "Source entry is unsupported; nothing was updated.")?
            .clone();
        let observed = nm_tunnel_client::snapshot().await?;
        let mut matching = observed
            .profiles
            .iter()
            .filter(|profile| profile.id() == id);
        let saved = matching
            .next()
            .ok_or("Selected saved profile is unavailable; nothing was updated.")?;
        if matching.next().is_some() {
            return Err("Ambiguous target identity; nothing was updated.".into());
        }
        println!(
            "Updating the selected saved profile with a checked NM version; no activation or automatic retry."
        );
        nm_tunnel_client::replace_profile(saved, profile).await?;
        println!(
            "Saved profile replacement confirmed; the existing connection was not reconnected."
        );
        return Ok(());
    }
    let mut imported = 0;
    for entry in subscription.entries() {
        let Ok(profile) = entry.profile() else {
            continue;
        };
        let mut draft = profile.to_draft();
        draft.name = format!("NMT lab node {}", imported + 1);
        let profile = draft.validate().map_err(|_| "Invalid imported profile.")?;
        nm_tunnel_client::save_profile(profile).await?;
        imported += 1;
    }
    println!(
        "Saved {imported} persistent NM profile(s), including credentials, without activation."
    );
    if imported == 0 {
        return Err("No supported profiles were imported.".into());
    }
    Ok(())
}
