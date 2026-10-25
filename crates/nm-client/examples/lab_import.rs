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
    let source = read_source(std::io::stdin(), Duration::from_secs(20))?;
    tokio::runtime::Runtime::new()?.block_on(import(source))
}

async fn import(source: String) -> Result<(), Box<dyn std::error::Error>> {
    println!("Loading authorized subscription; source and node details are never printed.");
    let subscription = nm_tunnel_subscription::fetch_subscription(source.trim().into()).await?;
    let mut imported = 0;
    for entry in subscription.entries() {
        let Ok(profile) = entry.profile() else {
            continue;
        };
        let mut draft = profile.fields().clone();
        draft.name = format!("NMT lab node {}", imported + 1);
        let profile = draft.validate().map_err(|_| "Invalid imported profile.")?;
        nm_tunnel_client::save_profile(profile).await?;
        imported += 1;
    }
    println!("Prepared {imported} session-only NM profile(s), without activation.");
    if imported == 0 {
        return Err("No supported profiles were imported.".into());
    }
    Ok(())
}
