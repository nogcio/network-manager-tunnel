//! Explicit live import check. Source is read from stdin, never argv or logs.
use nm_tunnel_subscription::{SubscriptionFormat, fetch_subscription_format};
use secrecy::SecretString;
use std::io::{self, Read};
use std::time::Duration;

fn read_source() -> io::Result<SecretString> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    // A detached ordinary thread does not keep the process/Tokio runtime alive
    // if a pipe never reaches EOF. Never echo input or join a stalled reader.
    std::thread::Builder::new().spawn(move || {
        let mut source = String::new();
        let result = match io::stdin().lock().take(8193).read_to_string(&mut source) {
            Ok(_) if source.len() <= 8192 => Ok(SecretString::from(source)),
            _ => Err(io::Error::other("Invalid or oversized subscription input.")),
        };
        let _ = sender.send(result);
    })?;
    receiver
        .recv_timeout(Duration::from_secs(20))
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "Subscription input did not complete before the deadline.",
            )
        })?
}

#[tokio::main]
async fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let format = if args.is_empty() {
        SubscriptionFormat::Complete
    } else if args == ["--nodes-only"] {
        SubscriptionFormat::NodesOnly
    } else {
        eprintln!("Usage: inspect [--nodes-only]; provide the source only through stdin.");
        std::process::exit(2);
    };
    println!("Requested format: {format:?}; no automatic fallback.");
    if format == SubscriptionFormat::NodesOnly {
        println!("Explicit node-only import does not preserve source DNS or routing policies.");
    }
    println!("Reading a subscription URL from stdin; output is aggregate-only.");
    let source = match read_source() {
        Ok(source) => source,
        Err(_) => {
            eprintln!(
                "Subscription input was invalid, oversized or did not reach EOF within 20 seconds."
            );
            std::process::exit(2);
        }
    };
    match fetch_subscription_format(source, format).await {
        Ok(list) => {
            if let Some(notice) = list.native_policy_notice() {
                println!("{notice}");
            }
            println!(
                "Imported: {}; supported: {}; unsupported: {}",
                list.entries().len(),
                list.supported_count(),
                list.entries().len() - list.supported_count()
            );
            // Error reasons are static project strings, never URLs, node names or credentials.
            let mut reasons = std::collections::BTreeMap::new();
            for entry in list.entries() {
                if let Err(reason) = entry.profile() {
                    *reasons.entry(reason).or_insert(0) += 1;
                }
            }
            for (reason, count) in reasons {
                println!("{count} rejected: {reason}");
            }
            if list.supported_count() != list.entries().len() {
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("Import failed: {error}");
            std::process::exit(1);
        }
    }
}
