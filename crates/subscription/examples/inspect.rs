//! Explicit live import check. Source is read from stdin, never argv or logs.
use nm_tunnel_subscription::fetch_subscription;
use secrecy::SecretString;
use std::io::{self, Read};

#[tokio::main]
async fn main() {
    println!("Reading a subscription URL from stdin; output is aggregate-only.");
    let mut source = String::new();
    if io::stdin()
        .lock()
        .take(8193)
        .read_to_string(&mut source)
        .is_err()
        || source.len() > 8192
    {
        eprintln!("Invalid or oversized subscription input.");
        std::process::exit(2);
    }
    match fetch_subscription(SecretString::from(source)).await {
        Ok(list) => {
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
