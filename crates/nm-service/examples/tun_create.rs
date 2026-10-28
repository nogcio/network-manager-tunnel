//! Explicit isolated kernel regression driver; never run against host networking.
#[path = "../src/supervisor/tun.rs"]
mod tun;

fn main() -> std::io::Result<()> {
    use std::{
        io,
        sync::{Arc, Barrier},
    };
    let expected = std::env::var("NMT_TEST_PARENT_NETNS").map_err(io::Error::other)?;
    let mapping = std::fs::read_to_string("/proc/self/uid_map")?;
    let ids: Vec<_> = mapping.split_whitespace().collect();
    if ids.len() != 3 || ids[0] != "0" || ids[1] == "0" || ids[2] != "1" {
        return Err(io::Error::other("Rootless single-UID namespace required."));
    }
    if std::fs::read_link("/proc/self/ns/net")?.to_string_lossy() == expected {
        return Err(io::Error::other("Host namespace refused."));
    }
    match std::env::args().nth(1).as_deref() {
        Some("reject") => {
            assert!(tun::create().is_err(), "Occupied name was adopted");
        }
        Some("race") => {
            let start = Arc::new(Barrier::new(3));
            let finish = Arc::new(Barrier::new(3));
            let tasks: Vec<_> = (0..2)
                .map(|_| {
                    let start = Arc::clone(&start);
                    let finish = Arc::clone(&finish);
                    std::thread::spawn(move || {
                        start.wait();
                        let result = tun::create();
                        // Keep the winning device alive until both attempts finish.
                        finish.wait();
                        result
                    })
                })
                .collect();
            start.wait();
            finish.wait();
            let results: Vec<_> = tasks
                .into_iter()
                .map(|task| {
                    task.join()
                        .map_err(|_| io::Error::other("TUN thread panicked"))
                })
                .collect::<io::Result<_>>()?;
            assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
            for device in results.into_iter().flatten() {
                assert_eq!(device.name()?, "nmtun0");
            }
        }
        _ => return Err(io::Error::other("Expected reject or race mode.")),
    }
    println!("PASS isolated exclusive TUN creation");
    Ok(())
}
