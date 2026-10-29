use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::io::{AsyncBufReadExt, BufReader};

type AuthorizationReply = ((bool, bool, HashMap<String, String>),);

struct Authority {
    allow: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
}
#[zbus::interface(name = "org.freedesktop.PolicyKit1.Authority")]
impl Authority {
    fn check_authorization(
        &self,
        subject: (String, HashMap<String, OwnedValue>),
        action: String,
        details: HashMap<String, String>,
        flags: u32,
        cancellation: String,
    ) -> zbus::fdo::Result<AuthorizationReply> {
        assert_eq!(subject.0, "system-bus-name");
        assert_eq!(subject.1.len(), 1);
        assert!(
            <&str>::try_from(
                subject
                    .1
                    .get("name")
                    .ok_or_else(|| zbus::fdo::Error::Failed("Subject name".into()))?
            )
            .map_err(|_| zbus::fdo::Error::Failed("Bus name".into()))?
            .starts_with(':')
        );
        assert_eq!(action, "org.freedesktop.NetworkManager.network-control");
        assert!(details.is_empty());
        assert!(cancellation.is_empty());
        assert_eq!(flags, 1);
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(((self.allow.load(Ordering::SeqCst), false, HashMap::new()),))
    }
}
struct Control(zbus::Connection);
#[zbus::interface(name = "org.example.ProtectionTest")]
impl Control {
    async fn release(&self, #[zbus(header)] header: Header<'_>) -> zbus::fdo::Result<()> {
        disconnect(&self.0, &header).await
    }
}

#[tokio::test]
async fn polkit_bus_subject_network_control_and_structured_reply_are_checked_before_release()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut daemon = tokio::process::Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let mut reader = BufReader::new(daemon.stdout.take().ok_or("Missing bus")?);
        let mut address = String::new();
        reader.read_line(&mut address).await?;
        let service = zbus::connection::Builder::address(address.trim())?
            .build()
            .await?;
        let client = zbus::connection::Builder::address(address.trim())?
            .build()
            .await?;
        let allow = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        service
            .object_server()
            .at(
                "/org/freedesktop/PolicyKit1/Authority",
                Authority {
                    allow: Arc::clone(&allow),
                    calls: Arc::clone(&calls),
                },
            )
            .await?;
        service.request_name("org.freedesktop.PolicyKit1").await?;
        service
            .object_server()
            .at("/test", Control(service.clone()))
            .await?;
        service.request_name("org.example.ProtectionTest").await?;
        let proxy = zbus::Proxy::new(
            &client,
            "org.example.ProtectionTest",
            "/test",
            "org.example.ProtectionTest",
        )
        .await?;
        assert!(
            proxy
                .call_with_flags::<_, _, ()>(
                    "Release",
                    zbus::proxy::MethodFlags::AllowInteractiveAuth.into(),
                    &()
                )
                .await
                .is_err()
        );
        allow.store(true, Ordering::SeqCst);
        proxy
            .call_with_flags::<_, _, ()>(
                "Release",
                zbus::proxy::MethodFlags::AllowInteractiveAuth.into(),
                &(),
            )
            .await?;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        daemon.kill().await?;
        daemon.wait().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await?
}
