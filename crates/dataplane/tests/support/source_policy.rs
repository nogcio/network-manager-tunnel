//! Synthetic complete-policy fixture shared by contracts and the isolated probe.
use nm_tunnel_profile::{Profile, SourcePolicy, import_vless};
use std::io;

pub fn profile() -> io::Result<Profile> {
    let policy = serde_json::json!({
        "version": 1,
        "dns": {"address":"1.1.1.1", "port":53, "transport":"udp", "via_proxy":true, "tls_name":""},
        "domain_policy": serde_json::json!({"version":1,"rules":[
            {"domain":["block.example"],"action":"block"},
            {"domain":["direct.example"],"action":"direct"}
        ]}).to_string(),
        "fakeip_range":"198.18.0.0/15", "tun_address":"172.19.0.1", "tun_prefix":30, "mtu":1400
    });
    let mut draft = import_vless("vless://12345678-1234-4234-8234-123456789abc@proxy.example:443?security=tls&sni=peer.example")
        .map_err(io::Error::other)?;
    draft.source_policy =
        Some(SourcePolicy::from_json(&policy.to_string()).map_err(io::Error::other)?);
    draft.fake_ip = true;
    draft.dns_interception = true;
    draft
        .validate()
        .map_err(|_| io::Error::other("Invalid synthetic source policy."))
}
