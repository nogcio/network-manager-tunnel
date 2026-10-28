//! Synthetic full source shared by parser and HTTP admission tests, never a suite.
use serde_json::{Value, json};
pub(crate) fn configuration() -> Value {
    json!({
        "dns": {
            "servers":[
                {"tag":"remote","address":"tls://1.1.1.1","address_resolver":"local","detour":"proxy"},
                {"tag":"direct-dns","address":"tcp://8.8.8.8","detour":"direct"},
                {"tag":"local","address":"local","detour":"direct"},
                {"tag":"fake","address":"fakeip"}
            ],
            "rules":[{"outbound":"any","server":"local"},{"query_type":["A","AAAA"],"server":"fake"}],
            "final":"remote", "independent_cache":true,
            "fakeip":{"enabled":true,"inet4_range":"198.18.0.0/15","inet6_range":"fd00::/16"}
        },
        "outbounds":[
            {"type":"selector","tag":"proxy","outbounds":["TCP node","WS node"],"default":"TCP node"},
            {"type":"vless","tag":"TCP node","server":"proxy.example","server_port":443,
                "uuid":"12345678-1234-4234-8234-123456789abc","flow":"xtls-rprx-vision",
                "tls":{"enabled":true,"server_name":"peer.example","utls":{"enabled":true,"fingerprint":"chrome"},
                    "reality":{"enabled":true,"public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","short_id":"aabb"}}},
            {"type":"vless","tag":"WS node","server":"edge.example","server_port":443,
                "uuid":"12345678-1234-4234-8234-123456789abd","packet_encoding":"xudp",
                "tls":{"enabled":true,"server_name":"certificate.example"},
                "transport":{"type":"ws","path":"/socket?mode=fixture","headers":{"Host":"cdn.example"}}},
            {"type":"direct","tag":"direct"},{"type":"block","tag":"block"}
        ],
        "route":{"auto_detect_interface":true,"final":"proxy","rules":[
            {"action":"sniff"},
            {"type":"logical","mode":"or","rules":[{"protocol":"dns"},{"port":53}],"action":"hijack-dns"},
            {"protocol":"bittorrent","outbound":"block"},
            {"domain_suffix":["direct.example","second.example","third.example"],"outbound":"direct"},
            {"ip_is_private":true,"outbound":"direct"}
        ]},
        "inbounds":[
            {"type":"tun","tag":"tun","address":["172.19.0.1/30","fdfe::1/126"],"mtu":1400,
                "auto_route":true,"strict_route":true,"stack":"mixed",
                "platform":{"http_proxy":{"enabled":true,"server":"127.0.0.1","server_port":2080}}},
            {"type":"mixed","tag":"mixed","listen":"127.0.0.1","listen_port":2080}
        ],
        "experimental":{"cache_file":{"enabled":true,"store_fakeip":true,"path":"/not-opened/source-cache"},
            "clash_api":{"external_controller":"127.0.0.1:9090","secret":"synthetic-controller-secret",
                "external_ui_download_url":"https://example.com/not-fetched","default_mode":"rule"}},
        "log":{"level":"info","output":"/not-opened/source-log"}
    })
}
