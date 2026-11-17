use umbranet_dpi::autohostlist::{failure_kind, host_from_payload, AutoHostList, Failure};
use umbranet_dpi::engine::Engine;
use umbranet_dpi::strategy::Strategy;
use umbranet_dpi::traffic::filter::{HostList, IpSet};

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("umbranet-auto-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn tcp_packet(
    payload: &[u8],
    flags: u8,
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
) -> Vec<u8> {
    let total = 20 + 20 + payload.len();
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&src);
    pkt[16..20].copy_from_slice(&dst);
    pkt[20..22].copy_from_slice(&sport.to_be_bytes());
    pkt[22..24].copy_from_slice(&dport.to_be_bytes());
    pkt[24..28].copy_from_slice(&1000u32.to_be_bytes());
    pkt[32] = 0x50;
    pkt[33] = flags;
    pkt[40..].copy_from_slice(payload);
    pkt
}

#[test]
fn records_domains_and_persists() {
    let dir = temp_dir("persist");
    let mut list = AutoHostList::load(&dir);
    assert!(list.is_empty());

    assert!(list.record("YouTube.com"));
    assert!(list.record("discord.com"));
    // повторно и мусор — без изменений
    assert!(!list.record("youtube.com"));
    assert!(!list.record(""));
    assert!(!list.record("localhost"));

    let reloaded = AutoHostList::load(&dir);
    assert_eq!(reloaded.domains(), vec!["discord.com", "youtube.com"]);
    assert!(reloaded.contains("www.youtube.com"));
    assert!(!reloaded.contains("notyoutube.com"));

    let mut list2 = AutoHostList::load(&dir);
    list2.clear().unwrap();
    assert!(AutoHostList::load(&dir).is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn detects_rst_and_hosts() {
    let rst = tcp_packet(&[], 0x14, [1, 1, 1, 1], [192, 168, 1, 10], 443, 50000);
    assert_eq!(failure_kind(&rst), Some(Failure::Rst));

    let data = tcp_packet(b"hello", 0x18, [1, 1, 1, 1], [192, 168, 1, 10], 443, 50000);
    assert_eq!(failure_kind(&data), None);

    let http = b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n";
    assert_eq!(host_from_payload(http).as_deref(), Some("blocked.example"));
    assert_eq!(host_from_payload(b"garbage"), None);
}

#[test]
fn engine_adds_domain_after_rst() {
    let dir = temp_dir("engine");
    let mut auto = AutoHostList::load(&dir);
    let strategy = Strategy::from_json(
        r#"{"version":1,"id":"p","name":"P","actions":[{"disorder":{"positions":["sld"]}}]}"#,
    )
    .unwrap();
    let mut engine = Engine::with_autohostlist(
        strategy,
        HostList::default(),
        IpSet::default(),
        Some(auto.clone()),
    );

    let payload = b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n";
    let out = engine.process_packet(&tcp_packet(payload, 0x18, [192, 168, 1, 10], [1, 1, 1, 1], 50000, 443), true);
    // Обхода ещё нет (домена нет в списке) — пакет уходит как есть.
    assert_eq!(out.len(), 1);

    // Сервер присылает RST на тот же адрес/порт.
    let rst = tcp_packet(&[], 0x14, [1, 1, 1, 1], [192, 168, 1, 10], 443, 50000);
    assert_eq!(umbranet_dpi::autohostlist::failure_kind(&rst), Some(Failure::Rst));
    engine.process_packet(&rst, false);

    // Домен попал в autohostlist, и теперь тот же запрос режется.
    assert!(engine.auto_domains().contains(&"blocked.example".to_string()));
    let out2 = engine.process_packet(&tcp_packet(payload, 0x18, [192, 168, 1, 10], [1, 1, 1, 1], 50000, 443), true);
    assert!(out2.len() > 1, "после RST домен должен обходиться");

    assert!(auto.record("unused.example"));
    engine.clear_auto().unwrap();
    assert!(engine.auto_domains().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}
