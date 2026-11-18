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
        HostList::from_lines(["blocked.example"]),
        IpSet::default(),
        Some(auto.clone()),
    );

    let payload = b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n";
    let out = engine.process_packet(
        &tcp_packet(payload, 0x18, [192, 168, 1, 10], [1, 1, 1, 1], 50000, 443),
        true,
    );
    // Тестовый домен явно выбран; autohostlist сам по себе не расширяет выбор.
    assert!(out.len() > 1);

    // Сервер присылает RST на тот же адрес/порт.
    let rst = tcp_packet(&[], 0x14, [1, 1, 1, 1], [192, 168, 1, 10], 443, 50000);
    assert_eq!(
        umbranet_dpi::autohostlist::failure_kind(&rst),
        Some(Failure::Rst)
    );
    engine.process_packet(&rst, false);

    // Домен попал в autohostlist, и теперь тот же запрос режется.
    assert!(engine
        .auto_domains()
        .contains(&"blocked.example".to_string()));
    let out2 = engine.process_packet(
        &tcp_packet(payload, 0x18, [192, 168, 1, 10], [1, 1, 1, 1], 50000, 443),
        true,
    );
    assert!(out2.len() > 1, "после RST домен должен обходиться");

    assert!(auto.record("unused.example"));
    engine.clear_auto().unwrap();
    assert!(engine.auto_domains().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn automatic_list_does_not_expand_explicit_selection() {
    let dir = temp_dir("scope");
    let mut auto = AutoHostList::load(&dir);
    auto.record("unselected.example");
    let strategy = Strategy::from_json(
        r#"{"version":1,"id":"p","name":"P","actions":[{"disorder":{"positions":["sld"]}}]}"#,
    )
    .unwrap();
    let mut engine = Engine::with_autohostlist(
        strategy,
        HostList::from_lines(["selected.example"]),
        IpSet::from_lines(["1.1.1.1"]),
        Some(auto),
    );
    let payload = b"GET / HTTP/1.1\r\nHost: unselected.example\r\n\r\n";
    let packet = tcp_packet(payload, 0x18, [192, 168, 1, 10], [1, 1, 1, 1], 50000, 443);
    assert_eq!(engine.process_packet(&packet, true), vec![packet]);
    let selected = tcp_packet(
        b"GET / HTTP/1.1\r\nHost: selected.example\r\n\r\n",
        0x18,
        [192, 168, 1, 10],
        [1, 1, 1, 1],
        50000,
        443,
    );
    assert!(engine.process_packet(&selected, true).len() > 1);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn ech_outer_name_and_ambiguous_http_are_never_treated_as_selected_hosts() {
    let strategy = Strategy::from_json(
        r#"{"version":1,"id":"p","name":"P","actions":[{"disorder":{"positions":["sld"]}}]}"#,
    )
    .unwrap();
    let mut engine = Engine::new(
        strategy,
        HostList::from_lines(["example.com"]),
        IpSet::default(),
    );
    let host = b"example.com";
    let mut names = vec![0, 0, host.len() as u8];
    names.extend_from_slice(host);
    let mut sni = (names.len() as u16).to_be_bytes().to_vec();
    sni.extend_from_slice(&names);
    let mut ext = vec![0, 0];
    ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sni);
    ext.extend_from_slice(&[0xfe, 0x0d, 0, 1, 0]);
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0; 32]);
    body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    let mut handshake = vec![1, 0, 0, body.len() as u8];
    handshake.extend_from_slice(&body);
    let mut record = vec![22, 3, 1];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    for payload in [
        record,
        b"GET / HTTP/1.1\r\nHost: example.com\r\nHost: other.com\r\n\r\n".to_vec(),
    ] {
        let raw = tcp_packet(&payload, 0x18, [192, 168, 1, 10], [1, 1, 1, 1], 50000, 443);
        assert_eq!(engine.process_packet(&raw, true), vec![raw]);
    }
}
