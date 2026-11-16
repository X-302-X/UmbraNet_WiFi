use umbranet_dpi::strategy::{Action, Strategy, StrategyFooling, StrategySplitPos};
use umbranet_dpi::traffic::checksum::verify_tcp;
use umbranet_dpi::traffic::desync::{
    apply_desync, auto_ttl, build_fake_tcp, find_host_range, resolve_split_positions,
    split_tls_record, write_checksums, DesyncPlan, Fooling, SplitPos,
};
use umbranet_dpi::traffic::packet::parse_ip;

fn build_ipv4_tcp_packet(payload: &[u8]) -> Vec<u8> {
    let total_len = 20 + 20 + payload.len();
    let mut pkt = vec![0u8; total_len];
    // IPv4 header
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    pkt[6] = 0x40; // DF
    pkt[8] = 64;   // TTL
    pkt[9] = 6;    // TCP
    pkt[12..16].copy_from_slice(&[192, 168, 1, 10]);
    pkt[16..20].copy_from_slice(&[142, 250, 74, 14]);
    // TCP header
    pkt[20..22].copy_from_slice(&50000u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
    pkt[24..28].copy_from_slice(&1000u32.to_be_bytes()); // seq
    pkt[28..32].copy_from_slice(&2000u32.to_be_bytes()); // ack
    pkt[32] = 0x50; // data offset = 5 (20 bytes)
    pkt[33] = 0x18; // PSH + ACK
    pkt[34..36].copy_from_slice(&64240u16.to_be_bytes());
    pkt[40..].copy_from_slice(payload);
    write_checksums(&mut pkt, false, 20);
    pkt
}

#[test]
fn auto_ttl_estimates_hops_correctly() {
    // Сервер с Linux (init=64), 10 хопов -> TTL=54, delta=2 -> fake_ttl=8
    assert_eq!(auto_ttl(54, 2, 1, 16), 8);
    // Сервер с Windows (init=128), 12 хопов -> TTL=116, delta=2 -> fake_ttl=10
    assert_eq!(auto_ttl(116, 2, 1, 16), 10);
    // Минимум зажат в min_ttl
    assert_eq!(auto_ttl(63, 5, 2, 16), 2);
}

#[test]
fn finds_http_host_and_resolves_sld() {
    let http = b"GET / HTTP/1.1\r\nHost: youtube.com\r\nUser-Agent: test\r\n\r\n";
    let range = find_host_range(http).expect("HTTP Host must be found");
    assert_eq!(&http[range.0..range.1], b"youtube.com");

    let cuts = resolve_split_positions(http, &[SplitPos::Method, SplitPos::Sld]);
    assert_eq!(cuts.len(), 2);
    assert_eq!(cuts[0], 4); // после "GET "
}

#[test]
fn desync_multisplit_disorder_and_fake_work() {
    let http = b"GET / HTTP/1.1\r\nHost: discord.com\r\n\r\n";
    let raw = build_ipv4_tcp_packet(http);
    assert!(verify_tcp(&raw).is_ok());

    let plan = DesyncPlan {
        splits: vec![SplitPos::Offset(4), SplitPos::Sld],
        disorder: true,
        fake: true,
        fake_repeats: 1,
        fooling: vec![Fooling::Ttl(3), Fooling::BadSum, Fooling::BadSeq(-5000)],
        fake_payload: Vec::new(),
        tls_record_split: None,
    };

    let packets = apply_desync(&raw, &plan).expect("desync should succeed");
    // 1 fake + 3 real segments
    assert_eq!(packets.len(), 4);

    // Первый пакет — fake с TTL=3 и битой контрольной суммой
    assert_eq!(packets[0][8], 3);
    assert!(verify_tcp(&packets[0]).is_err());

    // Реальные сегменты валидны по checksum и идут в обратном порядке (disorder)
    for seg in &packets[1..] {
        assert!(verify_tcp(seg).is_ok());
    }
    let p1 = parse_ip(&packets[1]).unwrap().tcp.unwrap().sequence_number;
    let p2 = parse_ip(&packets[2]).unwrap().tcp.unwrap().sequence_number;
    let p3 = parse_ip(&packets[3]).unwrap().tcp.unwrap().sequence_number;
    assert!(p1 > p2 && p2 > p3);
}

#[test]
fn fake_md5sig_adds_tcp_option_19() {
    let raw = build_ipv4_tcp_packet(b"hello");
    let fake = build_fake_tcp(&raw, &[Fooling::Md5Sig], &[]).unwrap();
    let parsed = parse_ip(&fake).unwrap();
    let tcp = parsed.tcp.unwrap();
    assert!(tcp.data_offset > 5);
    assert!(verify_tcp(&fake).is_ok());
}

#[test]
fn tls_record_split_creates_two_records() {
    let mut tls = vec![0x16, 0x03, 0x01, 0x00, 0x0a];
    tls.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    let split = split_tls_record(&tls, 4);
    assert_eq!(split.len(), tls.len() + 5);
    assert_eq!(split[0], 0x16);
    assert_eq!(u16::from_be_bytes([split[3], split[4]]), 4);
    assert_eq!(split[9], 0x16);
    assert_eq!(u16::from_be_bytes([split[12], split[13]]), 6);
}

#[test]
fn strategy_json_parses_desync_actions() {
    let json = r#"{
        "version": 1,
        "id": "yt_discord_ultra",
        "name": "YouTube + Discord Ultra",
        "actions": [
            { "fake": { "repeats": 2, "fooling": [{ "auto_ttl": { "delta": 2, "min": 1, "max": 12 } }, "bad_sum"] } },
            { "disorder": { "positions": ["sld", { "offset": 2 }] } }
        ]
    }"#;
    let s = Strategy::from_json(json).expect("valid strategy");
    assert_eq!(s.actions.len(), 2);
    assert!(matches!(s.actions[0], Action::Fake { repeats: 2, .. }));
    assert!(matches!(
        s.actions[1],
        Action::Disorder {
            positions: ref p
        } if p.contains(&StrategySplitPos::Sld)
    ));
    let _ = StrategyFooling::Md5Sig;
}
