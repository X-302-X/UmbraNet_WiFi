use umbranet_dpi::traffic::{
    application::Evidence,
    connections::{Config, Connections, Error as ConnectionError},
    offline_tcp::{self as adapter, Direction, Error, Handle},
    packet::{parse_ip, PacketError, Protocol},
    stream::StreamError,
};

#[derive(Clone, Copy)]
struct Tcp<'a> {
    seq: u32,
    ack: u32,
    flags: u8,
    options: &'a [u8],
    payload: &'a [u8],
}
fn tcp(seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Tcp<'_> {
    Tcp {
        seq,
        ack,
        flags,
        options: &[],
        payload,
    }
}
// Независимый построитель тестовых checksum, не вызывает проверяемый модуль.
fn fixture_sum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += (u32::from(pair[0]) << 8) | u32::from(*pair.get(1).unwrap_or(&0));
        sum = (sum & 0xffff) + (sum >> 16);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
fn seal(ip: &mut [u8]) {
    let v6 = ip[0] >> 4 == 6;
    let header = if v6 { 40 } else { ((ip[0] & 15) as usize) * 4 };
    let total = if v6 {
        40 + u16::from_be_bytes([ip[4], ip[5]]) as usize
    } else {
        u16::from_be_bytes([ip[2], ip[3]]) as usize
    };
    ip[header + 16..header + 18].fill(0);
    let mut pseudo = vec![];
    if v6 {
        pseudo.extend_from_slice(&ip[8..40]);
        pseudo.extend_from_slice(&((total - header) as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 6]);
    } else {
        pseudo.extend_from_slice(&ip[12..20]);
        pseudo.extend_from_slice(&[0, 6]);
        pseudo.extend_from_slice(&((total - header) as u16).to_be_bytes());
    }
    pseudo.extend_from_slice(&ip[header..total]);
    ip[header + 16..header + 18].copy_from_slice(&fixture_sum(&pseudo).to_be_bytes());
    if !v6 {
        ip[10..12].fill(0);
        let sum = fixture_sum(&ip[..header]);
        ip[10..12].copy_from_slice(&sum.to_be_bytes());
    }
}
fn packet(v6: bool, outgoing: bool, spec: Tcp<'_>) -> Vec<u8> {
    assert_eq!(spec.options.len() % 4, 0);
    let (src_port, dst_port) = if outgoing {
        (40000u16, 443u16)
    } else {
        (443, 40000)
    };
    let mut t = vec![0; 20];
    t[0..2].copy_from_slice(&src_port.to_be_bytes());
    t[2..4].copy_from_slice(&dst_port.to_be_bytes());
    t[4..8].copy_from_slice(&spec.seq.to_be_bytes());
    t[8..12].copy_from_slice(&spec.ack.to_be_bytes());
    t[12] = (((20 + spec.options.len()) / 4) as u8) << 4;
    t[13] = spec.flags;
    t[14..16].copy_from_slice(&1234u16.to_be_bytes());
    t.extend_from_slice(spec.options);
    t.extend_from_slice(spec.payload);
    let mut ip = vec![0; if v6 { 40 } else { 20 }];
    if v6 {
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&(t.len() as u16).to_be_bytes());
        ip[6] = 6;
        ip[8] = 0x20;
        ip[9] = 1;
        ip[23] = if outgoing { 1 } else { 2 };
        ip[24] = 0x20;
        ip[25] = 1;
        ip[39] = if outgoing { 2 } else { 1 };
    } else {
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&((20 + t.len()) as u16).to_be_bytes());
        ip[9] = 6;
        ip[12..16].copy_from_slice(if outgoing {
            &[192, 0, 2, 1]
        } else {
            &[198, 51, 100, 2]
        });
        ip[16..20].copy_from_slice(if outgoing {
            &[198, 51, 100, 2]
        } else {
            &[192, 0, 2, 1]
        });
    }
    ip.extend_from_slice(&t);
    seal(&mut ip);
    ip
}
fn table() -> Connections {
    Connections::new(Config::new(3, 512, 10, 30, 5).unwrap())
}
fn handshake(c: &mut Connections, v6: bool) -> Handle {
    let h = adapter::open(c, &packet(v6, true, tcp(100, 0, 2, b"")), 1).unwrap();
    adapter::syn_ack(c, &h, &packet(v6, false, tcp(500, 101, 0x12, b"")), 2).unwrap();
    adapter::client_ack(c, &h, &packet(v6, true, tcp(101, 501, 0x10, b"")), 3).unwrap();
    h
}
fn hello(ech: bool) -> Vec<u8> {
    let host = b"example.com";
    let mut names = vec![0, 0, host.len() as u8];
    names.extend_from_slice(host);
    let mut sni = (names.len() as u16).to_be_bytes().to_vec();
    sni.extend_from_slice(&names);
    let mut ext = vec![0, 0];
    ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sni);
    if ech {
        ext.extend_from_slice(&[0xfe, 0x0d, 0, 1, 0]);
    }
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0; 32]);
    body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    let mut hs = vec![1, 0, 0, body.len() as u8];
    hs.extend_from_slice(&body);
    let mut record = vec![22, 3, 1];
    record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    record.extend_from_slice(&hs);
    record
}

#[test]
fn extracts_fields_options_and_respects_ip_total_length() {
    for v6 in [false, true] {
        let mut raw = packet(
            v6,
            true,
            Tcp {
                seq: 0x01020304,
                ack: 0xa0b0c0d0,
                flags: 0x18,
                options: &[2, 4, 5, 6],
                payload: b"ABC",
            },
        );
        raw.extend_from_slice(b"ignored trailing bytes");
        let p = parse_ip(&raw).unwrap();
        let t = p.tcp.unwrap();
        assert_eq!(p.protocol, Protocol::Tcp);
        assert_eq!(
            (t.sequence, t.acknowledgment, t.flags, t.window),
            (0x01020304, 0xa0b0c0d0, 0x18, 1234)
        );
        assert_eq!(t.options, &[2, 4, 5, 6]);
        assert_eq!(p.payload, b"ABC");
    }
}

#[test]
fn ipv4_and_ipv6_synthetic_handshakes_reassemble_http_and_close() {
    for v6 in [false, true] {
        let mut c = table();
        let h = handshake(&mut c, v6);
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        adapter::payload(
            &mut c,
            &h,
            &packet(v6, true, tcp(111, 501, 0x18, &data[10..])),
            4,
        )
        .unwrap();
        assert_eq!(adapter::evidence(&mut c, &h, 4), Ok(Evidence::Unknown));
        let first = packet(v6, true, tcp(101, 501, 0x10, &data[..10]));
        adapter::payload(&mut c, &h, &first, 5).unwrap();
        adapter::payload(&mut c, &h, &first, 5).unwrap();
        assert_eq!(
            adapter::evidence(&mut c, &h, 5),
            Ok(Evidence::HttpHost("example.com".into()))
        );
        adapter::close(
            &mut c,
            &h,
            &packet(v6, false, tcp(501, 101, 0x11, b"")),
            Direction::Inbound,
            6,
        )
        .unwrap();
        assert_eq!(
            adapter::evidence(&mut c, &h, 6),
            Err(Error::Connection(ConnectionError::NotFound))
        );
    }
}

#[test]
fn synthetic_tls_and_ech_at_every_tcp_split() {
    for ech in [false, true] {
        let bytes = hello(ech);
        for split in 1..bytes.len() {
            let mut c = table();
            let h = handshake(&mut c, false);
            adapter::payload(
                &mut c,
                &h,
                &packet(
                    false,
                    true,
                    tcp(101 + split as u32, 501, 0x18, &bytes[split..]),
                ),
                4,
            )
            .unwrap();
            assert_eq!(adapter::evidence(&mut c, &h, 4), Ok(Evidence::Unknown));
            adapter::payload(
                &mut c,
                &h,
                &packet(false, true, tcp(101, 501, 0x18, &bytes[..split])),
                5,
            )
            .unwrap();
            let expected = if ech {
                Evidence::EncryptedClientHello
            } else {
                Evidence::TlsServerName("example.com".into())
            };
            assert_eq!(adapter::evidence(&mut c, &h, 5), Ok(expected));
        }
    }
}

#[test]
fn incorrect_ack_and_duplicate_data_conflict_retire_flow() {
    let mut c = table();
    let h = adapter::open(&mut c, &packet(false, true, tcp(100, 0, 2, b"")), 1).unwrap();
    assert_eq!(
        adapter::syn_ack(
            &mut c,
            &h,
            &packet(false, false, tcp(500, 99, 0x12, b"")),
            2
        ),
        Err(Error::Connection(ConnectionError::InvalidHandshake))
    );
    let mut c = table();
    let h = handshake(&mut c, false);
    adapter::payload(
        &mut c,
        &h,
        &packet(false, true, tcp(101, 501, 0x18, b"abc")),
        4,
    )
    .unwrap();
    assert_eq!(
        adapter::payload(
            &mut c,
            &h,
            &packet(false, true, tcp(102, 501, 0x18, b"x")),
            5
        ),
        Err(Error::Connection(ConnectionError::Prefix(
            StreamError::ConflictingOverlap
        )))
    );
    assert_eq!(
        adapter::evidence(&mut c, &h, 5),
        Err(Error::Connection(ConnectionError::NotFound))
    );
}

#[test]
fn mismatch_of_tuple_and_direction_never_changes_other_flow() {
    let mut c = table();
    let h = handshake(&mut c, false);
    let mut wrong = packet(false, true, tcp(101, 501, 0x10, b"x"));
    wrong[21] ^= 1;
    seal(&mut wrong);
    assert_eq!(
        adapter::payload(&mut c, &h, &wrong, 4),
        Err(Error::FlowMismatch)
    );
    let wrong_direction = packet(false, false, tcp(101, 501, 0x10, b"x"));
    assert_eq!(
        adapter::payload(&mut c, &h, &wrong_direction, 4),
        Err(Error::FlowMismatch)
    );
    assert_eq!(adapter::evidence(&mut c, &h, 4), Ok(Evidence::Unknown));
}

#[test]
fn unsupported_flags_retire_matching_flow_and_do_not_yield_evidence() {
    for flags in [0, 2, 4, 0x11, 0x30, 0x50, 0x90] {
        let mut c = table();
        let h = handshake(&mut c, false);
        assert_eq!(
            adapter::payload(
                &mut c,
                &h,
                &packet(false, true, tcp(101, 501, flags, b"x")),
                4
            ),
            Err(Error::UnexpectedTcpShape)
        );
        assert_eq!(
            adapter::evidence(&mut c, &h, 4),
            Err(Error::Connection(ConnectionError::NotFound))
        );
    }
}

#[test]
fn truncated_fragmented_and_unsupported_packets_disable_model() {
    let base = packet(false, true, tcp(101, 501, 0x18, b"x"));
    let mut fragmented = base.clone();
    fragmented[6] = 0x20;
    let mut bad_offset = base.clone();
    bad_offset[32] = 0x40;
    let mut reserved = base.clone();
    reserved[32] |= 1;
    let mut urgent = base.clone();
    urgent[39] = 1;
    let tcp_options = packet(
        false,
        true,
        Tcp {
            options: &[30, 4, 0, 0],
            ..tcp(101, 501, 0x18, b"x")
        },
    );
    for bad in [
        &base[..19],
        &fragmented[..],
        &bad_offset[..],
        &reserved[..],
        &urgent[..],
        &tcp_options[..],
    ] {
        let mut c = table();
        let h = handshake(&mut c, false);
        assert!(adapter::payload(&mut c, &h, bad, 4).is_err());
        assert!(!c.is_available());
        assert_eq!(
            adapter::evidence(&mut c, &h, 4),
            Err(Error::Connection(ConnectionError::Unavailable))
        );
    }
    assert_eq!(parse_ip(&fragmented), Err(PacketError::Fragmented));
    assert_eq!(parse_ip(&bad_offset), Err(PacketError::Invalid));
}

#[test]
fn delayed_handles_do_not_affect_reused_tuple() {
    let mut c = table();
    let old = handshake(&mut c, false);
    adapter::close(
        &mut c,
        &old,
        &packet(false, true, tcp(101, 501, 0x14, b"")),
        Direction::Outbound,
        4,
    )
    .unwrap();
    let new = adapter::open(&mut c, &packet(false, true, tcp(200, 0, 2, b"")), 9).unwrap();
    assert_eq!(
        adapter::syn_ack(
            &mut c,
            &old,
            &packet(false, false, tcp(500, 101, 0x12, b"")),
            9
        ),
        Err(Error::Connection(ConnectionError::StaleToken))
    );
    adapter::syn_ack(
        &mut c,
        &new,
        &packet(false, false, tcp(600, 201, 0x12, b"")),
        9,
    )
    .unwrap();
    adapter::client_ack(
        &mut c,
        &new,
        &packet(false, true, tcp(201, 601, 0x10, b"")),
        9,
    )
    .unwrap();
    assert_eq!(adapter::evidence(&mut c, &new, 9), Ok(Evidence::Unknown));
}

#[test]
fn arbitrary_short_packets_do_not_panic() {
    let mut seed = 0x12345678u32;
    for len in 0..500 {
        let mut bytes = vec![0; len % 140];
        for b in &mut bytes {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            *b = seed as u8;
        }
        let _ = parse_ip(&bytes);
        let mut c = table();
        let _ = adapter::open(&mut c, &bytes, 0);
    }
}

#[test]
fn unsupported_ip_options_ipv6_extensions_and_reserved_ip_flag_are_rejected() {
    let mut options = packet(false, true, tcp(100, 0, 2, b""));
    options[0] = 0x46;
    options.splice(20..20, [1, 1, 1, 1]);
    let len = options.len() as u16;
    options[2..4].copy_from_slice(&len.to_be_bytes());
    let mut reserved = packet(false, true, tcp(100, 0, 2, b""));
    reserved[6] = 0x80;
    let mut extension = packet(true, true, tcp(100, 0, 2, b""));
    extension[6] = 44;
    let mut udp = packet(false, true, tcp(100, 0, 2, b""));
    udp[9] = 17;
    for bytes in [options, reserved, extension, udp] {
        let mut c = table();
        assert!(adapter::open(&mut c, &bytes, 0).is_err());
        assert!(!c.is_available());
    }
}

#[test]
fn syn_payload_final_ack_payload_and_wrong_close_shape_do_not_create_evidence() {
    let mut c = table();
    let early = packet(false, true, tcp(100, 0, 2, b"early data"));
    assert_eq!(
        adapter::open(&mut c, &early, 0),
        Err(Error::UnexpectedTcpShape)
    );
    assert!(!c.is_available());
    let mut c = table();
    let h = adapter::open(&mut c, &packet(false, true, tcp(100, 0, 2, b"")), 1).unwrap();
    adapter::syn_ack(
        &mut c,
        &h,
        &packet(false, false, tcp(500, 101, 0x12, b"")),
        2,
    )
    .unwrap();
    assert_eq!(
        adapter::client_ack(
            &mut c,
            &h,
            &packet(false, true, tcp(101, 501, 0x10, b"data")),
            3
        ),
        Err(Error::UnexpectedTcpShape)
    );
    assert_eq!(
        adapter::evidence(&mut c, &h, 3),
        Err(Error::Connection(ConnectionError::NotFound))
    );
    let mut c = table();
    let h = handshake(&mut c, false);
    assert_eq!(
        adapter::close(
            &mut c,
            &h,
            &packet(false, true, tcp(101, 501, 0x15, b"")),
            Direction::Outbound,
            4
        ),
        Err(Error::UnexpectedTcpShape)
    );
    assert_eq!(
        adapter::evidence(&mut c, &h, 4),
        Err(Error::Connection(ConnectionError::NotFound))
    );
}

#[test]
fn all_shorter_captures_fail_and_backward_time_invalidates() {
    let raw = packet(false, true, tcp(100, 0, 2, b""));
    for len in 0..raw.len() {
        let mut c = table();
        assert!(adapter::open(&mut c, &raw[..len], 1).is_err());
        assert!(!c.is_available());
    }
    let mut c = table();
    let h = handshake(&mut c, false);
    assert_eq!(
        adapter::payload(
            &mut c,
            &h,
            &packet(false, true, tcp(101, 501, 0x18, b"x")),
            2
        ),
        Err(Error::Connection(ConnectionError::ClockWentBackwards))
    );
    assert!(!c.is_available());
}

#[test]
fn common_tcp_options_work_through_synthetic_handshake_and_data() {
    let syn_options = [
        2, 4, 5, 180, 4, 2, 8, 10, 0, 0, 0, 9, 0, 0, 0, 0, 1, 3, 3, 7,
    ];
    let timestamp = [1, 1, 8, 10, 0, 0, 0, 10, 0, 0, 0, 9];
    for v6 in [false, true] {
        let mut c = table();
        let syn = packet(
            v6,
            true,
            Tcp {
                options: &syn_options,
                ..tcp(100, 0, 2, b"")
            },
        );
        let h = adapter::open(&mut c, &syn, 1).unwrap();
        let syn_ack = packet(
            v6,
            false,
            Tcp {
                options: &syn_options,
                ..tcp(500, 101, 0x12, b"")
            },
        );
        adapter::syn_ack(&mut c, &h, &syn_ack, 2).unwrap();
        let ack = packet(
            v6,
            true,
            Tcp {
                options: &timestamp,
                ..tcp(101, 501, 0x10, b"")
            },
        );
        adapter::client_ack(&mut c, &h, &ack, 3).unwrap();
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let data = packet(
            v6,
            true,
            Tcp {
                options: &timestamp,
                ..tcp(101, 501, 0x18, request)
            },
        );
        adapter::payload(&mut c, &h, &data, 4).unwrap();
        assert_eq!(
            adapter::evidence(&mut c, &h, 4),
            Ok(Evidence::HttpHost("example.com".into()))
        );
    }
}

#[test]
fn checksum_and_option_failures_invalidate_the_offline_model() {
    use umbranet_dpi::traffic::{checksum::ChecksumError, tcp_options::OptionError};
    for v6 in [false, true] {
        let mut c = table();
        let h = handshake(&mut c, v6);
        let mut data = packet(v6, true, tcp(101, 501, 0x18, b"abc"));
        *data.last_mut().unwrap() ^= 1;
        assert_eq!(
            adapter::payload(&mut c, &h, &data, 4),
            Err(Error::Checksum(ChecksumError::Tcp))
        );
        assert!(!c.is_available());
        let mut c = table();
        let h = handshake(&mut c, v6);
        let invalid = packet(
            v6,
            true,
            Tcp {
                options: &[2, 4, 5, 180],
                ..tcp(101, 501, 0x18, b"x")
            },
        );
        assert_eq!(
            adapter::payload(&mut c, &h, &invalid, 4),
            Err(Error::TcpOptions(OptionError::WrongContext))
        );
        assert!(!c.is_available());
    }
    let mut c = table();
    let h = handshake(&mut c, false);
    let mut data = packet(false, true, tcp(101, 501, 0x18, b"x"));
    data[8] ^= 1;
    assert_eq!(
        adapter::payload(&mut c, &h, &data, 4),
        Err(Error::Checksum(ChecksumError::Ipv4Header))
    );
    assert!(!c.is_available());
}

#[test]
fn split_fixture_round_trip_and_selected_domain_classification_are_offline_only() {
    use umbranet_dpi::{
        catalog::Catalog,
        selection::Selection,
        strategy::Strategy,
        traffic::{
            classifier::{classify, Match},
            synthetic_split::split_fixture,
        },
    };
    let catalog = Catalog::from_json(include_str!("../services.json")).unwrap();
    let strategy =
        Strategy::from_json(include_str!("../../../strtegs_Uz/pass-through.json")).unwrap();
    let mut selected = Selection::default();
    selected.add_domain("example.com").unwrap();
    let snapshot = selected.snapshot(&catalog, &strategy).unwrap();
    for ech in [false, true] {
        for v6 in [false, true] {
            let mut c = table();
            let h = handshake(&mut c, v6);
            let raw = packet(v6, true, tcp(101, 501, 0x18, &hello(ech)));
            let segments = split_fixture(&raw, &[1, 12]).unwrap();
            for segment in segments.iter().rev() {
                adapter::payload(&mut c, &h, segment.bytes(), 4).unwrap();
            }
            let result = adapter::evidence(&mut c, &h, 4).unwrap();
            if ech {
                assert_eq!(result, Evidence::EncryptedClientHello);
                assert_eq!(classify(&snapshot, &result, None), Match::Unknown);
            } else {
                assert_eq!(result, Evidence::TlsServerName("example.com".into()));
                assert_eq!(
                    classify(&snapshot, &result, None),
                    Match::Domain("example.com".into())
                );
                let empty = Selection::default().snapshot(&catalog, &strategy).unwrap();
                assert_eq!(classify(&empty, &result, None), Match::Unknown);
            }
        }
    }
}

#[test]
fn initial_payload_ack_must_match_observed_syn_ack_and_revokes_candidate() {
    for v6 in [false, true] {
        for bad_ack in [0, 500, 502, u32::MAX] {
            let mut c = table();
            let h = handshake(&mut c, v6);
            let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
            adapter::payload(
                &mut c,
                &h,
                &packet(v6, true, tcp(101, 501, 0x18, request)),
                4,
            )
            .unwrap();
            assert_eq!(
                adapter::evidence(&mut c, &h, 4),
                Ok(Evidence::HttpHost("example.com".into()))
            );
            assert_eq!(
                adapter::payload(
                    &mut c,
                    &h,
                    &packet(v6, true, tcp(101, bad_ack, 0x18, request)),
                    5
                ),
                Err(Error::Connection(ConnectionError::UnexpectedAck))
            );
            assert_eq!(
                adapter::evidence(&mut c, &h, 5),
                Err(Error::Connection(ConnectionError::NotFound))
            );
            assert!(c.is_available()); // quarantine only that tuple
        }
    }
}

#[test]
fn server_isn_wraparound_and_stale_handle_cannot_retire_new_flow() {
    for v6 in [false, true] {
        let mut c = table();
        let old = adapter::open(&mut c, &packet(v6, true, tcp(100, 0, 2, b"")), 1).unwrap();
        adapter::syn_ack(
            &mut c,
            &old,
            &packet(v6, false, tcp(u32::MAX, 101, 0x12, b"")),
            2,
        )
        .unwrap();
        adapter::client_ack(&mut c, &old, &packet(v6, true, tcp(101, 0, 0x10, b"")), 3).unwrap();
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        adapter::payload(
            &mut c,
            &old,
            &packet(v6, true, tcp(101, 0, 0x18, request)),
            4,
        )
        .unwrap();
        assert_eq!(
            adapter::evidence(&mut c, &old, 4),
            Ok(Evidence::HttpHost("example.com".into()))
        );
        adapter::close(
            &mut c,
            &old,
            &packet(v6, true, tcp(101, 0, 0x14, b"")),
            Direction::Outbound,
            5,
        )
        .unwrap();
        let new = adapter::open(&mut c, &packet(v6, true, tcp(200, 0, 2, b"")), 10).unwrap();
        adapter::syn_ack(
            &mut c,
            &new,
            &packet(v6, false, tcp(600, 201, 0x12, b"")),
            10,
        )
        .unwrap();
        adapter::client_ack(
            &mut c,
            &new,
            &packet(v6, true, tcp(201, 601, 0x10, b"")),
            10,
        )
        .unwrap();
        assert_eq!(
            adapter::payload(
                &mut c,
                &old,
                &packet(v6, true, tcp(201, 999, 0x18, request)),
                10
            ),
            Err(Error::Connection(ConnectionError::StaleToken))
        );
        adapter::payload(
            &mut c,
            &new,
            &packet(v6, true, tcp(201, 601, 0x18, request)),
            10,
        )
        .unwrap();
        assert_eq!(
            adapter::evidence(&mut c, &new, 10),
            Ok(Evidence::HttpHost("example.com".into()))
        );
    }
}

#[test]
fn trailing_bytes_in_packet_are_not_flow_evidence() {
    for v6 in [false, true] {
        let mut c = table();
        let h = handshake(&mut c, v6);
        let mut data = packet(
            v6,
            true,
            tcp(
                101,
                501,
                0x18,
                b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            ),
        );
        data.push(0);
        assert_eq!(
            adapter::payload(&mut c, &h, &data, 4),
            Err(Error::UnsupportedPacket)
        );
        assert!(!c.is_available());
        assert_eq!(
            adapter::evidence(&mut c, &h, 4),
            Err(Error::Connection(ConnectionError::Unavailable))
        );
    }
}

#[test]
fn mismatched_ack_quarantines_only_its_tuple_not_other_connections() {
    fn with_local_port(mut raw: Vec<u8>, v6: bool, outgoing: bool, port: u16) -> Vec<u8> {
        let offset = (if v6 { 40 } else { 20 }) + if outgoing { 0 } else { 2 };
        raw[offset..offset + 2].copy_from_slice(&port.to_be_bytes());
        seal(&mut raw);
        raw
    }
    for v6 in [false, true] {
        let mut c = table();
        let first = handshake(&mut c, v6);
        let p = |out, spec| with_local_port(packet(v6, out, spec), v6, out, 40001);
        let second = adapter::open(&mut c, &p(true, tcp(200, 0, 2, b"")), 3).unwrap();
        adapter::syn_ack(&mut c, &second, &p(false, tcp(600, 201, 0x12, b"")), 3).unwrap();
        adapter::client_ack(&mut c, &second, &p(true, tcp(201, 601, 0x10, b"")), 3).unwrap();
        let selected = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        adapter::payload(
            &mut c,
            &first,
            &packet(v6, true, tcp(101, 501, 0x18, selected)),
            4,
        )
        .unwrap();
        adapter::payload(&mut c, &second, &p(true, tcp(201, 601, 0x18, selected)), 4).unwrap();
        assert_eq!(
            adapter::payload(
                &mut c,
                &first,
                &packet(v6, true, tcp(101, 502, 0x18, selected)),
                5
            ),
            Err(Error::Connection(ConnectionError::UnexpectedAck))
        );
        assert_eq!(
            adapter::evidence(&mut c, &first, 5),
            Err(Error::Connection(ConnectionError::NotFound))
        );
        assert_eq!(
            adapter::evidence(&mut c, &second, 5),
            Ok(Evidence::HttpHost("example.com".into()))
        );
        assert_eq!(
            adapter::open(&mut c, &packet(v6, true, tcp(300, 0, 2, b"")), 5),
            Err(Error::Connection(ConnectionError::KeyBusy))
        );
    }
}

fn observed_handshake(c: &mut Connections, v6: bool) {
    use adapter::Observation::Tracking;
    assert_eq!(
        adapter::observe(
            c,
            &packet(v6, true, tcp(100, 0, 2, b"")),
            Direction::Outbound,
            1
        ),
        Ok(Tracking)
    );
    assert_eq!(
        adapter::observe(
            c,
            &packet(v6, false, tcp(500, 101, 0x12, b"")),
            Direction::Inbound,
            2
        ),
        Ok(Tracking)
    );
    assert_eq!(
        adapter::observe(
            c,
            &packet(v6, true, tcp(101, 501, 0x10, b"")),
            Direction::Outbound,
            3
        ),
        Ok(Tracking)
    );
}

#[test]
fn automatic_packet_routing_collects_only_contiguous_selected_domain_candidate() {
    use adapter::Observation::{Candidate, Tracking, Untracked};
    use umbranet_dpi::{
        catalog::Catalog,
        selection::Selection,
        strategy::Strategy,
        traffic::classifier::{classify, Match},
    };
    let catalog = Catalog::from_json(include_str!("../services.json")).unwrap();
    let strategy =
        Strategy::from_json(include_str!("../../../strtegs_Uz/pass-through.json")).unwrap();
    let mut selected = Selection::default();
    selected.add_domain("example.com").unwrap();
    let snapshot = selected.snapshot(&catalog, &strategy).unwrap();
    for v6 in [false, true] {
        let mut c = table();
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let early = packet(v6, true, tcp(101, 501, 0x18, req));
        assert_eq!(
            adapter::observe(&mut c, &early, Direction::Outbound, 0),
            Ok(Untracked)
        );
        observed_handshake(&mut c, v6);
        let tail = packet(v6, true, tcp(111, 501, 0x18, &req[10..]));
        assert!(matches!(
            adapter::observe(&mut c, &tail, Direction::Outbound, 4),
            Ok(Candidate {
                evidence: Evidence::Unknown,
                ..
            })
        ));
        let head = packet(v6, true, tcp(101, 501, 0x18, &req[..10]));
        let result = adapter::observe(&mut c, &head, Direction::Outbound, 5).unwrap();
        let Candidate {
            key,
            token,
            evidence,
        } = result
        else {
            panic!("expected evidence");
        };
        assert_eq!(c.evidence(&key, token, 5), Ok(evidence.clone()));
        assert_eq!(
            classify(&snapshot, &evidence, None),
            Match::Domain("example.com".into())
        );
        assert_eq!(
            classify(
                &Selection::default().snapshot(&catalog, &strategy).unwrap(),
                &evidence,
                None
            ),
            Match::Unknown
        );
        let close = packet(v6, false, tcp(501, 101, 0x11, b""));
        assert_eq!(
            adapter::observe(&mut c, &close, Direction::Inbound, 6),
            Ok(adapter::Observation::Closed)
        );
        assert_eq!(c.evidence(&key, token, 6), Err(ConnectionError::NotFound));
        assert_eq!(
            adapter::observe(&mut c, &head, Direction::Outbound, 6),
            Ok(Untracked)
        );
        assert_eq!(
            adapter::observe(
                &mut c,
                &packet(v6, true, tcp(300, 0, 2, b"")),
                Direction::Outbound,
                6
            ),
            Err(Error::Connection(ConnectionError::KeyBusy))
        );
        assert_eq!(
            adapter::observe(
                &mut c,
                &packet(v6, true, tcp(300, 0, 2, b"")),
                Direction::Outbound,
                11
            ),
            Ok(Tracking)
        );
    }
}

#[test]
fn automatic_router_rejects_wrong_ack_conflicts_and_unmodelled_inbound_data() {
    use adapter::Observation::{Candidate, Untracked};
    for v6 in [false, true] {
        for bad in [
            packet(v6, true, tcp(101, 502, 0x18, b"x")),
            packet(v6, false, tcp(501, 101, 0x18, b"server data")),
        ] {
            let direction = if bad == packet(v6, true, tcp(101, 502, 0x18, b"x")) {
                Direction::Outbound
            } else {
                Direction::Inbound
            };
            let mut c = table();
            observed_handshake(&mut c, v6);
            assert!(adapter::observe(&mut c, &bad, direction, 4).is_err());
            let data = packet(v6, true, tcp(101, 501, 0x18, b"x"));
            assert_eq!(
                adapter::observe(&mut c, &data, Direction::Outbound, 4),
                Ok(Untracked)
            );
        }
        let mut c = table();
        observed_handshake(&mut c, v6);
        assert!(matches!(
            adapter::observe(
                &mut c,
                &packet(v6, true, tcp(101, 501, 0x18, b"abc")),
                Direction::Outbound,
                4
            ),
            Ok(Candidate {
                evidence: Evidence::Unknown,
                ..
            })
        ));
        assert_eq!(
            adapter::observe(
                &mut c,
                &packet(v6, true, tcp(102, 501, 0x18, b"X")),
                Direction::Outbound,
                5
            ),
            Err(Error::Connection(ConnectionError::Prefix(
                StreamError::ConflictingOverlap
            )))
        );
    }
}

#[test]
fn automatic_router_rejects_duplicate_syn_and_source_loss_disables_all() {
    use adapter::Observation::{Tracking, Untracked};
    let mut c = table();
    let syn = packet(false, true, tcp(100, 0, 2, b""));
    assert_eq!(
        adapter::observe(&mut c, &syn, Direction::Outbound, 1),
        Ok(Tracking)
    );
    assert_eq!(
        adapter::observe(&mut c, &syn, Direction::Outbound, 2),
        Err(Error::Connection(ConnectionError::KeyBusy))
    );
    let syn_ack = packet(false, false, tcp(500, 101, 0x12, b""));
    assert_eq!(
        adapter::observe(&mut c, &syn_ack, Direction::Inbound, 2),
        Ok(Untracked)
    );
    c.invalidate(); // observer must signal lost/uncertain capture
    assert_eq!(
        adapter::observe(&mut c, &syn, Direction::Outbound, 3),
        Err(Error::Connection(ConnectionError::Unavailable))
    );
}

#[test]
fn automatic_router_ech_and_invalid_capture_never_become_domain_evidence() {
    use adapter::Observation::Candidate;
    for v6 in [false, true] {
        let mut c = table();
        observed_handshake(&mut c, v6);
        let ech = packet(v6, true, tcp(101, 501, 0x18, &hello(true)));
        assert!(matches!(
            adapter::observe(&mut c, &ech, Direction::Outbound, 4),
            Ok(Candidate {
                evidence: Evidence::EncryptedClientHello,
                ..
            })
        ));
        let mut truncated = ech.clone();
        truncated.pop();
        assert!(adapter::observe(&mut c, &truncated, Direction::Outbound, 5).is_err());
        assert!(!c.is_available());
        assert_eq!(
            adapter::observe(&mut c, &ech, Direction::Outbound, 5),
            Err(Error::Connection(ConnectionError::Unavailable))
        );
    }
}

#[test]
fn automatic_router_scopes_candidates_to_distinct_flow_tokens_and_plan() {
    use adapter::Observation::Candidate;
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };
    use umbranet_dpi::{store::Store, strategy::Strategy, traffic::classifier::Match};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "umbra-router-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&dir).unwrap();
    let mut store = Store::open(&dir).unwrap();
    store.apply("add_domain", "example.com", true).unwrap();
    let strategy =
        Strategy::from_json(include_str!("../../../strtegs_Uz/pass-through.json")).unwrap();
    let plan = store.prepare_session(&strategy).unwrap();
    for v6 in [false, true] {
        let mut c = table();
        observed_handshake(&mut c, v6);
        let second_packet = |out: bool, spec: Tcp<'_>| {
            let mut p = packet(v6, out, spec);
            let offset = (if v6 { 40 } else { 20 }) + if out { 0 } else { 2 };
            p[offset..offset + 2].copy_from_slice(&40001u16.to_be_bytes());
            seal(&mut p);
            p
        };
        adapter::observe(
            &mut c,
            &second_packet(true, tcp(200, 0, 2, b"")),
            Direction::Outbound,
            3,
        )
        .unwrap();
        adapter::observe(
            &mut c,
            &second_packet(false, tcp(600, 201, 0x12, b"")),
            Direction::Inbound,
            3,
        )
        .unwrap();
        adapter::observe(
            &mut c,
            &second_packet(true, tcp(201, 601, 0x10, b"")),
            Direction::Outbound,
            3,
        )
        .unwrap();
        let selected = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let other = b"GET / HTTP/1.1\r\nHost: other.example\r\n\r\n";
        let Candidate {
            key: k1, token: t1, ..
        } = adapter::observe(
            &mut c,
            &packet(v6, true, tcp(101, 501, 0x18, selected)),
            Direction::Outbound,
            4,
        )
        .unwrap()
        else {
            panic!()
        };
        let Candidate {
            key: k2, token: t2, ..
        } = adapter::observe(
            &mut c,
            &second_packet(true, tcp(201, 601, 0x18, other)),
            Direction::Outbound,
            4,
        )
        .unwrap()
        else {
            panic!()
        };
        assert_ne!(k1, k2);
        assert_ne!(t1, t2);
        assert_eq!(
            plan.offline_tcp_candidate(&mut c, &k1, t1, 4),
            Ok(Match::Domain("example.com".into()))
        );
        assert_eq!(
            plan.offline_tcp_candidate(&mut c, &k2, t2, 4),
            Ok(Match::Unknown)
        );
        assert_eq!(
            plan.offline_tcp_candidate(&mut c, &k2, t1, 4),
            Err(ConnectionError::StaleToken)
        );
        assert!(adapter::observe(
            &mut c,
            &packet(v6, true, tcp(101, 501, 0x18, b"X")),
            Direction::Outbound,
            5
        )
        .is_err());
        assert_eq!(
            plan.offline_tcp_candidate(&mut c, &k1, t1, 5),
            Err(ConnectionError::NotFound)
        );
        assert_eq!(
            plan.offline_tcp_candidate(&mut c, &k2, t2, 5),
            Ok(Match::Unknown)
        );
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn automatic_router_capacity_never_evicts_or_crosses_connections() {
    use adapter::Observation::{Candidate, Tracking};
    let mut c = table();
    observed_handshake(&mut c, false);
    for port in [40001u16, 40002] {
        let mut syn = packet(false, true, tcp(200, 0, 2, b""));
        syn[20..22].copy_from_slice(&port.to_be_bytes());
        seal(&mut syn);
        assert_eq!(
            adapter::observe(&mut c, &syn, Direction::Outbound, 3),
            Ok(Tracking)
        );
    }
    let mut fourth = packet(false, true, tcp(200, 0, 2, b""));
    fourth[20..22].copy_from_slice(&40003u16.to_be_bytes());
    seal(&mut fourth);
    assert_eq!(
        adapter::observe(&mut c, &fourth, Direction::Outbound, 4),
        Err(Error::Connection(ConnectionError::Capacity))
    );
    let req = packet(
        false,
        true,
        tcp(
            101,
            501,
            0x18,
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        ),
    );
    assert!(matches!(
        adapter::observe(&mut c, &req, Direction::Outbound, 4),
        Ok(Candidate {
            evidence: Evidence::HttpHost(_),
            ..
        })
    ));
}

#[test]
fn automatic_router_never_reuses_an_expired_flow_for_payload() {
    use adapter::Observation::Untracked;
    let mut c = table();
    observed_handshake(&mut c, false);
    let data = packet(
        false,
        true,
        tcp(
            101,
            501,
            0x18,
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        ),
    );
    assert_eq!(
        adapter::observe(&mut c, &data, Direction::Outbound, 13),
        Ok(Untracked)
    );
    assert_eq!(
        adapter::observe(&mut c, &data, Direction::Outbound, 12),
        Err(Error::Connection(ConnectionError::ClockWentBackwards))
    );
    assert!(!c.is_available());
}

#[test]
fn offline_timestamp_fixture_changes_only_tsval_and_checksum() {
    use umbranet_dpi::traffic::synthetic_timestamp::{replace_tsval_fixture, Error};
    for v6 in [false, true] {
        // NOP,NOP,TS(10): TSval=0x10203040, TSecr=0x50607080.
        let options = [1, 1, 8, 10, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
        let raw = packet(
            v6,
            true,
            Tcp {
                options: &options,
                ..tcp(101, 501, 0x18, b"example")
            },
        );
        let out = replace_tsval_fixture(&raw, 0).unwrap();
        let p = parse_ip(out.bytes()).unwrap();
        assert_eq!(p.payload, b"example");
        assert_eq!(
            p.tcp.unwrap().options,
            &[1, 1, 8, 10, 0, 0, 0, 0, 0x50, 0x60, 0x70, 0x80]
        );
        let ip_len = if v6 { 40 } else { 20 };
        let mut expected = raw.clone();
        expected[ip_len + 24..ip_len + 28].fill(0);
        seal(&mut expected); // Independent fixture checksum calculation.
        assert_eq!(out.bytes(), expected);
        let no_ts = packet(v6, true, tcp(101, 501, 0x18, b"example"));
        assert_eq!(replace_tsval_fixture(&no_ts, 0), Err(Error::NoTimestamp));
        let mut bad_sum = raw.clone();
        *bad_sum.last_mut().unwrap() ^= 1;
        assert!(matches!(
            replace_tsval_fixture(&bad_sum, 0),
            Err(Error::Checksum(_))
        ));
        let mut trailing = raw.clone();
        trailing.push(0);
        assert_eq!(replace_tsval_fixture(&trailing, 0), Err(Error::Unsupported));
        let bad_opt = [8, 9, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0];
        let malformed = packet(
            v6,
            true,
            Tcp {
                options: &bad_opt,
                ..tcp(101, 501, 0x18, b"abc")
            },
        );
        assert!(matches!(
            replace_tsval_fixture(&malformed, 0),
            Err(Error::Options(_))
        ));
    }
}

#[test]
fn offline_timestamp_rejects_syn_duplicate_ts_and_never_panics_on_short_inputs() {
    use umbranet_dpi::traffic::synthetic_timestamp::{replace_tsval_fixture, Error};
    let options = [1, 1, 8, 10, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
    let syn = packet(
        false,
        true,
        Tcp {
            options: &options,
            ..tcp(100, 0, 0x02, b"data")
        },
    );
    assert_eq!(replace_tsval_fixture(&syn, 0), Err(Error::Unsupported));
    let duplicate = [8, 10, 0, 0, 0, 1, 0, 0, 0, 1, 8, 10, 0, 0, 0, 2, 0, 0, 0, 2];
    let raw = packet(
        false,
        true,
        Tcp {
            options: &duplicate,
            ..tcp(101, 501, 0x18, b"x")
        },
    );
    assert!(matches!(
        replace_tsval_fixture(&raw, 0),
        Err(Error::Options(_))
    ));
    let mut seed = 0x4321_8765u32;
    for len in 0..256 {
        let mut input = vec![0; len];
        for byte in &mut input {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            *byte = (seed >> 24) as u8;
        }
        let before = input.clone();
        let _ = replace_tsval_fixture(&input, 0);
        assert_eq!(input, before);
    }
}

#[test]
fn uz1_fake_fixture_uses_ts_zero_or_bad_checksum_without_touching_original() {
    use umbranet_dpi::traffic::checksum::verify_tcp;
    use umbranet_dpi::traffic::synthetic_uz1_fake::{fake_fixture, Variant};
    let fake = include_bytes!("fixtures/uz1/tls_clienthello_www_google_com.bin");
    let opts = [1, 1, 8, 10, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
    for v6 in [false, true] {
        for has_ts in [false, true] {
            let ip = if v6 { 40 } else { 20 };
            let options: &[u8] = if has_ts { &opts } else { &[] };
            let mut raw = packet(
                v6,
                true,
                Tcp {
                    options,
                    ..tcp(101, 501, 0x18, b"real application data")
                },
            );
            if !v6 {
                raw[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
                seal(&mut raw);
            }
            let input = raw.clone();
            let output = fake_fixture(&raw, fake, true).unwrap();
            assert_eq!(raw, input);
            let p = parse_ip(output.bytes()).unwrap();
            assert_eq!(p.payload, fake);
            assert_eq!(p.tcp.unwrap().sequence, 101);
            assert_eq!(p.tcp.unwrap().acknowledgment, 501);
            if !v6 {
                assert_eq!(&output.bytes()[4..6], &[0, 0]);
            }
            let mut expected = input[..ip + 20 + options.len()].to_vec();
            expected.extend_from_slice(fake);
            let total = if v6 {
                expected.len() - 40
            } else {
                expected.len()
            };
            if v6 {
                expected[4..6].copy_from_slice(&(total as u16).to_be_bytes());
            } else {
                expected[2..4].copy_from_slice(&(total as u16).to_be_bytes());
                expected[4..6].fill(0);
            }
            if has_ts {
                expected[ip + 24..ip + 28].fill(0);
            }
            seal(&mut expected); // independent test checksum implementation
            if has_ts {
                assert_eq!(output.variant(), Variant::TimestampZero);
                assert_eq!(&p.tcp.unwrap().options[8..12], &opts[8..12]);
                assert!(verify_tcp(output.bytes()).is_ok());
            } else {
                assert_eq!(output.variant(), Variant::BadChecksum);
                expected[ip + 16] ^= 1;
                assert!(verify_tcp(output.bytes()).is_err());
            }
            assert_eq!(output.bytes(), expected);
        }
    }
}

#[test]
fn uz1_fake_fixture_rejects_malformed_unsupported_and_oversized() {
    use umbranet_dpi::traffic::synthetic_uz1_fake::{fake_fixture, Error};
    for v6 in [false, true] {
        let raw = packet(v6, true, tcp(101, 501, 0x18, b"x"));
        assert_eq!(fake_fixture(&raw, &[], false), Err(Error::InvalidPayload));
        assert_eq!(
            fake_fixture(&raw, &[1; 65535], false),
            Err(Error::InvalidPayload)
        );
        let mut bad = raw.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(matches!(
            fake_fixture(&bad, b"x", false),
            Err(Error::Checksum(_))
        ));
        let mut tail = raw.clone();
        tail.push(0);
        assert_eq!(fake_fixture(&tail, b"x", false), Err(Error::Unsupported));
        let options = [8, 9, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0];
        let malformed = packet(
            v6,
            true,
            Tcp {
                options: &options,
                ..tcp(101, 501, 0x18, b"x")
            },
        );
        assert!(matches!(
            fake_fixture(&malformed, b"x", false),
            Err(Error::Options(_))
        ));
    }
    let mut seed = 0xa17d4c35u32;
    for n in 0..256 {
        let mut input = vec![0; n];
        for byte in &mut input {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            *byte = (seed >> 24) as u8;
        }
        let before = input.clone();
        let _ = fake_fixture(&input, b"x", false);
        assert_eq!(input, before);
    }
}

#[test]
fn offline_split_preserves_timestamp_in_each_segment_and_reassembles() {
    use umbranet_dpi::traffic::synthetic_split::{
        split_fixture, split_timestamp_fixture, SplitError,
    };
    let opts = [1, 1, 8, 10, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
    for v6 in [false, true] {
        let input = packet(
            v6,
            true,
            Tcp {
                options: &opts,
                ..tcp(u32::MAX, 501, 0x18, b"abcd")
            },
        );
        assert_eq!(split_fixture(&input, &[1]), Err(SplitError::Unsupported));
        let fragments = split_timestamp_fixture(&input, &[1, 3]).unwrap();
        assert_eq!(fragments.len(), 3);
        let mut joined = vec![];
        for (i, (fragment, offset)) in fragments.iter().zip([0u32, 1, 3]).enumerate() {
            let parsed = parse_ip(fragment.bytes()).unwrap();
            assert_eq!(parsed.tcp.unwrap().options, opts);
            assert_eq!(parsed.tcp.unwrap().sequence, u32::MAX.wrapping_add(offset));
            assert_eq!(parsed.tcp.unwrap().flags, if i == 2 { 0x18 } else { 0x10 });
            let mut expected = fragment.bytes().to_vec();
            seal(&mut expected);
            assert_eq!(fragment.bytes(), expected);
            joined.extend_from_slice(parsed.payload);
        }
        assert_eq!(joined, b"abcd");
        let no_ts = packet(v6, true, tcp(101, 501, 0x18, b"abcd"));
        assert_eq!(
            split_timestamp_fixture(&no_ts, &[1]),
            Err(SplitError::Unsupported)
        );
        let sack = [
            1, 1, 8, 10, 1, 2, 3, 4, 5, 6, 7, 8, 5, 10, 0, 0, 0, 1, 0, 0, 0, 2, 1, 1,
        ];
        let with_sack = packet(
            v6,
            true,
            Tcp {
                options: &sack,
                ..tcp(101, 501, 0x18, b"abcd")
            },
        );
        assert_eq!(
            split_timestamp_fixture(&with_sack, &[1]),
            Err(SplitError::Unsupported)
        );
    }
}
