use umbranet_dpi::traffic::{
    checksum::{verify_tcp, ChecksumError},
    packet::PacketError,
    tcp_options::{parse, OptionError},
};

fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|b| {
            let s = std::str::from_utf8(b).unwrap();
            u8::from_str_radix(s, 16).unwrap()
        })
        .collect()
}

// Независимые фиксированные векторы построены Scapy для IPv4 и IPv6.
const V4_EMPTY: &str =
    "45000028007b000040068e1ec0000201c63364029c4001bb00000064000001f5501804d21e6f0000";
const V4_ODD: &str =
    "4500002b007b000040068e1bc0000201c63364029c4001bb00000064000001f5501804d25a090000616263";
const V4_EVEN: &str =
    "4500002c007b000040068e1ac0000201c63364029c4001bb00000064000001f5501804d259a4000061626364";
const V4_ZERO: &str =
    "4500002a007b000040068e1cc0000201c63364029c4001bb00000064000001f5501804d2000000001e6d";
const V6_EMPTY: &str = "600000000014064020010db800000000000000000000000120010db80000000000000000000000029c4001bb00000064000001f5501804d2af310000";
const V6_ODD: &str = "600000000017064020010db800000000000000000000000120010db80000000000000000000000029c4001bb00000064000001f5501804d2eacb0000616263";
const V6_EVEN: &str = "600000000018064020010db800000000000000000000000120010db80000000000000000000000029c4001bb00000064000001f5501804d2ea66000061626364";
const V6_ZERO: &str = "600000000016064020010db800000000000000000000000120010db80000000000000000000000029c4001bb00000064000001f5501804d200000000af2f";

#[test]
fn independent_scapy_vectors_cover_both_ip_versions_odd_even_and_zero_checksum() {
    for s in [
        V4_EMPTY, V4_ODD, V4_EVEN, V4_ZERO, V6_EMPTY, V6_ODD, V6_EVEN, V6_ZERO,
    ] {
        let mut packet = hex(s);
        assert_eq!(verify_tcp(&packet), Ok(()));
        packet.extend_from_slice(b"extra capture bytes");
        assert_eq!(verify_tcp(&packet), Ok(()));
    }
}

#[test]
fn damaged_ip_header_tcp_pseudo_header_and_payload_are_detected() {
    let mut ip = hex(V4_ODD);
    ip[8] ^= 1;
    assert_eq!(verify_tcp(&ip), Err(ChecksumError::Ipv4Header));
    let mut v4 = hex(V4_ODD);
    v4[42] ^= 1;
    assert_eq!(verify_tcp(&v4), Err(ChecksumError::Tcp));
    let mut v6 = hex(V6_ODD);
    v6[23] ^= 1;
    assert_eq!(verify_tcp(&v6), Err(ChecksumError::Tcp));
    let mut v6 = hex(V6_EVEN);
    v6[63] ^= 1;
    assert_eq!(verify_tcp(&v6), Err(ChecksumError::Tcp));
    for s in [V4_ODD, V6_ODD] {
        let p = hex(s);
        for n in 0..p.len() {
            assert!(verify_tcp(&p[..n]).is_err());
        }
    }
}

#[test]
fn unsupported_fragment_or_ip_options_are_not_accepted_for_checksum() {
    let mut ip = hex(V4_EMPTY);
    ip[6] = 0x20;
    assert_eq!(
        verify_tcp(&ip),
        Err(ChecksumError::Packet(PacketError::Fragmented))
    );
    let mut ip = hex(V4_EMPTY);
    ip[0] = 0x46;
    ip.splice(20..20, [1, 1, 1, 1]);
    ip[3] += 4;
    assert_eq!(verify_tcp(&ip), Err(ChecksumError::Unsupported));
    let mut ip = hex(V6_EMPTY);
    ip[6] = 44;
    assert_eq!(
        verify_tcp(&ip),
        Err(ChecksumError::Packet(PacketError::Unsupported))
    );
}

#[test]
fn parses_common_syn_options_and_timestamp() {
    let raw = [
        2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 9, 0, 0, 0, 0, 1, 3, 3, 7,
    ];
    let result = parse(&raw, true, false).unwrap();
    assert_eq!(result.mss, Some(1460));
    assert_eq!(result.window_scale, Some(7));
    assert!(result.sack_permitted);
    assert_eq!(result.timestamp, Some((9, 0)));
    assert!(result.sack_blocks.is_empty());
    assert_eq!(parse(&[1, 1, 0, 0], true, false), Ok(Default::default()));
}

#[test]
fn parses_sack_blocks_including_sequence_wrap() {
    let raw = [
        5, 18, 0xff, 0xff, 0xff, 0xfe, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 8, 0, 0,
    ];
    let result = parse(&raw, false, true).unwrap();
    assert_eq!(result.sack_blocks, vec![(u32::MAX - 1, 2), (4, 8)]);
    assert_eq!(parse(&raw, true, true), Err(OptionError::WrongContext));
    assert_eq!(parse(&raw, false, false), Err(OptionError::WrongContext));
}

#[test]
fn rejects_bad_lengths_duplicates_unsupported_and_wrong_context() {
    let cases: &[(&[u8], bool, bool, OptionError)] = &[
        (&[2, 4, 0], true, false, OptionError::Malformed),
        (&[2, 1, 0, 0], true, false, OptionError::Malformed),
        (&[2, 5, 0, 1], true, false, OptionError::Malformed),
        (&[2, 4, 0, 0], true, false, OptionError::Malformed),
        (
            &[2, 4, 5, 6, 2, 4, 5, 6],
            true,
            false,
            OptionError::Malformed,
        ),
        (&[3, 3, 15, 0], true, false, OptionError::Malformed),
        (&[4, 2, 4, 2], true, false, OptionError::Malformed),
        (&[8, 10, 0, 0], true, false, OptionError::Malformed),
        (
            &[5, 10, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0],
            false,
            true,
            OptionError::Malformed,
        ),
        (&[0, 1, 0, 0], true, false, OptionError::Malformed),
        (&[30, 4, 0, 0], true, false, OptionError::Unsupported),
        (&[2, 4, 5, 6], false, true, OptionError::WrongContext),
        (&[3, 3, 7, 0], false, true, OptionError::WrongContext),
        (&[4, 2, 0, 0], false, true, OptionError::WrongContext),
    ];
    for (bytes, syn, ack, expected) in cases {
        assert_eq!(parse(bytes, *syn, *ack), Err(*expected), "{bytes:?}");
    }
    assert_eq!(parse(&[1; 44], true, false), Err(OptionError::Malformed));
}

#[test]
fn arbitrary_options_and_packet_inputs_are_bounded_and_do_not_panic() {
    let mut seed = 0x63f0a1d5u32;
    for n in 0..10000 {
        let mut bytes = vec![0; n % 80];
        for b in &mut bytes {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            *b = seed as u8;
        }
        let _ = parse(&bytes, seed & 1 != 0, seed & 2 != 0);
        let _ = verify_tcp(&bytes);
    }
}
