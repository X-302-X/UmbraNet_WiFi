use umbranet_dpi::traffic::{
    checksum::{verify_tcp, ChecksumError},
    packet::{parse_ip, PacketError},
    synthetic_split::{split_fixture, SplitError, MAX_SEGMENTS},
};

fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
const V4: &str =
    "4500002c007b000040068e1ac0000201c63364029c4001bb00000064000001f5501804d259a4000061626364";
const V6: &str = "600000000018064020010db800000000000000000000000120010db80000000000000000000000029c4001bb00000064000001f5501804d2ea66000061626364";
const V4_EXPECTED: [&str; 3] = [
    "45000029007b000040068e1dc0000201c63364029c4001bb00000064000001f5501004d2bd75000061",
    "4500002a007b000040068e1cc0000201c63364029c4001bb00000065000001f5501004d2bc1000006263",
    "45000029007b000040068e1dc0000201c63364029c4001bb00000067000001f5501804d2ba6a000064",
];
const V6_EXPECTED: [&str; 3] = [
    "600000000015064020010db800000000000000000000000120010db80000000000000000000000029c4001bb00000064000001f5501004d24e38000061",
    "600000000016064020010db800000000000000000000000120010db80000000000000000000000029c4001bb00000065000001f5501004d24cd300006263",
    "600000000015064020010db800000000000000000000000120010db80000000000000000000000029c4001bb00000067000001f5501804d24b2d000064",
];

// Тестовый генератор контрольных сумм, независимый от реализации split_fixture.
fn checksum(bytes: &[u8]) -> u16 {
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
fn seal(raw: &mut [u8]) {
    let v6 = raw[0] >> 4 == 6;
    let n = if v6 { 40 } else { ((raw[0] & 15) * 4) as usize };
    let raw_len = raw.len();
    if v6 {
        raw[4..6].copy_from_slice(&((raw_len - 40) as u16).to_be_bytes());
    } else {
        raw[2..4].copy_from_slice(&(raw_len as u16).to_be_bytes());
    }
    raw[n + 16..n + 18].fill(0);
    let mut pseudo = if v6 {
        raw[8..40].to_vec()
    } else {
        raw[12..20].to_vec()
    };
    if v6 {
        pseudo.extend_from_slice(&((raw.len() - n) as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 6]);
    } else {
        pseudo.extend_from_slice(&[0, 6]);
        pseudo.extend_from_slice(&((raw.len() - n) as u16).to_be_bytes());
    }
    pseudo.extend_from_slice(&raw[n..]);
    raw[n + 16..n + 18].copy_from_slice(&checksum(&pseudo).to_be_bytes());
    if !v6 {
        raw[10..12].fill(0);
        let x = checksum(&raw[..n]);
        raw[10..12].copy_from_slice(&x.to_be_bytes());
    }
}
fn fixture(v6: bool, payload: &[u8], seq: u32, flags: u8) -> Vec<u8> {
    let mut raw = hex(if v6 { V6 } else { V4 });
    let n = if v6 { 40 } else { 20 };
    raw.truncate(n + 20);
    raw.extend_from_slice(payload);
    raw[n + 4..n + 8].copy_from_slice(&seq.to_be_bytes());
    raw[n + 13] = flags;
    seal(&mut raw);
    raw
}

#[test]
fn output_matches_independent_scapy_vectors_exactly() {
    for (input, expected) in [(V4, V4_EXPECTED), (V6, V6_EXPECTED)] {
        let original = hex(input);
        let segments = split_fixture(&original, &[1, 3]).unwrap();
        assert_eq!(segments.len(), 3);
        for (actual, expected) in segments.iter().zip(expected) {
            assert_eq!(actual.bytes(), hex(expected));
            assert_eq!(verify_tcp(actual.bytes()), Ok(()));
        }
        assert_eq!(original, hex(input));
    }
}

#[test]
fn each_split_preserves_data_sequence_flags_headers_and_checksums() {
    for v6 in [false, true] {
        for flags in [0x10, 0x18] {
            for n in 2..90 {
                let data: Vec<u8> = (0..n).map(|i| (i * 71) as u8).collect();
                let seq = u32::MAX - 2;
                let original = fixture(v6, &data, seq, flags);
                let original_copy = original.clone();
                for cut in 1..n {
                    let out = split_fixture(&original, &[cut]).unwrap();
                    let mut joined = vec![];
                    for (index, part) in out.iter().enumerate() {
                        let packet = parse_ip(part.bytes()).unwrap();
                        let tcp = packet.tcp.unwrap();
                        assert_eq!(packet.source_port, 40000);
                        assert_eq!(packet.destination_port, 443);
                        assert_eq!(tcp.acknowledgment, 501);
                        assert_eq!(tcp.window, 1234);
                        assert_eq!(
                            tcp.sequence,
                            seq.wrapping_add(if index == 0 { 0 } else { cut as u32 })
                        );
                        assert_eq!(tcp.flags, if index == 0 { 0x10 } else { flags });
                        assert_eq!(verify_tcp(part.bytes()), Ok(()));
                        joined.extend_from_slice(packet.payload);
                    }
                    assert_eq!(joined, data);
                }
                assert_eq!(original, original_copy);
            }
        }
    }
}

#[test]
fn segments_are_bounded_and_cuts_must_be_strictly_internal() {
    let input = fixture(false, &[9; 40], 100, 0x18);
    for cuts in [
        &[][..],
        &[0][..],
        &[40][..],
        &[41][..],
        &[5, 5][..],
        &[6, 4][..],
        &[usize::MAX][..],
    ] {
        assert_eq!(split_fixture(&input, cuts), Err(SplitError::InvalidCuts));
    }
    let max: Vec<usize> = (1..MAX_SEGMENTS).collect();
    assert_eq!(split_fixture(&input, &max).unwrap().len(), MAX_SEGMENTS);
    let excess: Vec<usize> = (1..=MAX_SEGMENTS).collect();
    assert_eq!(
        split_fixture(&input, &excess),
        Err(SplitError::TooManySegments)
    );
    let empty = fixture(false, b"", 100, 0x10);
    assert_eq!(split_fixture(&empty, &[1]), Err(SplitError::EmptyPayload));
    let one = fixture(false, b"x", 100, 0x10);
    assert_eq!(split_fixture(&one, &[1]), Err(SplitError::InvalidCuts));
}

#[test]
fn unsupported_flags_headers_options_and_invalid_checksums_are_rejected() {
    for flags in [0, 0x02, 0x12, 0x11, 0x14, 0x30, 0x50, 0x90] {
        let original = fixture(false, b"abcd", 100, flags);
        assert_eq!(split_fixture(&original, &[1]), Err(SplitError::Unsupported));
    }
    let mut flags = fixture(false, b"abcd", 100, 0x18);
    flags[32] |= 1;
    seal(&mut flags);
    assert_eq!(split_fixture(&flags, &[1]), Err(SplitError::Unsupported));
    let mut urgent = fixture(false, b"abcd", 100, 0x18);
    urgent[39] = 1;
    seal(&mut urgent);
    assert_eq!(split_fixture(&urgent, &[1]), Err(SplitError::Unsupported));
    let mut options = fixture(false, b"abcd", 100, 0x18);
    options.splice(40..40, [1, 1, 1, 1]);
    options[32] = 0x60;
    seal(&mut options);
    assert_eq!(split_fixture(&options, &[1]), Err(SplitError::Unsupported));
    let mut trailing = hex(V4);
    trailing.push(0);
    assert_eq!(split_fixture(&trailing, &[1]), Err(SplitError::Unsupported));
    let mut tcp = hex(V4);
    *tcp.last_mut().unwrap() ^= 1;
    assert_eq!(
        split_fixture(&tcp, &[1]),
        Err(SplitError::Checksum(ChecksumError::Tcp))
    );
    let mut ip = hex(V4);
    ip[8] ^= 1;
    assert_eq!(
        split_fixture(&ip, &[1]),
        Err(SplitError::Checksum(ChecksumError::Ipv4Header))
    );
    let mut fragment = hex(V4);
    fragment[6] = 0x20;
    assert_eq!(
        split_fixture(&fragment, &[1]),
        Err(SplitError::Packet(PacketError::Fragmented))
    );
    let mut ext = hex(V6);
    ext[6] = 44;
    assert_eq!(
        split_fixture(&ext, &[1]),
        Err(SplitError::Packet(PacketError::Unsupported))
    );
}

#[test]
fn all_shorter_packets_and_random_inputs_fail_without_panics() {
    for s in [V4, V6] {
        let p = hex(s);
        for len in 0..p.len() {
            assert!(split_fixture(&p[..len], &[1]).is_err());
        }
    }
    let mut state = 0x12345678u32;
    for n in 0..5000 {
        let mut input = vec![0; n % 128];
        for b in &mut input {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *b = state as u8;
        }
        let _ = split_fixture(&input, &[0, (state as usize) % 128, usize::MAX]);
    }
}
