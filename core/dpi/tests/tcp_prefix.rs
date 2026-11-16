use umbranet_dpi::traffic::{
    application::Evidence,
    stream::{StreamError, TcpPrefix, MAX_PREFIX_BYTES},
};

fn hello(host: &str, ech: bool) -> Vec<u8> {
    let mut names = vec![0];
    names.extend_from_slice(&(host.len() as u16).to_be_bytes());
    names.extend_from_slice(host.as_bytes());
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
    let mut handshake = vec![1, 0, 0, body.len() as u8];
    handshake.extend_from_slice(&body);
    let mut record = vec![22, 3, 1];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[test]
fn tls_at_every_split_and_reverse_delivery() {
    let raw = hello("api.example.com", false);
    for split in 1..raw.len() {
        let mut stream = TcpPrefix::new(1000, 1024).unwrap();
        stream.insert(1001 + split as u32, &raw[split..]).unwrap();
        assert_eq!(stream.prefix().unwrap(), b"");
        assert_eq!(stream.evidence().unwrap(), Evidence::Unknown);
        stream.insert(1001, &raw[..split]).unwrap();
        assert_eq!(stream.prefix().unwrap(), raw);
        assert_eq!(
            stream.evidence().unwrap(),
            Evidence::TlsServerName("api.example.com".into())
        );
    }
}

#[test]
fn http_appears_only_after_gap_is_filled() {
    let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mut stream = TcpPrefix::new(40, 128).unwrap();
    stream.insert(41, &raw[..4]).unwrap();
    stream.insert(51, &raw[10..]).unwrap();
    assert_eq!(stream.prefix().unwrap(), &raw[..4]);
    assert_eq!(stream.evidence().unwrap(), Evidence::Unknown);
    stream.insert(45, &raw[4..10]).unwrap();
    assert_eq!(
        stream.evidence().unwrap(),
        Evidence::HttpHost("example.com".into())
    );
}

#[test]
fn retransmissions_allowed_conflicts_invalidate_even_after_evidence() {
    let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mut stream = TcpPrefix::new(10, 128).unwrap();
    stream.insert(11, raw).unwrap();
    stream.insert(11, raw).unwrap();
    stream.insert(15, &raw[4..20]).unwrap();
    assert!(matches!(stream.evidence().unwrap(), Evidence::HttpHost(_)));
    assert_eq!(
        stream.insert(11, b"BAD"),
        Err(StreamError::ConflictingOverlap)
    );
    assert_eq!(stream.evidence(), Err(StreamError::Poisoned));
    assert_eq!(stream.insert(11, raw), Err(StreamError::Poisoned));
}

#[test]
fn conflicting_out_of_order_overlap_and_outside_window_fail_closed() {
    let mut stream = TcpPrefix::new(100, 8).unwrap();
    stream.insert(105, b"ab").unwrap();
    assert_eq!(
        stream.insert(104, b"xbc"),
        Err(StreamError::ConflictingOverlap)
    );
    assert_eq!(stream.prefix(), Err(StreamError::Poisoned));
    for (seq, bytes) in [(100, &b"x"[..]), (109, &b"x"[..]), (108, &b"xy"[..])] {
        let mut stream = TcpPrefix::new(100, 8).unwrap();
        assert_eq!(stream.insert(seq, bytes), Err(StreamError::OutsideWindow));
        assert_eq!(stream.prefix(), Err(StreamError::Poisoned));
    }
}

#[test]
fn sequence_wrap_and_exact_limits() {
    let mut stream = TcpPrefix::new(u32::MAX - 2, 4).unwrap();
    stream.insert(0, b"cd").unwrap();
    stream.insert(u32::MAX - 1, b"ab").unwrap();
    assert_eq!(stream.prefix().unwrap(), b"abcd");
    assert_eq!(stream.insert(2, b"e"), Err(StreamError::OutsideWindow));
    assert!(matches!(
        TcpPrefix::new(0, 0),
        Err(StreamError::InvalidLimit)
    ));
    assert!(matches!(
        TcpPrefix::new(0, MAX_PREFIX_BYTES + 1),
        Err(StreamError::InvalidLimit)
    ));
    assert!(TcpPrefix::new(0, MAX_PREFIX_BYTES).is_ok());
}

#[test]
fn ech_does_not_expose_outer_sni_even_when_segmented() {
    let raw = hello("example.com", true);
    let mut stream = TcpPrefix::new(7, 1024).unwrap();
    for (i, byte) in raw.iter().enumerate() {
        stream.insert(8 + i as u32, &[*byte]).unwrap();
    }
    assert_eq!(stream.evidence().unwrap(), Evidence::EncryptedClientHello);
}

#[test]
fn truncations_and_short_random_fragments_never_panic() {
    let raw = hello("example.com", false);
    for len in 0..raw.len() {
        let mut stream = TcpPrefix::new(0, 1024).unwrap();
        stream.insert(1, &raw[..len]).unwrap();
        assert_eq!(stream.evidence().unwrap(), Evidence::Unknown);
    }
    let mut state = 0x12345678u32;
    for _ in 0..2000 {
        let mut stream = TcpPrefix::new(0, 128).unwrap();
        for _ in 0..8 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let len = (state as usize) % 8;
            let offset = ((state >> 8) as usize) % 128;
            let bytes = vec![state as u8; len];
            let _ = stream.insert(1 + offset as u32, &bytes);
            let _ = stream.evidence();
        }
    }
}
