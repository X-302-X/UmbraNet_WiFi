use umbranet_dpi::{
    catalog::Catalog,
    selection::Selection,
    strategy::Strategy,
    traffic::{
        application::{inspect_tcp, Evidence},
        classifier::{classify, Match},
        packet::{parse_ip, PacketError, Protocol},
    },
};

fn tcp_payload(data: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 20];
    bytes[0..2].copy_from_slice(&40000u16.to_be_bytes());
    bytes[2..4].copy_from_slice(&443u16.to_be_bytes());
    bytes[12] = 0x50;
    bytes.extend_from_slice(data);
    bytes
}
fn ipv4(proto: u8, data: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 20];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&((20 + data.len()) as u16).to_be_bytes());
    bytes[9] = proto;
    bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
    bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
    bytes.extend_from_slice(data);
    bytes
}
fn ipv6(proto: u8, data: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 40];
    bytes[0] = 0x60;
    bytes[4..6].copy_from_slice(&(data.len() as u16).to_be_bytes());
    bytes[6] = proto;
    bytes[23] = 1;
    bytes[39] = 2;
    bytes.extend_from_slice(data);
    bytes
}
fn extension(ty: u16, data: &[u8]) -> Vec<u8> {
    let mut out = vec![];
    out.extend_from_slice(&ty.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}
fn hello(host: &str, ech: bool) -> Vec<u8> {
    let mut names = vec![0];
    names.extend_from_slice(&(host.len() as u16).to_be_bytes());
    names.extend_from_slice(host.as_bytes());
    let mut sni = (names.len() as u16).to_be_bytes().to_vec();
    sni.extend_from_slice(&names);
    let mut extensions = extension(0, &sni);
    if ech {
        extensions.extend_from_slice(&extension(0xfe0d, &[1, 2, 3]));
    }
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    let mut hs = vec![
        1,
        ((body.len() >> 16) & 255) as u8,
        ((body.len() >> 8) & 255) as u8,
        body.len() as u8,
    ];
    hs.extend_from_slice(&body);
    let mut record = vec![22, 3, 1];
    record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    record.extend_from_slice(&hs);
    record
}
fn snapshot() -> umbranet_dpi::selection::Snapshot {
    let cat = Catalog::from_json(include_str!("../services.json")).unwrap();
    let strategy =
        Strategy::from_json(include_str!("../../../strtegs_Uz/pass-through.json")).unwrap();
    let mut selection = Selection::default();
    selection.add_domain("example.com").unwrap();
    selection.add_domain("api.example.com").unwrap();
    selection.add_process("Discord.exe").unwrap();
    selection.snapshot(&cat, &strategy).unwrap()
}

#[test]
fn ipv4_tcp_and_ipv6_udp_are_bounded() {
    let raw = ipv4(6, &tcp_payload(b"hello"));
    let packet = parse_ip(&raw).unwrap();
    assert_eq!(packet.source.to_string(), "192.0.2.1");
    assert_eq!(packet.destination_port, 443);
    assert_eq!(packet.protocol, Protocol::Tcp);
    assert_eq!(packet.payload, b"hello");
    let mut udp = vec![0, 53, 0x30, 0x39, 0, 11, 0, 0];
    udp.extend_from_slice(b"abc");
    let raw = ipv6(17, &udp);
    let packet = parse_ip(&raw).unwrap();
    assert_eq!(packet.protocol, Protocol::Udp);
    assert_eq!(packet.source_port, 53);
    assert_eq!(packet.payload, b"abc");
}
#[test]
fn no_classification_of_fragments_or_ipv6_extensions() {
    let mut raw = ipv4(6, &tcp_payload(b""));
    raw[6] = 0x20;
    assert_eq!(parse_ip(&raw), Err(PacketError::Fragmented));
    raw[6] = 0;
    raw[7] = 1;
    assert_eq!(parse_ip(&raw), Err(PacketError::Fragmented));
    assert_eq!(parse_ip(&ipv6(44, &[0; 8])), Err(PacketError::Unsupported));
}
#[test]
fn malformed_packet_lengths_fail_closed() {
    let mut p = ipv4(6, &tcp_payload(b"hello"));
    p[2..4].copy_from_slice(&200u16.to_be_bytes());
    assert_eq!(parse_ip(&p), Err(PacketError::Truncated));
    p[2..4].copy_from_slice(&10u16.to_be_bytes());
    assert_eq!(parse_ip(&p), Err(PacketError::Invalid));
    let mut tcp = tcp_payload(b"");
    tcp[12] = 0x40;
    assert_eq!(parse_ip(&ipv4(6, &tcp)), Err(PacketError::Invalid));
    let udp = [0, 1, 0, 2, 0, 4, 0, 0];
    assert_eq!(parse_ip(&ipv4(17, &udp)), Err(PacketError::Invalid));
}
#[test]
fn plain_http_host_requires_complete_valid_unambiguous_request() {
    assert_eq!(
        inspect_tcp(
            b"GET /x HTTP/1.1\r\nHost: API.Example.com:443\r\n\r\n",
            true
        ),
        Evidence::HttpHost("api.example.com".into())
    );
    for input in [
        &b"GET / HTTP/1.1\r\nHost: example.com\r\n"[..],
        &b"GET / HTTP/1.1\r\nHost: example.com\r\nHost: other.com\r\n\r\n"[..],
        &b"GET http://other.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"[..],
        &b"GET / HTTP/1.1\r\nHost: example.com:99999\r\n\r\n"[..],
    ] {
        assert_eq!(inspect_tcp(input, true), Evidence::Unknown);
    }
    assert_eq!(
        inspect_tcp(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", false),
        Evidence::Unknown
    );
}
#[test]
fn tls_clienthello_sni_and_ech_are_distinguished() {
    assert_eq!(
        inspect_tcp(&hello("API.Example.com", false), true),
        Evidence::TlsServerName("api.example.com".into())
    );
    assert_eq!(
        inspect_tcp(&hello("example.com", true), true),
        Evidence::EncryptedClientHello
    );
    let full = hello("example.com", false);
    for len in 0..full.len() {
        assert_eq!(inspect_tcp(&full[..len], true), Evidence::Unknown);
    }
    assert_eq!(inspect_tcp(&full, false), Evidence::Unknown);
}
#[test]
fn classifier_uses_specific_domain_and_only_verified_manual_processes() {
    let s = snapshot();
    assert_eq!(
        classify(
            &s,
            &Evidence::TlsServerName("sub.api.example.com".into()),
            None
        ),
        Match::Domain("api.example.com".into())
    );
    assert_eq!(
        classify(&s, &Evidence::TlsServerName("notexample.com".into()), None),
        Match::Unknown
    );
    assert_eq!(
        classify(&s, &Evidence::EncryptedClientHello, None),
        Match::Unknown
    );
    assert_eq!(
        classify(&s, &Evidence::Unknown, Some("DISCORD.EXE")),
        Match::Process("discord.exe".into())
    );
    assert_eq!(
        classify(&s, &Evidence::Unknown, Some("chrome.exe")),
        Match::Unknown
    );
    assert_eq!(classify(&s, &Evidence::Unknown, None), Match::Unknown);
}
#[test]
fn packet_and_http_evidence_work_together_on_synthetic_bytes() {
    let data = b"GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
    let raw = ipv4(6, &tcp_payload(data));
    let parsed = parse_ip(&raw).unwrap();
    let evidence = inspect_tcp(parsed.payload, true);
    assert_eq!(
        classify(&snapshot(), &evidence, None),
        Match::Domain("api.example.com".into())
    );
}
#[test]
fn arbitrary_short_inputs_do_not_panic() {
    let mut seed = 0x12345678u32;
    for n in 0..3000 {
        let size = n % 160;
        let mut bytes = vec![0; size];
        for b in &mut bytes {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            *b = seed as u8;
        }
        let _ = parse_ip(&bytes);
        let _ = inspect_tcp(&bytes, true);
    }
}
