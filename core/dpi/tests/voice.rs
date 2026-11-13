use umbranet_dpi::{
    catalog::Catalog,
    selection::Selection,
    strategy::Strategy,
    traffic::{
        classifier::{classify_udp, Match},
        voice::{inspect_udp, DiscoveryKind, UdpEvidence},
    },
};

fn stun() -> Vec<u8> {
    let mut b = vec![0u8; 20];
    b[0..2].copy_from_slice(&1u16.to_be_bytes());
    b[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
    b
}
fn discovery(kind: u16) -> Vec<u8> {
    let mut b = vec![0u8; 74];
    b[0..2].copy_from_slice(&kind.to_be_bytes());
    b[2..4].copy_from_slice(&70u16.to_be_bytes());
    b[4..8].copy_from_slice(&[1, 2, 3, 4]);
    b
}
fn snapshot() -> umbranet_dpi::selection::Snapshot {
    let c = Catalog::from_json(include_str!("../services.json")).unwrap();
    let strategy =
        Strategy::from_json(include_str!("../../../strtegs_Uz/pass-through.json")).unwrap();
    let mut selection = Selection::default();
    selection.set_service(&c, "discord", true).unwrap();
    selection.add_process("Discord.exe").unwrap();
    selection.snapshot(&c, &strategy).unwrap()
}

#[test]
fn detects_stun_with_or_without_padded_attributes() {
    let mut b = stun();
    assert_eq!(inspect_udp(&b), UdpEvidence::Stun);
    b[2..4].copy_from_slice(&8u16.to_be_bytes());
    b.extend_from_slice(&[0, 6, 0, 3, b'a', b'b', b'c', 0]);
    assert_eq!(inspect_udp(&b), UdpEvidence::Stun);
}
#[test]
fn rejects_bad_cookie_reserved_bits_and_length() {
    let mut b = stun();
    b[4] = 0;
    assert_eq!(inspect_udp(&b), UdpEvidence::Unknown);
    let mut b = stun();
    b[0] = 0x80;
    assert_eq!(inspect_udp(&b), UdpEvidence::Unknown);
    let mut b = stun();
    b[3] = 1;
    assert_eq!(inspect_udp(&b), UdpEvidence::Unknown);
    let mut b = stun();
    b[3] = 4;
    assert_eq!(inspect_udp(&b), UdpEvidence::Unknown);
    let mut b = stun();
    b[3] = 4;
    b.extend_from_slice(&[0, 6, 0, 3]);
    assert_eq!(inspect_udp(&b), UdpEvidence::Unknown);
}
#[test]
fn detects_documented_discovery_format_without_saving_contents() {
    assert_eq!(
        inspect_udp(&discovery(1)),
        UdpEvidence::DiscordIpDiscovery(DiscoveryKind::Request)
    );
    assert_eq!(
        inspect_udp(&discovery(2)),
        UdpEvidence::DiscordIpDiscovery(DiscoveryKind::Response)
    );
    assert_eq!(inspect_udp(&discovery(3)), UdpEvidence::Unknown);
    let mut bad = discovery(1);
    bad[3] = 69;
    assert_eq!(inspect_udp(&bad), UdpEvidence::Unknown);
    assert_eq!(inspect_udp(&discovery(1)[..73]), UdpEvidence::Unknown);
}
#[test]
fn discovery_and_stun_are_not_automatically_attributed_to_discord() {
    let s = snapshot();
    assert_eq!(classify_udp(&s, None), Match::Unknown);
    assert_eq!(classify_udp(&s, Some("other.exe")), Match::Unknown);
    assert_eq!(
        classify_udp(&s, Some("DISCORD.EXE")),
        Match::Process("discord.exe".into())
    );
}
#[test]
fn short_and_arbitrary_inputs_are_safe() {
    let d = discovery(1);
    for i in 0..d.len() {
        let _ = inspect_udp(&d[..i]);
    }
    let mut seed = 0x12345678u32;
    for n in 0..3000 {
        let mut b = vec![0; n % 100];
        for byte in &mut b {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            *byte = seed as u8;
        }
        let _ = inspect_udp(&b);
    }
}
