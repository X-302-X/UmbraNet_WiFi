use umbranet_dpi::{
    engine::Engine,
    strategy::Strategy,
    traffic::filter::{HostList, IpSet},
};

fn udp(payload: &[u8], port: u16) -> Vec<u8> {
    let mut p = vec![0; 28 + payload.len()];
    let len = p.len() as u16;
    p[0] = 0x45;
    p[2..4].copy_from_slice(&len.to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&[192, 0, 2, 1]);
    p[16..20].copy_from_slice(&[203, 0, 113, 53]);
    p[20..22].copy_from_slice(&50000u16.to_be_bytes());
    p[22..24].copy_from_slice(&port.to_be_bytes());
    p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p[28..].copy_from_slice(payload);
    p
}

#[test]
fn unverified_quic_and_stun_are_never_modified_even_with_matching_ip() {
    let strategy =
        Strategy::from_json(include_str!("../../../strtegs_Uz/quic-bypass.json")).unwrap();
    let mut quic = [0u8; 12];
    quic[..5].copy_from_slice(&[0xc0, 0, 0, 0, 1]);
    let mut stun = [0u8; 20];
    stun[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
    let list = HostList::from_lines(["youtube.com"]);
    for set in [IpSet::default(), IpSet::from_lines(["203.0.113.53"])] {
        let mut engine = Engine::new(strategy.clone(), list.clone(), set);
        for raw in [udp(&quic, 443), udp(&stun, 50001)] {
            assert_eq!(engine.process_packet(&raw, true), vec![raw]);
        }
    }
}
