//! Локальный синтетический микробенчмарк подсчёта TCP-статистики (не сеть).
//! cargo run --release --manifest-path core/dpi/Cargo.toml --example tcp_stats_bench
//! Результаты не измеряют WinDivert, WebView, LSO, потери и работу на Windows.
use std::{hint::black_box, time::Instant};
use umbranet_dpi::{
    capture::address::WinDivertAddress,
    diagnostics::tcp_stats::{PacketFacts, TcpStats},
};

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u64;
    for word in bytes.chunks(2) {
        sum += u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)]) as u64;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
fn packet(total: usize) -> Vec<u8> {
    assert!((40..=65535).contains(&total));
    let mut raw = vec![0u8; total];
    raw[0] = 0x45;
    raw[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    raw[8] = 64;
    raw[9] = 6;
    raw[12..16].copy_from_slice(&[192, 0, 2, 1]);
    raw[16..20].copy_from_slice(&[198, 51, 100, 2]);
    raw[20..22].copy_from_slice(&40000u16.to_be_bytes());
    raw[22..24].copy_from_slice(&443u16.to_be_bytes());
    raw[32] = 0x50;
    raw[33] = 0x18;
    raw[34..36].copy_from_slice(&1234u16.to_be_bytes());
    for (i, b) in raw[40..].iter_mut().enumerate() {
        *b = (i.wrapping_mul(37) & 0xff) as u8;
    }
    let ip = checksum(&raw[..20]);
    raw[10..12].copy_from_slice(&ip.to_be_bytes());
    let mut pseudo = Vec::with_capacity(12 + total - 20);
    pseudo.extend_from_slice(&raw[12..20]);
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&((total - 20) as u16).to_be_bytes());
    pseudo.extend_from_slice(&raw[20..]);
    let tcp = checksum(&pseudo);
    raw[36..38].copy_from_slice(&tcp.to_be_bytes());
    raw
}
fn main() {
    let mut addr = WinDivertAddress::default();
    addr.set_outbound(true);
    for (length, iterations) in [(64, 3_000_000u64), (1500, 600_000), (8192, 150_000)] {
        let p = packet(length);
        let mut stats = TcpStats::default();
        let start = Instant::now();
        for _ in 0..iterations {
            stats.record(PacketFacts::from_packet(black_box(&p), black_box(&addr)));
        }
        let elapsed = start.elapsed();
        assert_eq!(stats.outbound.total, iterations);
        assert_eq!(stats.outbound.tcp_checksum.flag_unset_valid, iterations);
        println!("IPv4 {length:5} bytes: {iterations:7} packets in {:.3} s; {:.0} ns/packet; {:.0} packets/s",elapsed.as_secs_f64(),elapsed.as_nanos() as f64 / iterations as f64, iterations as f64 / elapsed.as_secs_f64());
        black_box(stats);
    }
}
