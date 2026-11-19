//! Агрегаты пассивной TCP-проверки. Содержимое и адреса здесь не сохраняются.
//! Совпадение суммы, размер и флаги не определяют LSO и не доказывают цель.
use crate::capture::{address::WinDivertAddress, tcp_checksum};
use serde::Serialize;

#[derive(Debug, Clone, Copy)]
pub struct PacketFacts {
    outbound: bool,
    ipv6: bool,
    large: bool,
    checks: Option<Checks>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Checks {
    tcp_flag: bool,
    tcp_valid: bool,
    ipv4: Option<(bool, bool)>,
}
impl PacketFacts {
    /// Буфер и адрес используются только во время вызова, возвращаются лишь факты.
    pub fn from_packet(raw: &[u8], address: &WinDivertAddress) -> Self {
        let checks = tcp_checksum::checksums_for_capture(raw, address)
            .ok()
            .map(|s| Checks {
                tcp_flag: address.tcp_checksum(),
                tcp_valid: s.tcp_valid,
                ipv4: s
                    .ipv4_header_valid
                    .map(|valid| (address.ip_checksum(), valid)),
            });
        Self {
            outbound: address.outbound(),
            ipv6: address.ipv6(),
            large: raw.len() > 1500,
            checks,
        }
    }
}
#[derive(Debug, Default, Clone, Serialize)]
pub struct Matrix {
    pub flag_set_valid: u64,
    pub flag_set_invalid: u64,
    pub flag_unset_valid: u64,
    pub flag_unset_invalid: u64,
}
impl Matrix {
    fn add(&mut self, flag: bool, valid: bool) {
        let v = match (flag, valid) {
            (true, true) => &mut self.flag_set_valid,
            (true, false) => &mut self.flag_set_invalid,
            (false, true) => &mut self.flag_unset_valid,
            (false, false) => &mut self.flag_unset_invalid,
        };
        *v = v.saturating_add(1);
    }
}
#[derive(Debug, Default, Clone, Serialize)]
pub struct DirectionStats {
    pub total: u64,
    pub ipv4: u64,
    pub ipv6: u64,
    pub over_1500_bytes: u64,
    pub unsupported: u64,
    pub tcp_checksum: Matrix,
    pub ipv4_checksum: Matrix,
}
impl DirectionStats {
    fn record(&mut self, packet: PacketFacts) {
        self.total = self.total.saturating_add(1);
        let version = if packet.ipv6 {
            &mut self.ipv6
        } else {
            &mut self.ipv4
        };
        *version = version.saturating_add(1);
        if packet.large {
            self.over_1500_bytes = self.over_1500_bytes.saturating_add(1);
        }
        match packet.checks {
            Some(c) => {
                self.tcp_checksum.add(c.tcp_flag, c.tcp_valid);
                if let Some((flag, valid)) = c.ipv4 {
                    self.ipv4_checksum.add(flag, valid);
                }
            }
            None => self.unsupported = self.unsupported.saturating_add(1),
        }
    }
}
#[derive(Debug, Default, Clone, Serialize)]
pub struct TcpStats {
    pub outbound: DirectionStats,
    pub inbound: DirectionStats,
}
impl TcpStats {
    pub fn record(&mut self, facts: PacketFacts) {
        if facts.outbound {
            &mut self.outbound
        } else {
            &mut self.inbound
        }
        .record(facts);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bytes(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks_exact(2)
            .map(|n| u8::from_str_radix(std::str::from_utf8(n).unwrap(), 16).unwrap())
            .collect()
    }
    const V4: &str =
        "4500002b007b000040068e1bc0000201c63364029c4001bb00000064000001f5501804d25a090000616263";
    const V6:&str="600000000017064020010db800000000000000000000000120010db80000000000000000000000029c4001bb00000064000001f5501804d2eacb0000616263";
    #[test]
    fn optimized_checks_match_previous_inspect_then_recompute_policy() {
        fn previous(raw: &[u8], address: &WinDivertAddress) -> Option<Checks> {
            let eligible = matches!(
                tcp_checksum::inspect(raw, address),
                Ok(_)
                    | Err(tcp_checksum::Error::ContradictoryChecksum
                        | tcp_checksum::Error::UnverifiedInbound)
            );
            if !eligible {
                return None;
            }
            crate::traffic::checksum::tcp_checksums(raw)
                .ok()
                .map(|s| Checks {
                    tcp_flag: address.tcp_checksum(),
                    tcp_valid: s.tcp_valid,
                    ipv4: s
                        .ipv4_header_valid
                        .map(|valid| (address.ip_checksum(), valid)),
                })
        }
        for (fixture, version) in [(V4, 0), (V6, 1 << 20)] {
            let original = bytes(fixture);
            for mutation in 0..original.len() + 4 {
                let mut p = original.clone();
                if mutation < original.len() {
                    p[mutation] ^= 0x81;
                } else if mutation == original.len() {
                    p.pop();
                } else if mutation == original.len() + 1 {
                    p.push(0);
                }
                for flags in [
                    0,
                    1 << 17,
                    1 << 21,
                    1 << 22,
                    (1 << 17) | (1 << 21) | (1 << 22),
                    1 << 18,
                    1 << 19,
                    1 << 8,
                ] {
                    let a = WinDivertAddress::from_test_bits(version | flags);
                    assert_eq!(
                        PacketFacts::from_packet(&p, &a).checks,
                        previous(&p, &a),
                        "mutation={mutation} flags={flags:#x}"
                    );
                }
            }
        }
    }
    #[test]
    fn matrix_separates_flags_from_byte_sums_without_retaining_packet_data() {
        let mut stats = TcpStats::default();
        let valid = bytes(V4);
        let mut bad = valid.clone();
        bad[36] ^= 1;
        for (p, bits) in [
            (&valid, (1 << 17) | (1 << 21) | (1 << 22)),
            (&valid, 1 << 17),
            (&bad, (1 << 17) | (1 << 21) | (1 << 22)),
            (&bad, 1 << 17),
        ] {
            stats.record(PacketFacts::from_packet(
                p,
                &WinDivertAddress::from_test_bits(bits),
            ));
        }
        assert_eq!(stats.outbound.total, 4);
        let m = &stats.outbound.tcp_checksum;
        assert_eq!(
            (
                m.flag_set_valid,
                m.flag_set_invalid,
                m.flag_unset_valid,
                m.flag_unset_invalid
            ),
            (1, 1, 1, 1)
        );
        assert_eq!(stats.outbound.ipv4_checksum.flag_set_valid, 2);
        assert_eq!(stats.outbound.ipv4_checksum.flag_unset_valid, 2);
        let json = serde_json::to_string(&stats).unwrap();
        assert!(!json.contains("192.0.2.1"));
        assert!(!json.contains("616263"));
    }
    #[test]
    fn ipv6_inbound_and_unsupported_have_separate_counts() {
        let mut stats = TcpStats::default();
        let p = bytes(V6);
        stats.record(PacketFacts::from_packet(
            &p,
            &WinDivertAddress::from_test_bits((1 << 20) | (1 << 22)),
        ));
        let mut bad = p.clone();
        bad[56] ^= 1;
        stats.record(PacketFacts::from_packet(
            &bad,
            &WinDivertAddress::from_test_bits(1 << 20),
        ));
        stats.record(PacketFacts::from_packet(
            &vec![0; 1501],
            &WinDivertAddress::from_test_bits(1 << 20),
        ));
        assert_eq!(
            (
                stats.inbound.total,
                stats.inbound.ipv6,
                stats.inbound.unsupported,
                stats.inbound.over_1500_bytes
            ),
            (3, 3, 1, 1)
        );
        assert_eq!(stats.inbound.tcp_checksum.flag_set_valid, 1);
        assert_eq!(stats.inbound.tcp_checksum.flag_unset_invalid, 1);
        assert_eq!(stats.inbound.ipv4_checksum.flag_set_valid, 0);
    }
}
