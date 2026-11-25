//! Консервативная проверка байтов и метаданных WinDivert 2.2.
//! В исходниках драйвера 2.2.2 исходящие флаги образуются из NBL transmit
//! checksum metadata, а WinDivertSend может пересчитать флаги со значением 0:
//! https://github.com/basil00/WinDivert/blob/v2.2.2/sys/windivert.c
//! Это не независимая проверка checksum и не доказательство побайтового wire.
//! Не устанавливает подлинность пакета, выбранную цель или отсутствие LSO.
//! Непроверенные offload-пакеты остаются неизменёнными; они не доказательство.
use super::address::WinDivertAddress;
use crate::traffic::checksum::{tcp_checksums, ChecksumError, TcpChecksums};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    /// Байты проходят вычисление. Это не подтверждает доставку/цель.
    ValidBytes,
    /// На исходящем пакете неустановленный флаг допускает offload, но его
    /// наличие не доказано. Никакой классификации или модификации на этом основании.
    UnverifiedOutbound,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Metadata,
    InvalidLength,
    Packet(ChecksumError),
    ContradictoryChecksum,
    UnverifiedInbound,
}

/// Проверяет рамку и считает суммы один раз. Не интерпретирует флаги и не
/// даёт разрешения на обработку; исключительно общий шаг для inspect/статистики.
pub(crate) fn checksums_for_capture(
    raw: &[u8],
    addr: &WinDivertAddress,
) -> Result<TcpChecksums, Error> {
    if !addr.network_packet() || addr.loopback() || addr.impostor() {
        return Err(Error::Metadata);
    }
    let Some(first) = raw.first() else {
        return Err(Error::InvalidLength);
    };
    let declared = match first >> 4 {
        4 if !addr.ipv6() && raw.len() >= 20 => u16::from_be_bytes([raw[2], raw[3]]) as usize,
        6 if addr.ipv6() && raw.len() >= 40 => 40 + u16::from_be_bytes([raw[4], raw[5]]) as usize,
        4 if raw.len() < 20 => return Err(Error::InvalidLength),
        6 if raw.len() < 40 => return Err(Error::InvalidLength),
        _ => return Err(Error::Metadata),
    };
    if declared != raw.len() {
        return Err(Error::InvalidLength);
    }
    tcp_checksums(raw).map_err(Error::Packet)
}

/// Не изменяет ни пакет, ни адрес. Неподдерживаемый или неоднозначный пакет
/// не должен использоваться как свидетельство для модификации других пакетов.
pub fn inspect(raw: &[u8], addr: &WinDivertAddress) -> Result<Check, Error> {
    let sums = checksums_for_capture(raw, addr)?;
    if (sums.ipv4_header_valid == Some(false) && addr.ip_checksum())
        || (!sums.tcp_valid && addr.tcp_checksum())
    {
        return Err(Error::ContradictoryChecksum);
    }
    if sums.ipv4_header_valid == Some(false) || !sums.tcp_valid {
        return if addr.outbound() {
            Ok(Check::UnverifiedOutbound)
        } else {
            Err(Error::UnverifiedInbound)
        };
    }
    Ok(Check::ValidBytes)
}

/// До появления надёжного подтверждения отсутствия LSO и принадлежности потоку
/// никакой результат inspect не разрешает активное преобразование. Адрес при
/// вызове send остаётся оригинальным в packet_loop, однако WinDivert 2.2 может
/// сам пересчитывать checksum при снятых флагах; wire-байты не гарантируются.
/// При флаге IPv4=1 и неверных байтах драйвер может не исправить этот заголовок.
/// Не подключать к живому активному пути до проверки внешнего pass-through.
#[cfg(any(test, all(windows, target_arch = "x86_64")))]
pub(crate) fn pass_through_while_lso_unknown(raw: &[u8]) -> Vec<Vec<u8>> {
    vec![raw.to_vec()]
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
    const OUT: u32 = 1 << 17;
    const V6BIT: u32 = 1 << 20;
    const IP: u32 = 1 << 21;
    const TCP: u32 = 1 << 22;
    fn addr(bits: u32) -> WinDivertAddress {
        WinDivertAddress::from_test_bits(bits)
    }
    #[test]
    fn valid_vectors_in_both_directions_and_metadata_flags() {
        for (s, v6) in [(V4, false), (V6, true)] {
            let p = bytes(s);
            let bits = if v6 { V6BIT } else { IP };
            assert_eq!(inspect(&p, &addr(bits | TCP | OUT)), Ok(Check::ValidBytes));
            assert_eq!(inspect(&p, &addr(bits | TCP)), Ok(Check::ValidBytes));
            // unset flags need not imply that already-valid bytes are invalid.
            assert_eq!(
                inspect(&p, &addr(if v6 { V6BIT } else { 0 })),
                Ok(Check::ValidBytes)
            );
        }
    }
    #[test]
    fn offload_unknown_is_outbound_only_and_no_bytes_change() {
        for (s, v6) in [(V4, false), (V6, true)] {
            let mut p = bytes(s);
            let tcp = if v6 { 40 } else { 20 };
            p[tcp + 16..tcp + 18].copy_from_slice(&[0x12, 0x34]);
            let original = p.clone();
            let version = if v6 { V6BIT } else { IP };
            assert_eq!(
                inspect(&p, &addr(version | OUT)),
                Ok(Check::UnverifiedOutbound)
            );
            assert_eq!(inspect(&p, &addr(version)), Err(Error::UnverifiedInbound));
            assert_eq!(
                inspect(&p, &addr(version | OUT | TCP)),
                Err(Error::ContradictoryChecksum)
            );
            assert_eq!(p, original);
        }
        let mut p = bytes(V4);
        p[10..12].fill(0);
        assert_eq!(inspect(&p, &addr(OUT | TCP)), Ok(Check::UnverifiedOutbound));
        assert_eq!(
            inspect(&p, &addr(OUT | TCP | IP)),
            Err(Error::ContradictoryChecksum)
        );
    }
    #[test]
    fn unknown_lso_always_returns_only_original_even_for_valid_checksums() {
        let valid = bytes(V4);
        assert_eq!(
            inspect(&valid, &addr(OUT | IP | TCP)),
            Ok(Check::ValidBytes)
        );
        let mut unverified = valid.clone();
        unverified[36..38].fill(0);
        assert_eq!(
            inspect(&unverified, &addr(OUT | IP)),
            Ok(Check::UnverifiedOutbound)
        );
        for packet in [valid, unverified, vec![0], vec![0xaa; 65535]] {
            assert_eq!(pass_through_while_lso_unknown(&packet), vec![packet]);
        }
    }
    #[test]
    fn ip_and_tcp_sums_are_independent() {
        let mut p = bytes(V4);
        p[10] ^= 1;
        let result = tcp_checksums(&p).unwrap();
        assert_eq!(result.ipv4_header_valid, Some(false));
        assert!(result.tcp_valid);
        p[36] ^= 1;
        let result = tcp_checksums(&p).unwrap();
        assert_eq!(result.ipv4_header_valid, Some(false));
        assert!(!result.tcp_valid);
        assert_eq!(
            crate::traffic::checksum::verify_tcp(&p),
            Err(ChecksumError::Ipv4Header)
        );
    }
    #[test]
    fn arbitrary_inputs_and_metadata_never_panic_or_modify_input() {
        let mut seed = 0x5482_f4a1_u32;
        for n in 0..600usize {
            let mut packet = vec![0u8; n % 100];
            for byte in &mut packet {
                seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                *byte = (seed >> 24) as u8;
            }
            let before = packet.clone();
            let _ = inspect(&packet, &addr(seed));
            assert_eq!(packet, before);
        }
    }
    #[test]
    fn malformed_metadata_fragments_and_trailing_data_are_not_evidence() {
        let p = bytes(V4);
        for bits in [1, 1 << 8, 1 << 18, 1 << 19, V6BIT] {
            assert_eq!(inspect(&p, &addr(bits)), Err(Error::Metadata));
        }
        for n in 0..p.len() {
            assert!(inspect(&p[..n], &addr(OUT)).is_err());
        }
        let mut extra = p.clone();
        extra.push(0);
        assert_eq!(inspect(&extra, &addr(OUT)), Err(Error::InvalidLength));
        let mut fragment = p.clone();
        fragment[6] = 0x20;
        assert!(matches!(
            inspect(&fragment, &addr(OUT)),
            Err(Error::Packet(_))
        ));
    }
}
