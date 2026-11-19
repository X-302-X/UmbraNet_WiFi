//! Проверка IPv4 header и TCP checksum в полных пакетах.
//! Результат сам по себе не подтверждает цель или доставку и не выявляет LSO.
use super::packet::{parse_ip, PacketError, Protocol};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumError {
    Packet(PacketError),
    Unsupported,
    Ipv4Header,
    Tcp,
}

/// Независимая проверка имеющихся в буфере байтов, без учёта WinDivert metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpChecksums {
    /// None для IPv6, у которого нет контрольной суммы заголовка.
    pub ipv4_header_valid: Option<bool>,
    pub tcp_valid: bool,
}

fn sum_words(bytes: &[u8]) -> u64 {
    let mut words = bytes.chunks_exact(2);
    let mut sum: u64 = words
        .by_ref()
        .map(|w| u16::from_be_bytes([w[0], w[1]]) as u64)
        .sum();
    if let [last] = words.remainder() {
        sum += (*last as u64) << 8;
    }
    sum
}
fn valid_sum(mut sum: u64) -> bool {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum == 0xffff
}

/// Раздельно считает TCP и IPv4 header. Не поддерживает IP options, IPv6
/// extensions, фрагменты и jumbograms; parse_ip проверяет границы до срезов.
/// Лишние байты после IP length игнорируются (вызывающий может требовать точную длину).
pub fn tcp_checksums(bytes: &[u8]) -> Result<TcpChecksums, ChecksumError> {
    let packet = parse_ip(bytes).map_err(ChecksumError::Packet)?;
    if packet.protocol != Protocol::Tcp {
        return Err(ChecksumError::Unsupported);
    }
    let (ip, sum) = match bytes[0] >> 4 {
        4 => {
            if bytes[0] & 0x0f != 5 || bytes[6] & 0x80 != 0 {
                return Err(ChecksumError::Unsupported);
            }
            let total = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
            let tcp = &bytes[20..total];
            (
                Some(valid_sum(sum_words(&bytes[..20]))),
                sum_words(&bytes[12..20]) + 6 + tcp.len() as u64 + sum_words(tcp),
            )
        }
        6 => {
            let length = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
            let tcp = &bytes[40..40 + length];
            (
                None,
                sum_words(&bytes[8..40]) + length as u64 + 6 + sum_words(tcp),
            )
        }
        _ => return Err(ChecksumError::Unsupported),
    };
    Ok(TcpChecksums {
        ipv4_header_valid: ip,
        tcp_valid: valid_sum(sum),
    })
}

/// Офлайн-проверка полных пакетов без offload. Для WinDivert также нужно
/// учитывать соответствующие флаги WINDIVERT_ADDRESS; их здесь нет.
pub fn verify_tcp(bytes: &[u8]) -> Result<(), ChecksumError> {
    let sums = tcp_checksums(bytes)?;
    if sums.ipv4_header_valid == Some(false) {
        return Err(ChecksumError::Ipv4Header);
    }
    if !sums.tcp_valid {
        return Err(ChecksumError::Tcp);
    }
    Ok(())
}
