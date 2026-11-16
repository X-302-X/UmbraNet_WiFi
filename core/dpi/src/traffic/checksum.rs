//! Офлайн-проверка IPv4 header и TCP checksum на полных синтетических IP-пакетах.
//! Не пригодна для выводов о живом захвате с checksum/segmentation offload.
use super::packet::{parse_ip, PacketError, Protocol};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumError {
    Packet(PacketError),
    Unsupported,
    Ipv4Header,
    Tcp,
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

/// Проверяет checksum IPv4 header (если IPv4) и TCP с соответствующим pseudo-header.
/// Не поддерживает IPv4 options, IPv6 extension headers, фрагменты и jumbograms.
/// Предполагается полный пакет без offload; лишние байты после IP length игнорируются.
pub fn verify_tcp(bytes: &[u8]) -> Result<(), ChecksumError> {
    let packet = parse_ip(bytes).map_err(ChecksumError::Packet)?;
    if packet.protocol != Protocol::Tcp {
        return Err(ChecksumError::Unsupported);
    }
    let sum = match bytes[0] >> 4 {
        4 => {
            if bytes[0] & 0x0f != 5 || bytes[6] & 0x80 != 0 {
                return Err(ChecksumError::Unsupported);
            }
            let total = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
            if !valid_sum(sum_words(&bytes[..20])) {
                return Err(ChecksumError::Ipv4Header);
            }
            let tcp = &bytes[20..total];
            sum_words(&bytes[12..20]) + 6 + tcp.len() as u64 + sum_words(tcp)
        }
        6 => {
            let length = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
            let tcp = &bytes[40..40 + length];
            // Length occupies 32 bits, followed by three zero octets and protocol 6.
            sum_words(&bytes[8..40]) + (length as u64) + 6 + sum_words(tcp)
        }
        _ => return Err(ChecksumError::Unsupported),
    };
    if !valid_sum(sum) {
        return Err(ChecksumError::Tcp);
    }
    Ok(())
}
