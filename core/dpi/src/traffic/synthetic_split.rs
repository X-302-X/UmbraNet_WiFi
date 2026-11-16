//! Офлайн-преобразование синтетического TCP-пакета в тестовые сегменты.
//! НЕ является стратегией обхода, не выбирает цели и не отправляет данные.
//! Полученные байты нельзя применять для работы с реальным трафиком.
use super::checksum::{verify_tcp, ChecksumError};
use super::packet::{parse_ip, PacketError, Protocol};

pub const MAX_SEGMENTS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitError {
    Packet(PacketError),
    Checksum(ChecksumError),
    Unsupported,
    EmptyPayload,
    InvalidCuts,
    TooManySegments,
}

/// Тестовый байтовый результат, не готовый для отправки в сеть.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureSegment(Vec<u8>);
impl FixtureSegment {
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

fn sum_words(bytes: &[u8]) -> u64 {
    let mut chunks = bytes.chunks_exact(2);
    let mut sum: u64 = chunks
        .by_ref()
        .map(|c| u16::from_be_bytes([c[0], c[1]]) as u64)
        .sum();
    if let [b] = chunks.remainder() {
        sum += (*b as u64) << 8;
    }
    sum
}
fn finish_sum(mut sum: u64) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Вызывается только для собственных, уже ограниченных IPv4/IPv6 сегментов.
fn write_checksums(raw: &mut [u8], ipv6: bool) {
    let ip_len = if ipv6 { 40 } else { 20 };
    let tcp_len = raw.len() - ip_len;
    raw[ip_len + 16..ip_len + 18].fill(0);
    let pseudo = if ipv6 {
        sum_words(&raw[8..40])
    } else {
        sum_words(&raw[12..20])
    };
    let checksum = finish_sum(pseudo + tcp_len as u64 + 6 + sum_words(&raw[ip_len..]));
    raw[ip_len + 16..ip_len + 18].copy_from_slice(&checksum.to_be_bytes());
    if !ipv6 {
        raw[10..12].fill(0);
        let checksum = finish_sum(sum_words(&raw[..20]));
        raw[10..12].copy_from_slice(&checksum.to_be_bytes());
    }
}

/// `cuts` — строго возрастающие ненулевые offsets внутри TCP payload.
/// Возвращает новые тестовые пакеты в исходном порядке; вход не изменяется.
/// Поддерживается только полный IPv4/IPv6 TCP без IP/TCP options и фрагментов,
/// без offload, с флагами ACK или ACK+PSH и без дополнительных байтов после IP.
/// Только последний сегмент сохраняет исходный PSH. Все прочие заголовочные поля,
/// в том числе IPv4 ID, копируются. Применимость к живому TCP не проверяется.
pub fn split_fixture(raw: &[u8], cuts: &[usize]) -> Result<Vec<FixtureSegment>, SplitError> {
    let packet = parse_ip(raw).map_err(SplitError::Packet)?;
    if packet.protocol != Protocol::Tcp {
        return Err(SplitError::Unsupported);
    }
    let tcp = packet.tcp.ok_or(SplitError::Unsupported)?;
    let ipv6 = raw[0] >> 4 == 6;
    let ip_len = if ipv6 { 40 } else { 20 };
    let total = if ipv6 {
        40 + u16::from_be_bytes([raw[4], raw[5]]) as usize
    } else {
        u16::from_be_bytes([raw[2], raw[3]]) as usize
    };
    if total != raw.len()
        || (!ipv6 && (raw[0] & 0x0f != 5 || raw[6] & 0x80 != 0))
        || !tcp.options.is_empty()
        || tcp.reserved_and_ns != 0
        || tcp.urgent_pointer != 0
        || !matches!(tcp.flags, 0x10 | 0x18)
        || packet.source_port == 0
        || packet.destination_port == 0
    {
        return Err(SplitError::Unsupported);
    }
    verify_tcp(raw).map_err(SplitError::Checksum)?;
    if packet.payload.is_empty() {
        return Err(SplitError::EmptyPayload);
    }
    if cuts.len() >= MAX_SEGMENTS {
        return Err(SplitError::TooManySegments);
    }
    if cuts.is_empty()
        || cuts.iter().any(|c| *c == 0 || *c >= packet.payload.len())
        || cuts.windows(2).any(|w| w[0] >= w[1])
    {
        return Err(SplitError::InvalidCuts);
    }
    let header_len = ip_len + 20;
    let mut result = Vec::with_capacity(cuts.len() + 1);
    let mut start = 0;
    for end in cuts
        .iter()
        .copied()
        .chain(std::iter::once(packet.payload.len()))
    {
        let mut segment = Vec::with_capacity(header_len + end - start);
        segment.extend_from_slice(&raw[..header_len]);
        segment.extend_from_slice(&packet.payload[start..end]);
        if ipv6 {
            let length = (segment.len() - 40) as u16;
            segment[4..6].copy_from_slice(&length.to_be_bytes());
        } else {
            let length = segment.len() as u16;
            segment[2..4].copy_from_slice(&length.to_be_bytes());
        }
        segment[ip_len + 4..ip_len + 8]
            .copy_from_slice(&tcp.sequence.wrapping_add(start as u32).to_be_bytes());
        if end != packet.payload.len() {
            segment[ip_len + 13] &= !0x08;
        }
        write_checksums(&mut segment, ipv6);
        result.push(FixtureSegment(segment));
        start = end;
    }
    Ok(result)
}
