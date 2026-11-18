//! Активный UDP / QUIC / Discord Voice desync:
//! - определение QUIC Initial пакетов;
//! - определение Discord Voice / STUN пакетов;
//! - генерация fake UDP-пакетов (TTL, BadSum) с пересчётом IPv4/UDP checksum.

use super::desync::{DesyncError, Fooling, MAX_DESYNC_PACKETS};
use super::packet::{parse_ip, Protocol};

/// Проверяет, является ли UDP payload пакетом QUIC Initial.
pub fn is_quic_initial(payload: &[u8]) -> bool {
    if payload.len() < 12 {
        return false;
    }
    // Long header: bit 7 = 1 (0x80), Fixed bit = 1 (0x40)
    if payload[0] & 0xc0 != 0xc0 {
        return false;
    }
    let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    if version == 0 {
        return false; // Version Negotiation
    }
    let pkt_type = (payload[0] & 0x30) >> 4;
    // QUIC v1: Initial = 0; QUIC v2 (0x6b3343cf): Initial = 1
    if version == 0x6b33_43cf {
        pkt_type == 1
    } else {
        pkt_type == 0
    }
}

/// Проверяет, похож ли UDP payload на Discord IP Discovery или STUN/RTP.
pub fn is_discord_voice_or_stun(payload: &[u8]) -> bool {
    // Discord IP Discovery: 74 байта, type 0x0001 (request), length 70 (0x0046)
    if payload.len() == 74
        && payload[0] == 0x00
        && payload[1] == 0x01
        && payload[2] == 0x00
        && payload[3] == 0x46
    {
        return true;
    }
    // STUN: magic cookie 0x2112A442 на смещении 4..8
    if payload.len() >= 20 && payload[4..8] == [0x21, 0x12, 0xa4, 0x42] {
        return true;
    }
    false
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
    let res = !(sum as u16);
    if res == 0 {
        0xffff
    } else {
        res
    }
}

fn write_udp_checksums(raw: &mut [u8], ipv6: bool, ip_len: usize) {
    let udp_len = raw.len() - ip_len;
    raw[ip_len + 6..ip_len + 8].fill(0);
    let pseudo = if ipv6 {
        sum_words(&raw[8..40])
    } else {
        sum_words(&raw[12..20])
    };
    let udp_sum = finish_sum(pseudo + udp_len as u64 + 17 + sum_words(&raw[ip_len..]));
    raw[ip_len + 6..ip_len + 8].copy_from_slice(&udp_sum.to_be_bytes());
    if !ipv6 {
        raw[10..12].fill(0);
        let ip_sum = finish_sum(sum_words(&raw[..ip_len]));
        raw[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    }
}

/// Создаёт fake UDP-пакет на основе оригинального IPv4/IPv6 UDP-пакета.
pub fn build_fake_udp(
    raw: &[u8],
    fooling: &[Fooling],
    fake_payload: &[u8],
) -> Result<Vec<u8>, DesyncError> {
    let packet = parse_ip(raw).map_err(DesyncError::Packet)?;
    if packet.protocol != Protocol::Udp {
        return Err(DesyncError::Unsupported);
    }
    let ipv6 = raw[0] >> 4 == 6;
    let ip_len = if ipv6 {
        40
    } else {
        ((raw[0] & 0x0f) as usize) * 4
    };
    let header_len = ip_len + 8;
    if raw.len() < header_len {
        return Err(DesyncError::Unsupported);
    }

    let payload = if fake_payload.is_empty() {
        packet.payload
    } else {
        fake_payload
    };

    let mut fake = Vec::with_capacity(header_len + payload.len());
    fake.extend_from_slice(&raw[..header_len]);
    fake.extend_from_slice(payload);

    let udp_len = (8 + payload.len()) as u16;
    fake[ip_len + 4..ip_len + 6].copy_from_slice(&udp_len.to_be_bytes());
    if ipv6 {
        fake[4..6].copy_from_slice(&udp_len.to_be_bytes());
    } else {
        let total_len = fake.len() as u16;
        fake[2..4].copy_from_slice(&total_len.to_be_bytes());
    }

    let mut bad_sum = false;
    for f in fooling {
        match *f {
            Fooling::Ttl(ttl) => {
                if ipv6 {
                    fake[7] = ttl.max(1);
                } else {
                    fake[8] = ttl.max(1);
                }
            }
            Fooling::BadSum => bad_sum = true,
            Fooling::BadSeq(_) | Fooling::Md5Sig => {}
        }
    }

    write_udp_checksums(&mut fake, ipv6, ip_len);
    if bad_sum {
        fake[ip_len + 6] ^= 0xff;
        fake[ip_len + 7] ^= 0xff;
    }
    Ok(fake)
}

/// Генерирует `repeats` фейковых UDP-пакетов и добавляет оригинальный пакет в конец.
pub fn apply_udp_desync(
    raw: &[u8],
    repeats: u8,
    fooling: &[Fooling],
    fake_payload: &[u8],
) -> Result<Vec<Vec<u8>>, DesyncError> {
    let count = repeats.max(1) as usize;
    if count + 1 > MAX_DESYNC_PACKETS {
        return Err(DesyncError::TooManyPackets);
    }
    let mut out = Vec::with_capacity(count + 1);
    for _ in 0..count {
        out.push(build_fake_udp(raw, fooling, fake_payload)?);
    }
    out.push(raw.to_vec());
    Ok(out)
}
