//! Офлайн-модель одного fake с TS=0 либо ошибочной суммой, по наблюдению
//! selftest старого e1-spike 0.9.6. Это НЕ полный перенос Uz1, не доказательство
//! равенства байтов и НЕ интерфейс для WinDivert или отправки в сеть.
use super::checksum::{verify_tcp, ChecksumError};
use super::desync::write_checksums;
use super::packet::{parse_ip, PacketError, Protocol};
use super::tcp_options::{self, OptionError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Packet(PacketError),
    Checksum(ChecksumError),
    Options(OptionError),
    Unsupported,
    InvalidPayload,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    TimestampZero,
    BadChecksum,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeFixture {
    bytes: Vec<u8>,
    variant: Variant,
}
impl FakeFixture {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn variant(&self) -> Variant {
        self.variant
    }
}

/// Базовый пакет должен быть полноценным synthetic TCP с валидными checksum.
/// Готовится одна копия с указанным fake payload: TSval=0 при наличии TS,
/// иначе намеренно портится один бит TCP checksum. Нет подмены, если вход или
/// options неоднозначны. Не проверяются цель, handshake, PAWS и доставка.
pub fn fake_fixture(
    raw: &[u8],
    fake_payload: &[u8],
    zero_ipv4_id: bool,
) -> Result<FakeFixture, Error> {
    let packet = parse_ip(raw).map_err(Error::Packet)?;
    if packet.protocol != Protocol::Tcp {
        return Err(Error::Unsupported);
    }
    let tcp = packet.tcp.ok_or(Error::Unsupported)?;
    let ipv6 = raw[0] >> 4 == 6;
    let ip_len = if ipv6 { 40 } else { 20 };
    let total = if ipv6 {
        40 + u16::from_be_bytes([raw[4], raw[5]]) as usize
    } else {
        u16::from_be_bytes([raw[2], raw[3]]) as usize
    };
    if total != raw.len()
        || (!ipv6 && (raw[0] & 0x0f != 5 || raw[6] & 0x80 != 0))
        || tcp.reserved_and_ns != 0
        || tcp.urgent_pointer != 0
        || !matches!(tcp.flags, 0x10 | 0x18)
        || packet.payload.is_empty()
        || packet.source_port == 0
        || packet.destination_port == 0
    {
        return Err(Error::Unsupported);
    }
    verify_tcp(raw).map_err(Error::Checksum)?;
    let options = tcp_options::parse(tcp.options, false, true).map_err(Error::Options)?;
    let header_len = ip_len + 20 + tcp.options.len();
    let len = header_len
        .checked_add(fake_payload.len())
        .ok_or(Error::InvalidPayload)?;
    if fake_payload.is_empty() || (if ipv6 { len - 40 } else { len }) > u16::MAX as usize {
        return Err(Error::InvalidPayload);
    }
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&raw[..header_len]);
    out.extend_from_slice(fake_payload);
    if ipv6 {
        out[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
    } else {
        out[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        if zero_ipv4_id {
            out[4..6].fill(0);
        }
    }
    let variant = if options.timestamp.is_some() {
        let mut offset = 0;
        let mut found = false;
        while offset < tcp.options.len() {
            match tcp.options[offset] {
                0 => break,
                1 => offset += 1,
                8 => {
                    let at = ip_len + 20 + offset + 2;
                    out[at..at + 4].fill(0);
                    found = true;
                    break;
                }
                _ => offset += tcp.options[offset + 1] as usize,
            }
        }
        if !found {
            return Err(Error::Unsupported);
        }
        Variant::TimestampZero
    } else {
        Variant::BadChecksum
    };
    write_checksums(&mut out, ipv6, ip_len);
    if variant == Variant::BadChecksum {
        // Flip a single bit, avoiding one's-complement zero/negative-zero equivalence.
        out[ip_len + 16] ^= 1;
    }
    Ok(FakeFixture {
        bytes: out,
        variant,
    })
}
