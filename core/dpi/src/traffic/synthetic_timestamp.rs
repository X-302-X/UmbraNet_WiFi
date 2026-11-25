//! Изменение TSval только в тестовом TCP-пакете; сеть не открывается.
//! Это НЕ реализация fooling=ts из e1-spike и не доказательство PAWS/доставки.
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
    NoTimestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureTimestampPacket(Vec<u8>);
impl FixtureTimestampPacket {
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Поддерживает только полный проверенный TCP ACK или ACK+PSH без IP options,
/// без фрагментов и без неизвестных TCP options. Меняет уже существующий TSval;
/// TSecr, payload, флаги и остальные поля не меняются. Число new_tsval — только
/// вход теста: оно не проверяет PAWS и не предполагает правило старого движка.
pub fn replace_tsval_fixture(raw: &[u8], new_tsval: u32) -> Result<FixtureTimestampPacket, Error> {
    let packet = parse_ip(raw).map_err(Error::Packet)?;
    if packet.protocol != Protocol::Tcp {
        return Err(Error::Unsupported);
    }
    let tcp = packet.tcp.ok_or(Error::Unsupported)?;
    let v6 = raw[0] >> 4 == 6;
    let ip_len = if v6 { 40 } else { 20 };
    let declared = if v6 {
        40 + u16::from_be_bytes([raw[4], raw[5]]) as usize
    } else {
        u16::from_be_bytes([raw[2], raw[3]]) as usize
    };
    if declared != raw.len()
        || (!v6 && (raw[0] & 0x0f != 5 || raw[6] & 0x80 != 0))
        || tcp.reserved_and_ns != 0
        || tcp.urgent_pointer != 0
        || !matches!(tcp.flags, 0x10 | 0x18)
        || packet.source_port == 0
        || packet.destination_port == 0
        || packet.payload.is_empty()
    {
        return Err(Error::Unsupported);
    }
    verify_tcp(raw).map_err(Error::Checksum)?;
    let options = tcp_options::parse(tcp.options, false, true).map_err(Error::Options)?;
    if options.timestamp.is_none() {
        return Err(Error::NoTimestamp);
    }
    let mut offset = 0;
    while offset < tcp.options.len() {
        match tcp.options[offset] {
            0 => break,
            1 => offset += 1,
            8 => {
                // parse() уже подтвердил длину 10 и отсутствие дублирующих TS.
                let mut result = raw.to_vec();
                let at = ip_len + 20 + offset + 2;
                result[at..at + 4].copy_from_slice(&new_tsval.to_be_bytes());
                write_checksums(&mut result, v6, ip_len);
                return Ok(FixtureTimestampPacket(result));
            }
            _ => offset += tcp.options[offset + 1] as usize,
        }
    }
    Err(Error::NoTimestamp)
}
