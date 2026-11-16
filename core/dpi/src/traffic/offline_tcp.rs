//! Только офлайн-адаптер синтетических пакетов к модели жизненного цикла.
//! Проверяет checksum только для полных офлайн-пакетов без offload.
//! Не устанавливает подлинность и не предназначен для WinDivert.
use std::net::SocketAddr;

use super::application::Evidence;
use super::checksum::{verify_tcp, ChecksumError};
use super::connections::{Connections, Error as ConnectionError, Token};
use super::packet::{parse_ip, PacketError, Protocol, TcpHeader};
use super::tcp_options::{self, OptionError};
use crate::flow::tracker::{FlowKey, Transport};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Outbound,
    Inbound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handle {
    key: FlowKey,
    token: Token,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Packet(PacketError),
    Checksum(ChecksumError),
    TcpOptions(OptionError),
    UnsupportedPacket,
    InvalidAddress,
    FlowMismatch,
    UnexpectedTcpShape,
    Connection(ConnectionError),
}

struct Segment<'a> {
    key: FlowKey,
    tcp: TcpHeader<'a>,
    payload: &'a [u8],
}

fn decode(bytes: &[u8], direction: Direction) -> Result<Segment<'_>, Error> {
    let packet = parse_ip(bytes).map_err(Error::Packet)?;
    // IP options и IPv6 extension headers не интерпретируются: никакого угадывания.
    if bytes[0] >> 4 == 4 && (bytes[0] & 0x0f != 5 || bytes[6] & 0x80 != 0) {
        return Err(Error::UnsupportedPacket);
    }
    if packet.protocol != Protocol::Tcp {
        return Err(Error::UnsupportedPacket);
    }
    let tcp = packet.tcp.ok_or(Error::UnsupportedPacket)?;
    if tcp.reserved_and_ns != 0 || tcp.urgent_pointer != 0 {
        return Err(Error::UnsupportedPacket);
    }
    verify_tcp(bytes).map_err(Error::Checksum)?;
    tcp_options::parse(tcp.options, tcp.flags & 0x02 != 0, tcp.flags & 0x10 != 0)
        .map_err(Error::TcpOptions)?;
    let source = SocketAddr::new(packet.source, packet.source_port);
    let destination = SocketAddr::new(packet.destination, packet.destination_port);
    let (local, remote) = match direction {
        Direction::Outbound => (source, destination),
        Direction::Inbound => (destination, source),
    };
    let key = FlowKey::new(local, remote, Transport::Tcp).ok_or(Error::InvalidAddress)?;
    Ok(Segment {
        key,
        tcp,
        payload: packet.payload,
    })
}

fn prepare<'a>(
    table: &mut Connections,
    bytes: &'a [u8],
    direction: Direction,
    now: u64,
) -> Result<Segment<'a>, Error> {
    table.sweep(now).map_err(Error::Connection)?;
    match decode(bytes, direction) {
        Ok(segment) => Ok(segment),
        Err(error) => {
            // Из повреждённого пакета нельзя надёжно определить, какой поток потерял данные.
            table.invalidate();
            Err(error)
        }
    }
}

fn checked<'a>(
    table: &mut Connections,
    handle: &Handle,
    bytes: &'a [u8],
    direction: Direction,
    now: u64,
) -> Result<Segment<'a>, Error> {
    let segment = prepare(table, bytes, direction, now)?;
    if segment.key != handle.key {
        return Err(Error::FlowMismatch);
    }
    Ok(segment)
}

fn reject(table: &mut Connections, handle: &Handle, now: u64) -> Result<(), Error> {
    table
        .close(&handle.key, handle.token, now)
        .map_err(Error::Connection)?;
    Err(Error::UnexpectedTcpShape)
}

/// Только исходящий SYN без данных, ACK и дополнительных флагов.
pub fn open(table: &mut Connections, bytes: &[u8], now: u64) -> Result<Handle, Error> {
    let s = prepare(table, bytes, Direction::Outbound, now)?;
    if s.tcp.flags != 0x02 || s.tcp.acknowledgment != 0 || !s.payload.is_empty() {
        // Адресованный так SYN может относиться и к уже существующему потоку.
        table.invalidate();
        return Err(Error::UnexpectedTcpShape);
    }
    let token = table
        .open(s.key.clone(), s.tcp.sequence, now)
        .map_err(Error::Connection)?;
    Ok(Handle { key: s.key, token })
}

/// Входящий SYN+ACK без данных; порядок и номера проверяются в модели.
pub fn syn_ack(
    table: &mut Connections,
    handle: &Handle,
    bytes: &[u8],
    now: u64,
) -> Result<(), Error> {
    let s = checked(table, handle, bytes, Direction::Inbound, now)?;
    if s.tcp.flags != 0x12 || !s.payload.is_empty() {
        return reject(table, handle, now);
    }
    table
        .syn_ack(
            &handle.key,
            handle.token,
            s.tcp.sequence,
            s.tcp.acknowledgment,
            now,
        )
        .map_err(Error::Connection)
}

/// Исходящий ACK без данных для завершения модели handshake.
pub fn client_ack(
    table: &mut Connections,
    handle: &Handle,
    bytes: &[u8],
    now: u64,
) -> Result<(), Error> {
    let s = checked(table, handle, bytes, Direction::Outbound, now)?;
    if s.tcp.flags != 0x10 || !s.payload.is_empty() {
        return reject(table, handle, now);
    }
    table
        .client_ack(
            &handle.key,
            handle.token,
            s.tcp.sequence,
            s.tcp.acknowledgment,
            now,
        )
        .map_err(Error::Connection)
}

/// Только исходящие непустые данные с ACK и необязательным PSH.
pub fn payload(
    table: &mut Connections,
    handle: &Handle,
    bytes: &[u8],
    now: u64,
) -> Result<(), Error> {
    let s = checked(table, handle, bytes, Direction::Outbound, now)?;
    if !matches!(s.tcp.flags, 0x10 | 0x18) || s.payload.is_empty() {
        return reject(table, handle, now);
    }
    table
        .payload(&handle.key, handle.token, s.tcp.sequence, s.payload, now)
        .map_err(Error::Connection)
}

/// Любой одиночный FIN или RST завершает только офлайн-наблюдение, не TCP в ОС.
/// Проверка пригодности seq/ack для настоящего сетевого стека здесь отсутствует.
pub fn close(
    table: &mut Connections,
    handle: &Handle,
    bytes: &[u8],
    direction: Direction,
    now: u64,
) -> Result<(), Error> {
    let s = checked(table, handle, bytes, direction, now)?;
    if !matches!(s.tcp.flags, 0x01 | 0x11 | 0x04 | 0x14) || !s.payload.is_empty() {
        return reject(table, handle, now);
    }
    table
        .close(&handle.key, handle.token, now)
        .map_err(Error::Connection)
}

/// Предварительный результат; не доказывает доставку, PID или безопасность изменения пакета.
pub fn evidence(table: &mut Connections, handle: &Handle, now: u64) -> Result<Evidence, Error> {
    table
        .evidence(&handle.key, handle.token, now)
        .map_err(Error::Connection)
}
