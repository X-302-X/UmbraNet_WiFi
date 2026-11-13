//! Ограниченный разбор IPv4/IPv6 и TCP/UDP. Фрагменты не объединяются.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: Protocol,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketError {
    Truncated,
    Invalid,
    Fragmented,
    Unsupported,
}

fn be16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

pub fn parse_ip(bytes: &[u8]) -> Result<Packet<'_>, PacketError> {
    let first = *bytes.first().ok_or(PacketError::Truncated)?;
    let (src, dst, proto, payload) = match first >> 4 {
        4 => {
            if bytes.len() < 20 {
                return Err(PacketError::Truncated);
            }
            let header_len = ((first & 0x0f) as usize) * 4;
            if header_len < 20 {
                return Err(PacketError::Invalid);
            }
            let total = be16(&bytes[2..4]) as usize;
            if total < header_len {
                return Err(PacketError::Invalid);
            }
            if bytes.len() < total || bytes.len() < header_len {
                return Err(PacketError::Truncated);
            }
            // И первый фрагмент с MF, и последующие оставляем без классификации.
            if be16(&bytes[6..8]) & 0x3fff != 0 {
                return Err(PacketError::Fragmented);
            }
            let src = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
            let dst = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
            (
                IpAddr::V4(src),
                IpAddr::V4(dst),
                bytes[9],
                &bytes[header_len..total],
            )
        }
        6 => {
            if bytes.len() < 40 {
                return Err(PacketError::Truncated);
            }
            let length = be16(&bytes[4..6]) as usize;
            if length == 0 {
                return Err(PacketError::Unsupported);
            } // Jumbogram или нет данных.
            let total = 40 + length;
            if bytes.len() < total {
                return Err(PacketError::Truncated);
            }
            let mut src = [0; 16];
            src.copy_from_slice(&bytes[8..24]);
            let mut dst = [0; 16];
            dst.copy_from_slice(&bytes[24..40]);
            // Extension headers, включая фрагменты, пока не интерпретируются.
            (
                IpAddr::V6(Ipv6Addr::from(src)),
                IpAddr::V6(Ipv6Addr::from(dst)),
                bytes[6],
                &bytes[40..total],
            )
        }
        _ => return Err(PacketError::Unsupported),
    };
    match proto {
        6 => {
            if payload.len() < 20 {
                return Err(PacketError::Truncated);
            }
            let header_len = ((payload[12] >> 4) as usize) * 4;
            if header_len < 20 {
                return Err(PacketError::Invalid);
            }
            if payload.len() < header_len {
                return Err(PacketError::Truncated);
            }
            Ok(Packet {
                source: src,
                destination: dst,
                source_port: be16(&payload[0..2]),
                destination_port: be16(&payload[2..4]),
                protocol: Protocol::Tcp,
                payload: &payload[header_len..],
            })
        }
        17 => {
            if payload.len() < 8 {
                return Err(PacketError::Truncated);
            }
            let length = be16(&payload[4..6]) as usize;
            if length < 8 {
                return Err(PacketError::Invalid);
            }
            if payload.len() < length {
                return Err(PacketError::Truncated);
            }
            Ok(Packet {
                source: src,
                destination: dst,
                source_port: be16(&payload[0..2]),
                destination_port: be16(&payload[2..4]),
                protocol: Protocol::Udp,
                payload: &payload[8..length],
            })
        }
        _ => Err(PacketError::Unsupported),
    }
}
