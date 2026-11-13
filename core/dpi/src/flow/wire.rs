//! Разбор адреса WinDivert FLOW 2.2; данные не являются содержимым пакета.
use crate::flow::tracker::{FlowKey, Transport};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RawFlow {
    pub endpoint: u64,
    pub parent_endpoint: u64,
    pub pid: u32,
    pub local: [u32; 4],
    pub remote: [u32; 4],
    pub local_port: u16,
    pub remote_port: u16,
    pub protocol: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RawAddress {
    pub timestamp: i64,
    pub bits: u32,
    pub reserved: u32,
    pub flow: RawFlow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowEventKind {
    Established,
    Deleted,
}

/// Событие — наблюдение WinDivert, а не гарантированная идентификация пакета.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowEvent {
    pub kind: FlowEventKind,
    pub timestamp_qpc: u64,
    pub endpoint: u64,
    pub pid: u32,
    pub key: FlowKey,
}

/// Четыре UINT32 задают 128-битное число младшим словом вперёд.
fn host_words_to_ip(words: [u32; 4]) -> IpAddr {
    let mut bytes = [0u8; 16];
    for (chunk, value) in bytes.chunks_exact_mut(4).zip(words.into_iter().rev()) {
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    let ipv6 = Ipv6Addr::from(bytes);
    ipv6.to_ipv4_mapped()
        .map(IpAddr::V4)
        .unwrap_or(IpAddr::V6(ipv6))
}

pub(crate) fn decode(raw: RawAddress) -> Option<FlowEvent> {
    let layer = raw.bits & 0xff;
    let event = (raw.bits >> 8) & 0xff;
    let outbound = raw.bits & (1 << 17) != 0;
    if layer != 2 || !outbound || raw.timestamp < 0 || raw.flow.endpoint == 0 || raw.flow.pid == 0 {
        return None;
    }
    let kind = match event {
        1 => FlowEventKind::Established,
        2 => FlowEventKind::Deleted,
        _ => return None,
    };
    let protocol = match raw.flow.protocol {
        6 => Transport::Tcp,
        17 => Transport::Udp,
        _ => return None,
    };
    let local = SocketAddr::new(host_words_to_ip(raw.flow.local), raw.flow.local_port);
    let remote = SocketAddr::new(host_words_to_ip(raw.flow.remote), raw.flow.remote_port);
    Some(FlowEvent {
        kind,
        timestamp_qpc: raw.timestamp as u64,
        endpoint: raw.flow.endpoint,
        pid: raw.flow.pid,
        key: FlowKey::new(local, remote, protocol)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};
    fn sample() -> RawAddress {
        RawAddress {
            timestamp: 123,
            bits: 2 | (1 << 8) | (1 << 17),
            reserved: 0,
            flow: RawFlow {
                endpoint: 42,
                parent_endpoint: 0,
                pid: 100,
                local: [0xc0000202, 0xffff, 0, 0],
                remote: [0xc6336404, 0xffff, 0, 0],
                local_port: 50001,
                remote_port: 443,
                protocol: 6,
            },
        }
    }
    #[test]
    fn matches_official_win_divert_x64_layout() {
        assert_eq!(size_of::<RawFlow>(), 64);
        assert_eq!(size_of::<RawAddress>(), 80);
        assert_eq!(offset_of!(RawAddress, flow), 16);
        assert_eq!(offset_of!(RawFlow, pid), 16);
        assert_eq!(offset_of!(RawFlow, local), 20);
        assert_eq!(offset_of!(RawFlow, remote), 36);
        assert_eq!(offset_of!(RawFlow, local_port), 52);
        assert_eq!(offset_of!(RawFlow, protocol), 56);
    }
    #[test]
    fn decodes_flow_and_host_order_ipv4() {
        let actual = decode(sample()).unwrap();
        assert_eq!(actual.kind, FlowEventKind::Established);
        assert_eq!(
            actual.key,
            FlowKey::new(
                "192.0.2.2:50001".parse().unwrap(),
                "198.51.100.4:443".parse().unwrap(),
                Transport::Tcp
            )
            .unwrap()
        );
        assert_eq!(actual.pid, 100);
        assert_eq!(actual.timestamp_qpc, 123);
    }
    #[test]
    fn decodes_ipv6_word_order() {
        assert_eq!(
            host_words_to_ip([1, 0, 0, 0x20010db8]),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
    }
    #[test]
    fn rejects_untrusted_or_unsupported_events() {
        let mut r = sample();
        r.bits = 2 | (2 << 8) | (1 << 17);
        assert_eq!(decode(r).unwrap().kind, FlowEventKind::Deleted);
        r.bits = 2 | (1 << 8);
        assert!(decode(r).is_none());
        r = sample();
        r.timestamp = -1;
        assert!(decode(r).is_none());
        r = sample();
        r.flow.pid = 0;
        assert!(decode(r).is_none());
        r = sample();
        r.flow.protocol = 1;
        assert!(decode(r).is_none());
        r = sample();
        r.flow.remote_port = 0;
        assert!(decode(r).is_none());
    }
}
