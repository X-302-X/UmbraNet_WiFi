//! Активный цикл обработки трафика (Engine Loop):
//! связывает DivertChannel, HostList/IpSet, кэш server_ttl для AutoTtl,
//! TCP/TLS desync и UDP/QUIC/Discord desync.

use crate::strategy::Strategy;
use crate::traffic::desync::{apply_desync, find_host_range, Fooling};
use crate::traffic::filter::{HostList, IpSet};
use crate::traffic::packet::{parse_ip, Protocol};
use crate::traffic::udp_desync::{apply_udp_desync, is_discord_voice_or_stun, is_quic_initial};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(windows)]
use crate::capture::windivert::DivertChannel;
#[cfg(windows)]
use std::io;
#[cfg(windows)]
use std::path::Path;
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};

pub struct Engine {
    pub strategy: Strategy,
    pub hostlist: HostList,
    pub ipset: IpSet,
    pub udp_repeats: u8,
    server_ttl: HashMap<IpAddr, u8>,
}

impl Engine {
    pub fn new(strategy: Strategy, hostlist: HostList, ipset: IpSet) -> Self {
        Self {
            strategy,
            hostlist,
            ipset,
            udp_repeats: 6,
            server_ttl: HashMap::new(),
        }
    }

    fn extract_ips(raw: &[u8]) -> Option<(IpAddr, IpAddr, u8)> {
        if raw.len() < 20 {
            return None;
        }
        match raw[0] >> 4 {
            4 => {
                let src = IpAddr::V4(Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]));
                let dst = IpAddr::V4(Ipv4Addr::new(raw[16], raw[17], raw[18], raw[19]));
                Some((src, dst, raw[8]))
            }
            6 if raw.len() >= 40 => {
                let mut s = [0u8; 16];
                let mut d = [0u8; 16];
                s.copy_from_slice(&raw[8..24]);
                d.copy_from_slice(&raw[24..40]);
                Some((IpAddr::V6(Ipv6Addr::from(s)), IpAddr::V6(Ipv6Addr::from(d)), raw[7]))
            }
            _ => None,
        }
    }

    /// Обрабатывает один перехваченный IP-пакет.
    /// Возвращает список пакетов для отправки обратно в сеть.
    pub fn process_packet(&mut self, raw: &[u8], outbound: bool) -> Vec<Vec<u8>> {
        let Some((src_ip, dst_ip, ttl)) = Self::extract_ips(raw) else {
            return vec![raw.to_vec()];
        };

        // На входящих пакетах запоминаем TTL сервера для AutoTtl
        if !outbound {
            self.server_ttl.insert(src_ip, ttl);
            return vec![raw.to_vec()];
        }

        if self.strategy.is_pass_through() {
            return vec![raw.to_vec()];
        }

        let Ok(parsed) = parse_ip(raw) else {
            return vec![raw.to_vec()];
        };

        if parsed.payload.is_empty() {
            return vec![raw.to_vec()];
        }

        match parsed.protocol {
            Protocol::Tcp => {
                let host_matched = if self.hostlist.is_empty() {
                    true
                } else if let Some((s, e)) = find_host_range(parsed.payload) {
                    let host = String::from_utf8_lossy(&parsed.payload[s..e]);
                    self.hostlist.matches(&host)
                } else {
                    false
                };

                let ip_matched = self.ipset.is_empty() || self.ipset.contains(dst_ip);
                if !host_matched && !ip_matched {
                    return vec![raw.to_vec()];
                }

                let sttl = self.server_ttl.get(&dst_ip).copied();
                let plan = self.strategy.to_desync_plan(sttl);
                apply_desync(raw, &plan).unwrap_or_else(|_| vec![raw.to_vec()])
            }
            Protocol::Udp => {
                let ip_matched = self.ipset.is_empty() || self.ipset.contains(dst_ip);
                if !ip_matched {
                    return vec![raw.to_vec()];
                }
                if is_quic_initial(parsed.payload) || is_discord_voice_or_stun(parsed.payload) {
                    let fooling = [Fooling::Ttl(3), Fooling::BadSum];
                    apply_udp_desync(raw, self.udp_repeats, &fooling, &[])
                        .unwrap_or_else(|_| vec![raw.to_vec()])
                } else {
                    vec![raw.to_vec()]
                }
            }
            _ => vec![raw.to_vec()],
        }
    }

    /// Запускает блокирующий цикл перехвата и модификации пакетов через WinDivert.
    #[cfg(windows)]
    pub fn run_divert(
        &mut self,
        dll_path: &Path,
        filter: &str,
        stop_flag: &AtomicBool,
    ) -> io::Result<()> {
        let channel = DivertChannel::open(dll_path, filter)?;
        while !stop_flag.load(Ordering::Relaxed) {
            let (raw, addr) = match channel.receive() {
                Ok(res) => res,
                Err(_) if stop_flag.load(Ordering::Relaxed) => break,
                Err(e) => return Err(e),
            };
            // В WinDivert RawAddress.outbound == 1 (или бит 0) означает исходящий пакет
            let outbound = (addr.outbound & 1) != 0;
            let out_packets = self.process_packet(&raw, outbound);
            for pkt in out_packets {
                let _ = channel.send(&pkt, &addr);
            }
        }
        Ok(())
    }
}
