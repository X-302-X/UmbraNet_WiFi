//! Активный цикл обработки трафика (Engine Loop):
//! связывает DivertChannel, HostList/IpSet, кэш server_ttl для AutoTtl,
//! TCP/TLS desync и UDP/QUIC/Discord desync.

use crate::autohostlist::{failure_kind, AutoHostList};
use crate::strategy::Strategy;
use crate::traffic::application::{inspect_tcp, Evidence};
use crate::traffic::desync::{apply_desync, Fooling};
use crate::traffic::filter::{HostList, IpSet};
use crate::traffic::packet::{parse_ip, Protocol};
use crate::traffic::udp_desync::{apply_udp_desync, is_discord_voice_or_stun, is_quic_initial};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(all(windows, target_arch = "x86_64"))]
use std::io;
#[cfg(all(windows, target_arch = "x86_64"))]
use std::sync::atomic::AtomicBool;
#[cfg(all(windows, target_arch = "x86_64"))]
use std::sync::mpsc::Sender;

/// Ограничение кэша TTL, чтобы долгая сессия не росла бесконечно.
const MAX_TTL_ENTRIES: usize = 4096;

/// Сколько живёт запись «этот домен ушёл на этот адрес» для autohostlist.
const PENDING_TTL_SECS: u64 = 30;

pub struct Engine {
    pub strategy: Strategy,
    pub hostlist: HostList,
    pub ipset: IpSet,
    pub auto: Option<AutoHostList>,
    udp_repeats: u8,
    udp_fooling: Vec<Fooling>,
    server_ttl: HashMap<IpAddr, u8>,
    /// (адрес назначения, порт) -> (домен, время) для реакции на RST.
    pending: HashMap<(IpAddr, u16), (String, std::time::Instant)>,
}

impl Engine {
    pub fn new(strategy: Strategy, hostlist: HostList, ipset: IpSet) -> Self {
        Self::with_autohostlist(strategy, hostlist, ipset, None)
    }

    pub fn with_autohostlist(
        strategy: Strategy,
        hostlist: HostList,
        ipset: IpSet,
        auto: Option<AutoHostList>,
    ) -> Self {
        let (udp_repeats, udp_fooling) = strategy.udp_fake().unwrap_or((6, vec![Fooling::Ttl(3)]));
        Self {
            strategy,
            hostlist,
            ipset,
            auto,
            udp_repeats,
            udp_fooling,
            server_ttl: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    /// Домены, автоматически добавленные из-за сбоев.
    pub fn auto_domains(&self) -> Vec<String> {
        self.auto.as_ref().map(|a| a.domains()).unwrap_or_default()
    }

    pub fn clear_auto(&mut self) -> Result<(), String> {
        match &mut self.auto {
            Some(auto) => auto.clear(),
            None => Ok(()),
        }
    }

    fn host_allowed(&self, host: &str) -> bool {
        // Autohostlist не должна расширять явно выбранную область.
        self.hostlist.matches(host)
    }

    /// Заменяет активную стратегию без пересоздания движка.
    pub fn set_strategy(&mut self, strategy: Strategy) {
        let (repeats, fooling) = strategy.udp_fake().unwrap_or((6, vec![Fooling::Ttl(3)]));
        self.strategy = strategy;
        self.udp_repeats = repeats;
        self.udp_fooling = fooling;
        self.server_ttl.clear();
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
                Some((
                    IpAddr::V6(Ipv6Addr::from(s)),
                    IpAddr::V6(Ipv6Addr::from(d)),
                    raw[7],
                ))
            }
            _ => None,
        }
    }

    fn remember_ttl(&mut self, ip: IpAddr, ttl: u8) {
        if self.server_ttl.len() >= MAX_TTL_ENTRIES && !self.server_ttl.contains_key(&ip) {
            self.server_ttl.clear();
        }
        self.server_ttl.insert(ip, ttl);
    }

    /// Обрабатывает один перехваченный IP-пакет.
    /// Возвращает список пакетов для отправки обратно в сеть.
    pub fn process_packet(&mut self, raw: &[u8], outbound: bool) -> Vec<Vec<u8>> {
        let Some((src_ip, dst_ip, ttl)) = Self::extract_ips(raw) else {
            return vec![raw.to_vec()];
        };

        // На входящих пакетах запоминаем TTL сервера для AutoTtl
        // и ловим RST, чтобы пополнить autohostlist.
        if !outbound {
            self.remember_ttl(src_ip, ttl);
            if let Ok(parsed) = parse_ip(raw) {
                if failure_kind(raw).is_some() {
                    // Ключ — адрес сервера и его порт (у входящего source_port = 443).
                    let key = (src_ip, parsed.source_port);
                    if let Some((host, at)) = self.pending.get(&key) {
                        if at.elapsed().as_secs() <= PENDING_TTL_SECS {
                            if let Some(auto) = &mut self.auto {
                                auto.record(host);
                            }
                        }
                    }
                }
            }
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
                // Это только синтаксический разбор одного payload, а не доказательство
                // начала TCP-потока. Активный запуск отдельно заблокирован до внедрения
                // проверенного жизненного цикла соединений.
                let host = match inspect_tcp(parsed.payload, true) {
                    Evidence::HttpHost(host) | Evidence::TlsServerName(host) => host,
                    Evidence::EncryptedClientHello | Evidence::Unknown => return vec![raw.to_vec()],
                };
                // IP/CDN может быть общим, а autohostlist — не явный выбор пользователя.
                if !self.host_allowed(&host) {
                    return vec![raw.to_vec()];
                }
                self.pending
                    .retain(|_, (_, at)| at.elapsed().as_secs() <= PENDING_TTL_SECS);
                if self.pending.len() >= MAX_TTL_ENTRIES {
                    self.pending.clear();
                }
                self.pending.insert(
                    (dst_ip, parsed.destination_port),
                    (host, std::time::Instant::now()),
                );

                let sttl = self.server_ttl.get(&dst_ip).copied();
                let plan = self.strategy.to_desync_plan(sttl);
                match apply_desync(raw, &plan) {
                    Ok(packets) => packets,
                    // Известные ограничения (нет payload, слишком много сегментов) — не ошибка.
                    Err(_) => vec![raw.to_vec()],
                }
            }
            Protocol::Udp => {
                // Формат QUIC/STUN и IP не подтверждают принадлежность выбранному
                // сервису или процессу. До надёжной привязки не изменяем UDP.
                if !crate::safety::udp_target_verified() {
                    return vec![raw.to_vec()];
                }
                let ip_matched = self.ipset.is_empty() || self.ipset.contains(dst_ip);
                if !ip_matched {
                    return vec![raw.to_vec()];
                }
                if self.udp_fooling.is_empty() {
                    return vec![raw.to_vec()];
                }
                if is_quic_initial(parsed.payload) || is_discord_voice_or_stun(parsed.payload) {
                    match apply_udp_desync(raw, self.udp_repeats, &self.udp_fooling, &[]) {
                        Ok(packets) => packets,
                        Err(_) => vec![raw.to_vec()],
                    }
                } else {
                    vec![raw.to_vec()]
                }
            }
        }
    }

    /// Цикл с передачей ошибок наружу (для интерфейса).
    #[cfg(all(windows, target_arch = "x86_64"))]
    pub fn run_channel_with_events(
        &mut self,
        channel: &crate::capture::windivert::DivertChannel,
        stop_flag: &AtomicBool,
        events: Option<Sender<String>>,
    ) -> io::Result<()> {
        let result = self.run_channel(channel, stop_flag);
        if let (Err(error), Some(tx)) = (&result, events) {
            let _ = tx.send(format!("Движок остановлен: {error}"));
        }
        result
    }

    /// Цикл обработки по уже открытому каналу (нужен для внешней остановки).
    #[cfg(all(windows, target_arch = "x86_64"))]
    pub fn run_channel(
        &mut self,
        channel: &crate::capture::windivert::DivertChannel,
        stop_flag: &AtomicBool,
    ) -> io::Result<()> {
        // Даже при наличии канала цикл нельзя включать до безопасного drain.
        crate::safety::active_start_guard()
            .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
        // Контроллер должен сначала установить флаг, затем выполнить Shutdown(RECV).
        // Цикл отправит оригиналы оставшейся очереди до ERROR_NO_DATA.
        // Это не является подтверждением закрытия handle или выгрузки драйвера.
        crate::capture::packet_loop::run(channel, stop_flag, |raw, _addr| {
            // Даже корректные checksum и metadata не доказывают отсутствие LSO
            // или принадлежность выбранной цели. Только неизменённый оригинал.
            crate::capture::tcp_checksum::pass_through_while_lso_unknown(raw)
        })
    }
}
