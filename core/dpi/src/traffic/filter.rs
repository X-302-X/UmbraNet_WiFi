//! Фильтрация трафика по спискам доменов (Hostlist) и подсетям (IPSet).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Список доменов для точечного применения desync-стратегий.
#[derive(Debug, Clone, Default)]
pub struct HostList {
    domains: Vec<String>,
}

impl HostList {
    pub fn from_lines<'a>(lines: impl IntoIterator<Item = &'a str>) -> Self {
        let domains = lines
            .into_iter()
            .map(|l| l.trim().trim_start_matches('.').to_ascii_lowercase())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        Self { domains }
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// Проверяет точное совпадение или совпадение по суффиксу (поддомену).
    pub fn matches(&self, host: &str) -> bool {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return false;
        }
        self.domains.iter().any(|d| {
            host == *d
                || (host.len() > d.len()
                    && host.ends_with(d.as_str())
                    && host.as_bytes()[host.len() - d.len() - 1] == b'.')
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cidr {
    V4 { net: u32, mask: u32 },
    V6 { net: u128, mask: u128 },
}

/// Список IP-адресов и CIDR-подсетей (IPv4 / IPv6).
#[derive(Debug, Clone, Default)]
pub struct IpSet {
    entries: Vec<Cidr>,
}

impl IpSet {
    pub fn from_lines<'a>(lines: impl IntoIterator<Item = &'a str>) -> Self {
        let mut entries = Vec::new();
        for raw in lines {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(cidr) = parse_cidr(line) {
                entries.push(cidr);
            }
        }
        Self { entries }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let addr = u32::from(v4);
                self.entries.iter().any(|c| match *c {
                    Cidr::V4 { net, mask } => (addr & mask) == net,
                    Cidr::V6 { .. } => false,
                })
            }
            IpAddr::V6(v6) => {
                let addr = u128::from(v6);
                self.entries.iter().any(|c| match *c {
                    Cidr::V6 { net, mask } => (addr & mask) == net,
                    Cidr::V4 { .. } => false,
                })
            }
        }
    }
}

fn parse_cidr(s: &str) -> Option<Cidr> {
    if let Some((ip_str, prefix_str)) = s.split_once('/') {
        let prefix: u32 = prefix_str.parse().ok()?;
        match ip_str.parse::<IpAddr>().ok()? {
            IpAddr::V4(v4) if prefix <= 32 => {
                let mask = if prefix == 0 {
                    0
                } else {
                    !0u32 << (32 - prefix)
                };
                Some(Cidr::V4 {
                    net: u32::from(v4) & mask,
                    mask,
                })
            }
            IpAddr::V6(v6) if prefix <= 128 => {
                let mask = if prefix == 0 {
                    0
                } else {
                    !0u128 << (128 - prefix)
                };
                Some(Cidr::V6 {
                    net: u128::from(v6) & mask,
                    mask,
                })
            }
            _ => None,
        }
    } else {
        match s.parse::<IpAddr>().ok()? {
            IpAddr::V4(v4) => Some(Cidr::V4 {
                net: u32::from(Ipv4Addr::from(u32::from(v4))),
                mask: !0u32,
            }),
            IpAddr::V6(v6) => Some(Cidr::V6 {
                net: u128::from(Ipv6Addr::from(u128::from(v6))),
                mask: !0u128,
            }),
        }
    }
}
