//! autohostlist: домены, которые уже пострадали от DPI (RST, обрыв TLS),
//! автоматически добавляются в список обхода и сохраняются на диск.

use crate::traffic::desync::find_host_range;
use crate::traffic::filter::HostList;
use crate::traffic::packet::{parse_ip, Protocol};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const FILE_NAME: &str = "autohostlist.txt";
const MAX_DOMAINS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// Сервер прислал RST на исходящий запрос.
    Rst,
    /// TLS/HTTP ответ не пришёл за отведённое время.
    Timeout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Stored {
    version: u32,
    domains: Vec<String>,
}

#[derive(Clone)]
pub struct AutoHostList {
    path: PathBuf,
    domains: BTreeSet<String>,
}

impl AutoHostList {
    pub fn load(dir: &Path) -> Self {
        let path = dir.join(FILE_NAME);
        let domains = fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str::<Stored>(&text).ok())
            .filter(|stored| stored.version == 1)
            .map(|stored| {
                stored
                    .domains
                    .into_iter()
                    .map(|d| d.trim().to_ascii_lowercase())
                    .filter(|d| !d.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        Self { path, domains }
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    pub fn domains(&self) -> Vec<String> {
        self.domains.iter().cloned().collect()
    }

    /// Домены как готовый `HostList` (используется движком).
    pub fn as_hostlist(&self) -> HostList {
        HostList::from_lines(self.domains.iter().map(|s| s.as_str()))
    }

    pub fn contains(&self, host: &str) -> bool {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        self.domains.iter().any(|d| {
            host == *d
                || (host.len() > d.len()
                    && host.ends_with(d.as_str())
                    && host.as_bytes()[host.len() - d.len() - 1] == b'.')
        })
    }

    /// Регистрирует сбой для домена. Возвращает true, если домен добавлен впервые.
    pub fn record(&mut self, host: &str) -> bool {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || host.len() > 253 || !host.contains('.') {
            return false;
        }
        if self.domains.contains(&host) {
            return false;
        }
        if self.domains.len() >= MAX_DOMAINS {
            return false;
        }
        self.domains.insert(host);
        let _ = self.save();
        true
    }

    pub fn clear(&mut self) -> Result<(), String> {
        self.domains.clear();
        self.save()
    }

    fn save(&self) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Не удалось создать {}: {e}", parent.display()))?;
        }
        let stored = Stored {
            version: 1,
            domains: self.domains.iter().cloned().collect(),
        };
        let text = serde_json::to_string_pretty(&stored)
            .map_err(|e| format!("Не удалось собрать autohostlist: {e}"))?;
        crate::selection::atomic_write(&self.path, text.as_bytes())
            .map_err(|e| format!("Не удалось сохранить autohostlist: {e}"))
    }
}

/// Признак сбоя на входящем пакете от сервера.
pub fn failure_kind(raw: &[u8]) -> Option<Failure> {
    let packet = parse_ip(raw).ok()?;
    if packet.protocol != Protocol::Tcp {
        return None;
    }
    let tcp = packet.tcp?;
    // RST без полезной нагрузки — типичный признак вмешательства DPI.
    if tcp.flags & 0x04 != 0 && packet.payload.is_empty() {
        return Some(Failure::Rst);
    }
    None
}

/// Имя домена из payload (HTTP Host или TLS SNI).
pub fn host_from_payload(payload: &[u8]) -> Option<String> {
    let (start, end) = find_host_range(payload)?;
    let host = std::str::from_utf8(&payload[start..end]).ok()?;
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}
