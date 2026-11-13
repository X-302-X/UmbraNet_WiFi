//! Классификация использует только доказанные признаки; она не изменяет пакеты.
use super::application::Evidence;
use crate::domain::domain_matches;
use crate::selection::Snapshot;

#[derive(Debug, PartialEq, Eq)]
pub enum Match {
    Domain(String),
    Process(String),
    Unknown,
}

/// `verified_process` допускается только из проверенного сопоставления текущего соединения.
/// Неизвестная или устаревшая привязка не должна передаваться как подтверждённая.
pub fn classify(snapshot: &Snapshot, evidence: &Evidence, verified_process: Option<&str>) -> Match {
    if let Some(process) = verified_process {
        let name = process.to_ascii_lowercase();
        if snapshot.manual_processes.contains(&name) {
            return Match::Process(name);
        }
    }
    let hostname = match evidence {
        Evidence::HttpHost(host) | Evidence::TlsServerName(host) => host,
        Evidence::EncryptedClientHello | Evidence::Unknown => return Match::Unknown,
    };
    snapshot
        .domains
        .iter()
        .filter(|target| domain_matches(target, hostname))
        .max_by_key(|target| target.len())
        .cloned()
        .map(Match::Domain)
        .unwrap_or(Match::Unknown)
}

/// Один только похожий UDP-формат или порт не доказывает, что это Discord.
/// Привязка `verified_process` пока должна быть получена и проверена отдельно.
pub fn classify_udp(snapshot: &Snapshot, verified_process: Option<&str>) -> Match {
    if let Some(process) = verified_process {
        let name = process.to_ascii_lowercase();
        if snapshot.manual_processes.contains(&name) {
            return Match::Process(name);
        }
    }
    Match::Unknown
}
