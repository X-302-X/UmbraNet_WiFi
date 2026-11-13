//! Подготовка пассивного наблюдения; ничего не запускается при открытии приложения.
//! Настоящая сетевая работа требует отдельной Windows-проверки.
use crate::selection::Snapshot;

const WEB: &str = "outbound and !loopback and (tcp.DstPort == 80 or tcp.DstPort == 443 or tcp.DstPort == 2053 or tcp.DstPort == 2083 or tcp.DstPort == 2087 or tcp.DstPort == 2096 or tcp.DstPort == 8443 or udp.DstPort == 443)";
const WEB_AND_DISCORD_VOICE: &str = "outbound and !loopback and (tcp.DstPort == 80 or tcp.DstPort == 443 or tcp.DstPort == 2053 or tcp.DstPort == 2083 or tcp.DstPort == 2087 or tcp.DstPort == 2096 or tcp.DstPort == 8443 or udp.DstPort == 443 or (udp.DstPort >= 19294 and udp.DstPort <= 19344) or (udp.DstPort >= 50000 and udp.DstPort <= 65535))";

/// Только предварительный выбор копий для диагностики, не решение об обходе.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapturePlan {
    include_discord_voice: bool,
}

impl CapturePlan {
    pub fn from_snapshot(snapshot: &Snapshot) -> Option<Self> {
        if snapshot.domains.is_empty() && snapshot.manual_processes.is_empty() {
            return None;
        }
        Some(Self {
            include_discord_voice: snapshot.services.contains("discord")
                || snapshot.manual_processes.contains("discord.exe"),
        })
    }

    pub fn includes_discord_voice(&self) -> bool {
        self.include_discord_voice
    }

    pub fn filter(&self) -> &'static str {
        if self.include_discord_voice {
            WEB_AND_DISCORD_VOICE
        } else {
            WEB
        }
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub mod windivert;
