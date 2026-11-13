//! Подготовка пассивного наблюдения; ничего не запускается при открытии приложения.
//! Настоящая сетевая работа требует отдельной Windows-проверки.
use crate::catalog::Catalog;
use crate::selection::{Selection, Snapshot};

const WEB: &str = "outbound and !loopback and (tcp.DstPort == 80 or tcp.DstPort == 443 or tcp.DstPort == 2053 or tcp.DstPort == 2083 or tcp.DstPort == 2087 or tcp.DstPort == 2096 or tcp.DstPort == 8443 or udp.DstPort == 443)";
const WEB_AND_DISCORD_VOICE: &str = "outbound and !loopback and (tcp.DstPort == 80 or tcp.DstPort == 443 or tcp.DstPort == 2053 or tcp.DstPort == 2083 or tcp.DstPort == 2087 or tcp.DstPort == 2096 or tcp.DstPort == 8443 or udp.DstPort == 443 or (udp.DstPort >= 19294 and udp.DstPort <= 19344) or (udp.DstPort >= 50000 and udp.DstPort <= 65535))";
const FLOW_WEB: &str = "outbound and ((protocol == 6 and (remotePort == 80 or remotePort == 443 or remotePort == 2053 or remotePort == 2083 or remotePort == 2087 or remotePort == 2096 or remotePort == 8443)) or (protocol == 17 and remotePort == 443))";
const FLOW_WEB_AND_DISCORD_VOICE: &str = "outbound and ((protocol == 6 and (remotePort == 80 or remotePort == 443 or remotePort == 2053 or remotePort == 2083 or remotePort == 2087 or remotePort == 2096 or remotePort == 8443)) or (protocol == 17 and (remotePort == 443 or (remotePort >= 19294 and remotePort <= 19344) or (remotePort >= 50000 and remotePort <= 65535))))";

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

    /// Строит план из текущего выбора без запуска стратегии или двигателя.
    pub fn from_selection(
        catalog: &Catalog,
        selection: &Selection,
    ) -> Result<Option<Self>, String> {
        if selection.active_domains(catalog)?.is_empty() && selection.manual_processes().is_empty()
        {
            return Ok(None);
        }
        Ok(Some(Self {
            include_discord_voice: selection.selected_services().contains("discord")
                || selection.manual_processes().contains("discord.exe"),
        }))
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

    /// На FLOW применяются те же категории портов, что и в пассивном NETWORK.
    pub fn flow_filter(&self) -> &'static str {
        if self.include_discord_voice {
            FLOW_WEB_AND_DISCORD_VOICE
        } else {
            FLOW_WEB
        }
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub mod windivert;
