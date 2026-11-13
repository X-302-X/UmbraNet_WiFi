//! Распознавание формы UDP-сообщений. Совпадение формы не доказывает источник.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryKind {
    Request,
    Response,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpEvidence {
    /// Похоже на корректное сообщение STUN; STUN используют и другие приложения.
    Stun,
    /// Похоже на задокументированный формат Discord IP Discovery.
    DiscordIpDiscovery(DiscoveryKind),
    Unknown,
}

fn word(bytes: &[u8]) -> usize {
    u16::from_be_bytes([bytes[0], bytes[1]]) as usize
}

/// Никакие идентификаторы, IP, порты или содержимое пакета не сохраняются.
pub fn inspect_udp(payload: &[u8]) -> UdpEvidence {
    if looks_like_stun(payload) {
        return UdpEvidence::Stun;
    }
    // Discord документирует 4-байтовый заголовок и 70 байт после него.
    // Одно только сходство формата не является доказательством процесса или сервиса.
    if payload.len() == 74 && word(&payload[2..4]) == 70 {
        return match word(&payload[..2]) {
            1 => UdpEvidence::DiscordIpDiscovery(DiscoveryKind::Request),
            2 => UdpEvidence::DiscordIpDiscovery(DiscoveryKind::Response),
            _ => UdpEvidence::Unknown,
        };
    }
    UdpEvidence::Unknown
}

fn looks_like_stun(payload: &[u8]) -> bool {
    if payload.len() < 20 || payload[0] & 0xc0 != 0 || payload[4..8] != [0x21, 0x12, 0xa4, 0x42] {
        return false;
    }
    let length = word(&payload[2..4]);
    if length % 4 != 0 || payload.len() != 20 + length {
        return false;
    }
    let mut attributes = &payload[20..];
    while !attributes.is_empty() {
        if attributes.len() < 4 {
            return false;
        }
        let value_len = word(&attributes[2..4]);
        let padded_len = (value_len + 3) & !3;
        if attributes.len() - 4 < padded_len {
            return false;
        }
        attributes = &attributes[4 + padded_len..];
    }
    true
}
