//! Активный TCP/TLS desync-движок:
//! - семантический поиск позиций разреза (SNI, Host, SLD, Method, Mid, Offset);
//! - AutoTTL на основе входящего TTL сервера;
//! - генерация fake-пакетов (TTL, BadSum, BadSeq, TCP MD5SIG option);
//! - multisplit и disorder для IPv4/IPv6 TCP (включая пакеты с TCP options);
//! - TLS record split (разбиение TLS ClientHello на несколько TLS-записей).

use super::packet::{parse_ip, PacketError, Protocol};

pub const MAX_DESYNC_PACKETS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesyncError {
    Packet(PacketError),
    Unsupported,
    EmptyPayload,
    InvalidConfig,
    TooManyPackets,
}

/// Способ задания позиции разреза в TCP payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitPos {
    /// Точное смещение от начала payload (1..len).
    Offset(usize),
    /// Начало имени хоста (HTTP Host или TLS SNI).
    Host,
    /// Конец имени хоста.
    EndHost,
    /// Середина домена (SLD), чтобы разорвать имя хоста пополам.
    Sld,
    /// Сразу после HTTP-метода (например, после `GET `).
    Method,
    /// Середина payload.
    Mid,
}

/// Метод «отравления» DPI для fake-пакета (чтобы DPI его принял, а сервер отбросил).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fooling {
    /// Низкий TTL (или AutoTTL).
    Ttl(u8),
    /// Намеренно неверная TCP checksum.
    BadSum,
    /// Сдвиг sequence number (выход за TCP window сервера).
    BadSeq(i32),
    /// Добавление TCP option 19 (MD5 Signature, 18 байт).
    Md5Sig,
}

/// План одного desync-преобразования.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesyncPlan {
    /// Позиции разреза (для split/multisplit/disorder).
    pub splits: Vec<SplitPos>,
    /// Отправлять сегменты в обратном порядке (disorder).
    pub disorder: bool,
    /// Вставлять fake-пакет перед реальными сегментами.
    pub fake: bool,
    /// Сколько раз повторить fake-пакет.
    pub fake_repeats: u8,
    /// Методы fooling для fake-пакета.
    pub fooling: Vec<Fooling>,
    /// Кастомный payload для fake-пакета (если пусто — копируется начало реального).
    pub fake_payload: Vec<u8>,
    /// Разбить TLS ClientHello на несколько TLS-записей перед TCP-сегментацией.
    pub tls_record_split: Option<usize>,
}

impl Default for DesyncPlan {
    fn default() -> Self {
        Self {
            splits: vec![SplitPos::Sld],
            disorder: false,
            fake: false,
            fake_repeats: 1,
            fooling: vec![Fooling::BadSum],
            fake_payload: Vec::new(),
            tls_record_split: None,
        }
    }
}

/// Вычисляет оптимальный TTL для fake-пакета на основе TTL от сервера.
/// Эвристика как в zapret: определяем исходный TTL (64 / 128 / 255),
/// считаем число хопов и вычитаем `delta`, зажимая в `[min_ttl, max_ttl]`.
pub fn auto_ttl(server_ttl: u8, delta: u8, min_ttl: u8, max_ttl: u8) -> u8 {
    let initial: u8 = if server_ttl <= 64 {
        64
    } else if server_ttl <= 128 {
        128
    } else {
        255
    };
    let hops = initial.saturating_sub(server_ttl).max(1);
    let target = hops.saturating_sub(delta).max(1);
    target.clamp(min_ttl.max(1), max_ttl.max(min_ttl.max(1)))
}

fn sum_words(bytes: &[u8]) -> u64 {
    let mut chunks = bytes.chunks_exact(2);
    let mut sum: u64 = chunks
        .by_ref()
        .map(|c| u16::from_be_bytes([c[0], c[1]]) as u64)
        .sum();
    if let [b] = chunks.remainder() {
        sum += (*b as u64) << 8;
    }
    sum
}

fn finish_sum(mut sum: u64) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Пересчитывает IPv4 header checksum (если IPv4) и TCP checksum.
pub fn write_checksums(raw: &mut [u8], ipv6: bool, ip_len: usize) {
    let tcp_len = raw.len() - ip_len;
    raw[ip_len + 16..ip_len + 18].fill(0);
    let pseudo = if ipv6 {
        sum_words(&raw[8..40])
    } else {
        sum_words(&raw[12..20])
    };
    let tcp_sum = finish_sum(pseudo + tcp_len as u64 + 6 + sum_words(&raw[ip_len..]));
    raw[ip_len + 16..ip_len + 18].copy_from_slice(&tcp_sum.to_be_bytes());
    if !ipv6 {
        raw[10..12].fill(0);
        let ip_sum = finish_sum(sum_words(&raw[..ip_len]));
        raw[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    }
}

/// Находит диапазон `(start, end)` имени хоста в HTTP-запросе или TLS ClientHello SNI.
pub fn find_host_range(payload: &[u8]) -> Option<(usize, usize)> {
    if let Some(range) = find_tls_sni_range(payload) {
        return Some(range);
    }
    find_http_host_range(payload)
}

fn find_http_host_range(payload: &[u8]) -> Option<(usize, usize)> {
    let lower_scan_limit = payload.len().min(2048);
    let slice = &payload[..lower_scan_limit];
    for i in 0..slice.len().saturating_sub(6) {
        let is_line_start = i == 0 || (i >= 2 && slice[i - 2] == b'\r' && slice[i - 1] == b'\n');
        if !is_line_start {
            continue;
        }
        if slice[i..].len() >= 5 && slice[i..i + 5].eq_ignore_ascii_case(b"host:") {
            let mut start = i + 5;
            while start < slice.len() && (slice[start] == b' ' || slice[start] == b'\t') {
                start += 1;
            }
            let mut end = start;
            while end < slice.len() && slice[end] != b'\r' && slice[end] != b'\n' && slice[end] != b':' {
                end += 1;
            }
            if end > start {
                return Some((start, end));
            }
        }
    }
    None
}

fn find_tls_sni_range(payload: &[u8]) -> Option<(usize, usize)> {
    // TLS Record: ContentType=0x16 (Handshake), Version 0x03 0x01..0x04
    if payload.len() < 43 || payload[0] != 0x16 || payload[1] != 0x03 {
        return None;
    }
    // HandshakeType=0x01 (ClientHello)
    if payload[5] != 0x01 {
        return None;
    }
    let mut pos = 9 + 2 + 32; // record(5) + hs(4) + version(2) + random(32)
    if pos >= payload.len() {
        return None;
    }
    let session_id_len = payload[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > payload.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;
    if pos + 1 > payload.len() {
        return None;
    }
    let comp_len = payload[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > payload.len() {
        return None;
    }
    let ext_total_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total_len).min(payload.len());

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let ext_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            break;
        }
        if ext_type == 0x0000 && ext_len >= 5 {
            // SNI list: list_len(2) + name_type(1) + name_len(2) + name
            let name_type = payload[pos + 2];
            let name_len = u16::from_be_bytes([payload[pos + 3], payload[pos + 4]]) as usize;
            let name_start = pos + 5;
            let name_end = name_start + name_len;
            if name_type == 0 && name_len > 0 && name_end <= pos + ext_len {
                return Some((name_start, name_end));
            }
        }
        pos += ext_len;
    }
    None
}

fn find_http_method_end(payload: &[u8]) -> Option<usize> {
    const METHODS: &[&[u8]] = &[
        b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ",
    ];
    for m in METHODS {
        if payload.starts_with(m) && payload.len() > m.len() {
            return Some(m.len());
        }
    }
    None
}

/// Преобразует список `SplitPos` в отсортированные уникальные смещения внутри `1..payload.len()`.
pub fn resolve_split_positions(payload: &[u8], positions: &[SplitPos]) -> Vec<usize> {
    if payload.len() <= 1 {
        return Vec::new();
    }
    let host_range = find_host_range(payload);
    let mut cuts = Vec::new();
    for pos in positions {
        let offset = match pos {
            SplitPos::Offset(o) => Some(*o),
            SplitPos::Host => host_range.map(|(s, _)| s),
            SplitPos::EndHost => host_range.map(|(_, e)| e),
            SplitPos::Sld => host_range.map(|(s, e)| s + (e - s) / 2),
            SplitPos::Method => find_http_method_end(payload),
            SplitPos::Mid => Some(payload.len() / 2),
        };
        if let Some(o) = offset {
            if o > 0 && o < payload.len() {
                cuts.push(o);
            }
        }
    }
    cuts.sort_unstable();
    cuts.dedup();
    cuts
}

/// Разбивает TLS Handshake record (0x16) на два TLS-записи по смещению `split_at` внутри record payload.
/// Если пакет не является одиночной TLS-записью или `split_at` вне границ — возвращает исходный payload.
pub fn split_tls_record(payload: &[u8], split_at: usize) -> Vec<u8> {
    if payload.len() < 6 || payload[0] != 0x16 || payload[1] != 0x03 {
        return payload.to_vec();
    }
    let rec_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if 5 + rec_len != payload.len() || split_at == 0 || split_at >= rec_len {
        return payload.to_vec();
    }
    let ver = [payload[1], payload[2]];
    let first_len = (split_at as u16).to_be_bytes();
    let second_len = ((rec_len - split_at) as u16).to_be_bytes();

    let mut out = Vec::with_capacity(payload.len() + 5);
    out.push(0x16);
    out.extend_from_slice(&ver);
    out.extend_from_slice(&first_len);
    out.extend_from_slice(&payload[5..5 + split_at]);

    out.push(0x16);
    out.extend_from_slice(&ver);
    out.extend_from_slice(&second_len);
    out.extend_from_slice(&payload[5 + split_at..]);
    out
}

/// Создаёт fake TCP-пакет на основе оригинального IPv4/IPv6 TCP-пакета и заданных методов `Fooling`.
pub fn build_fake_tcp(
    raw: &[u8],
    fooling: &[Fooling],
    fake_payload: &[u8],
) -> Result<Vec<u8>, DesyncError> {
    let packet = parse_ip(raw).map_err(DesyncError::Packet)?;
    if packet.protocol != Protocol::Tcp {
        return Err(DesyncError::Unsupported);
    }
    let _tcp = packet.tcp.ok_or(DesyncError::Unsupported)?;
    let ipv6 = raw[0] >> 4 == 6;
    let ip_len = if ipv6 { 40 } else { ((raw[0] & 0x0f) as usize) * 4 };
    if raw.len() < ip_len + 20 {
        return Err(DesyncError::Unsupported);
    }
    let data_offset = raw[ip_len + 12] >> 4;
    let tcp_hdr_len = data_offset as usize * 4;
    let base_hdr_len = ip_len + tcp_hdr_len;
    if raw.len() < base_hdr_len {
        return Err(DesyncError::Unsupported);
    }

    let add_md5 = fooling.contains(&Fooling::Md5Sig);
    let extra_opts_len = if add_md5 { 20 } else { 0 }; // 18 bytes MD5 + 2 bytes NOP padding
    let payload = if fake_payload.is_empty() {
        packet.payload
    } else {
        fake_payload
    };

    let mut fake = Vec::with_capacity(base_hdr_len + extra_opts_len + payload.len());
    fake.extend_from_slice(&raw[..base_hdr_len]);
    if add_md5 {
        // TCP Option 19 (MD5 Signature): kind=19, len=18, 16 zero bytes + 2 NOPs (0x01, 0x01)
        fake.push(19);
        fake.push(18);
        fake.extend_from_slice(&[0u8; 16]);
        fake.push(1);
        fake.push(1);
        let new_doff = (data_offset + 5).min(15);
        fake[ip_len + 12] = (fake[ip_len + 12] & 0x0f) | (new_doff << 4);
    }
    fake.extend_from_slice(payload);

    // Обновляем длину IP-пакета
    if ipv6 {
        let plen = (fake.len() - 40) as u16;
        fake[4..6].copy_from_slice(&plen.to_be_bytes());
    } else {
        let tlen = fake.len() as u16;
        fake[2..4].copy_from_slice(&tlen.to_be_bytes());
    }

    // Применяем fooling
    let mut bad_sum = false;
    for f in fooling {
        match *f {
            Fooling::Ttl(ttl) => {
                if ipv6 {
                    fake[7] = ttl.max(1);
                } else {
                    fake[8] = ttl.max(1);
                }
            }
            Fooling::BadSeq(delta) => {
                let seq = u32::from_be_bytes([
                    fake[ip_len + 4],
                    fake[ip_len + 5],
                    fake[ip_len + 6],
                    fake[ip_len + 7],
                ]);
                let new_seq = seq.wrapping_add_signed(delta);
                fake[ip_len + 4..ip_len + 8].copy_from_slice(&new_seq.to_be_bytes());
            }
            Fooling::BadSum => {
                bad_sum = true;
            }
            Fooling::Md5Sig => {}
        }
    }

    write_checksums(&mut fake, ipv6, ip_len);
    if bad_sum {
        fake[ip_len + 16] ^= 0xff;
        fake[ip_len + 17] ^= 0xff;
    }

    Ok(fake)
}

/// Применяет `DesyncPlan` к реальному IPv4/IPv6 TCP-пакету и возвращает
/// последовательность готовых к отправке IP-пакетов.
pub fn apply_desync(raw: &[u8], plan: &DesyncPlan) -> Result<Vec<Vec<u8>>, DesyncError> {
    let packet = parse_ip(raw).map_err(DesyncError::Packet)?;
    if packet.protocol != Protocol::Tcp {
        return Err(DesyncError::Unsupported);
    }
    let tcp = packet.tcp.ok_or(DesyncError::Unsupported)?;
    if packet.payload.is_empty() {
        return Err(DesyncError::EmptyPayload);
    }

    let ipv6 = raw[0] >> 4 == 6;
    let ip_len = if ipv6 { 40 } else { ((raw[0] & 0x0f) as usize) * 4 };
    if raw.len() < ip_len + 20 {
        return Err(DesyncError::Unsupported);
    }
    let tcp_hdr_len = (raw[ip_len + 12] >> 4) as usize * 4;
    let header_len = ip_len + tcp_hdr_len;
    if raw.len() < header_len {
        return Err(DesyncError::Unsupported);
    }

    let working_payload = match plan.tls_record_split {
        Some(pos) => split_tls_record(packet.payload, pos),
        None => packet.payload.to_vec(),
    };

    let cuts = resolve_split_positions(&working_payload, &plan.splits);
    let mut segments = Vec::new();
    let mut start = 0usize;
    let base_seq = tcp.sequence;
    let base_ip_id = if ipv6 {
        0
    } else {
        u16::from_be_bytes([raw[4], raw[5]])
    };

    let boundaries: Vec<usize> = cuts
        .iter()
        .copied()
        .chain(std::iter::once(working_payload.len()))
        .collect();

    for (idx, &end) in boundaries.iter().enumerate() {
        let mut seg = Vec::with_capacity(header_len + (end - start));
        seg.extend_from_slice(&raw[..header_len]);
        seg.extend_from_slice(&working_payload[start..end]);

        if ipv6 {
            let plen = (seg.len() - 40) as u16;
            seg[4..6].copy_from_slice(&plen.to_be_bytes());
        } else {
            let tlen = seg.len() as u16;
            seg[2..4].copy_from_slice(&tlen.to_be_bytes());
            let ip_id = base_ip_id.wrapping_add(idx as u16);
            seg[4..6].copy_from_slice(&ip_id.to_be_bytes());
        }

        let seg_seq = base_seq.wrapping_add(start as u32);
        seg[ip_len + 4..ip_len + 8].copy_from_slice(&seg_seq.to_be_bytes());

        // PSH оставляем только на последнем сегменте
        if idx + 1 < boundaries.len() {
            seg[ip_len + 13] &= !0x08;
        }

        write_checksums(&mut seg, ipv6, ip_len);
        segments.push(seg);
        start = end;
    }

    if plan.disorder && segments.len() > 1 {
        segments.reverse();
    }

    let mut out = Vec::new();
    if plan.fake {
        let repeats = plan.fake_repeats.max(1);
        for _ in 0..repeats {
            if out.len() >= MAX_DESYNC_PACKETS {
                return Err(DesyncError::TooManyPackets);
            }
            out.push(build_fake_tcp(raw, &plan.fooling, &plan.fake_payload)?);
        }
    }

    if out.len() + segments.len() > MAX_DESYNC_PACKETS {
        return Err(DesyncError::TooManyPackets);
    }
    out.extend(segments);
    Ok(out)
}
