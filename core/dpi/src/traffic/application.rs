//! Ограниченное распознавание HTTP Host и TLS ClientHello SNI без сборки потока.
use crate::domain::normalize_domain;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evidence {
    HttpHost(String),
    TlsServerName(String),
    /// Наружное имя ECH не подтверждает внутреннее имя назначения.
    EncryptedClientHello,
    Unknown,
}

fn word(bytes: &[u8]) -> usize {
    u16::from_be_bytes([bytes[0], bytes[1]]) as usize
}
fn take<'a>(input: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if input.len() < n {
        return None;
    }
    let (first, rest) = input.split_at(n);
    *input = rest;
    Some(first)
}
fn u8_len(input: &mut &[u8]) -> Option<usize> {
    Some(take(input, 1)?[0] as usize)
}
fn u16_len(input: &mut &[u8]) -> Option<usize> {
    Some(word(take(input, 2)?))
}

/// `at_stream_start` должно быть подтверждено отслеживанием последовательности TCP.
/// Произвольный кусок потока сам по себе не является доказательством Host или SNI.
pub fn inspect_tcp(payload: &[u8], at_stream_start: bool) -> Evidence {
    if !at_stream_start {
        return Evidence::Unknown;
    }
    if payload.first() == Some(&22) {
        return parse_tls(payload).unwrap_or(Evidence::Unknown);
    }
    parse_http(payload).unwrap_or(Evidence::Unknown)
}

fn parse_http(bytes: &[u8]) -> Option<Evidence> {
    // Максимум размера заголовков, чтобы не тратить память на большие произвольные payload.
    let end = bytes
        .windows(4)
        .take(16_384)
        .position(|w| w == b"\r\n\r\n")?
        + 4;
    let headers = std::str::from_utf8(&bytes[..end]).ok()?;
    if !headers.is_ascii() {
        return None;
    }
    let mut lines = headers.split("\r\n");
    let request = lines.next()?;
    let parts: Vec<_> = request.split(' ').collect();
    if parts.len() != 3
        || parts[0].is_empty()
        || !parts[0].bytes().all(|c| c.is_ascii_uppercase())
        || !(parts[1].starts_with('/') || (parts[0] == "OPTIONS" && parts[1] == "*"))
        || !matches!(parts[2], "HTTP/1.1" | "HTTP/1.0")
    {
        return None;
    }
    let mut host = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        // Не поддерживаем продолжение заголовков и неоднозначный синтаксис.
        if line.starts_with([' ', '\t']) {
            return None;
        }
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("host") {
            if host.is_some() {
                return None;
            }
            let value = value.trim();
            let hostname = if let Some((name, port)) = value.rsplit_once(':') {
                if port.is_empty()
                    || !port.bytes().all(|c| c.is_ascii_digit())
                    || port.parse::<u16>().is_err()
                {
                    return None;
                }
                name
            } else {
                value
            };
            host = Some(normalize_domain(hostname).ok()?);
        }
    }
    host.map(Evidence::HttpHost)
}

fn parse_tls(bytes: &[u8]) -> Option<Evidence> {
    if bytes.len() < 5 || bytes[0] != 22 || bytes[1] != 3 {
        return None;
    }
    let len = word(&bytes[3..5]);
    if bytes.len() < 5 + len {
        return None;
    }
    let mut record = &bytes[5..5 + len];
    let head = take(&mut record, 4)?;
    if head[0] != 1 {
        return None;
    }
    let handshake_len = ((head[1] as usize) << 16) | ((head[2] as usize) << 8) | head[3] as usize;
    let mut hello = take(&mut record, handshake_len)?;
    take(&mut hello, 2 + 32)?;
    let n = u8_len(&mut hello)?;
    take(&mut hello, n)?;
    let n = u16_len(&mut hello)?;
    if n == 0 || n % 2 != 0 {
        return None;
    }
    take(&mut hello, n)?;
    let n = u8_len(&mut hello)?;
    if n == 0 {
        return None;
    }
    take(&mut hello, n)?;
    let n = u16_len(&mut hello)?;
    let mut extensions = take(&mut hello, n)?;
    if !hello.is_empty() {
        return None;
    }
    let mut host = None;
    let mut ech = false;
    let mut saw_sni = false;
    while !extensions.is_empty() {
        let ty = u16_len(&mut extensions)?;
        let n = u16_len(&mut extensions)?;
        let mut data = take(&mut extensions, n)?;
        if ty == 0xfe0d {
            ech = true;
        }
        if ty == 0 {
            if saw_sni {
                return None;
            }
            saw_sni = true;
            let n = u16_len(&mut data)?;
            let mut names = take(&mut data, n)?;
            if !data.is_empty() || names.is_empty() {
                return None;
            }
            while !names.is_empty() {
                let kind = take(&mut names, 1)?[0];
                let n = u16_len(&mut names)?;
                let name = take(&mut names, n)?;
                if kind == 0 {
                    if host.is_some() {
                        return None;
                    }
                    host = Some(normalize_domain(std::str::from_utf8(name).ok()?).ok()?);
                }
            }
        }
    }
    if ech {
        Some(Evidence::EncryptedClientHello)
    } else {
        host.map(Evidence::TlsServerName)
    }
}
