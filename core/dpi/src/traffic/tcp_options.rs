//! Строгий разбор распространённых TCP options без отслеживания их negotiation.

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Options {
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub sack_blocks: Vec<(u32, u32)>,
    pub timestamp: Option<(u32, u32)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionError {
    Malformed,
    Unsupported,
    WrongContext,
}

fn u32be(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// `syn` и `ack` — биты текущего TCP-заголовка, не состояние соединения.
/// Неизвестные options отвергаются; EOL допускает только нулевое заполнение.
/// SACK/TS negotiation, порядок блоков и значения timestamp здесь не проверяются.
pub fn parse(options: &[u8], syn: bool, ack: bool) -> Result<Options, OptionError> {
    if options.len() > 40 || options.len() % 4 != 0 {
        return Err(OptionError::Malformed);
    }
    let mut result = Options::default();
    let mut i = 0;
    let mut saw_sack = false;
    while i < options.len() {
        match options[i] {
            0 => {
                if options[i + 1..].iter().any(|b| *b != 0) {
                    return Err(OptionError::Malformed);
                }
                break;
            }
            1 => {
                i += 1;
                continue;
            }
            _ => {}
        }
        if i + 1 >= options.len() {
            return Err(OptionError::Malformed);
        }
        let length = options[i + 1] as usize;
        if length < 2 || length > options.len() - i {
            return Err(OptionError::Malformed);
        }
        let data = &options[i + 2..i + length];
        match options[i] {
            2 => {
                if length != 4 || result.mss.is_some() {
                    return Err(OptionError::Malformed);
                }
                if !syn {
                    return Err(OptionError::WrongContext);
                }
                let mss = u16::from_be_bytes([data[0], data[1]]);
                if mss == 0 {
                    return Err(OptionError::Malformed);
                }
                result.mss = Some(mss);
            }
            3 => {
                if length != 3 || result.window_scale.is_some() || data[0] > 14 {
                    return Err(OptionError::Malformed);
                }
                if !syn {
                    return Err(OptionError::WrongContext);
                }
                result.window_scale = Some(data[0]);
            }
            4 => {
                if length != 2 || result.sack_permitted {
                    return Err(OptionError::Malformed);
                }
                if !syn {
                    return Err(OptionError::WrongContext);
                }
                result.sack_permitted = true;
            }
            5 => {
                if saw_sack || length < 10 || length > 34 || (length - 2) % 8 != 0 {
                    return Err(OptionError::Malformed);
                }
                if syn || !ack {
                    return Err(OptionError::WrongContext);
                }
                saw_sack = true;
                for block in data.chunks_exact(8) {
                    let left = u32be(&block[..4]);
                    let right = u32be(&block[4..]);
                    if left == right {
                        return Err(OptionError::Malformed);
                    }
                    result.sack_blocks.push((left, right));
                }
            }
            8 => {
                if length != 10 || result.timestamp.is_some() {
                    return Err(OptionError::Malformed);
                }
                result.timestamp = Some((u32be(&data[..4]), u32be(&data[4..])));
            }
            _ => return Err(OptionError::Unsupported),
        }
        i += length;
    }
    Ok(result)
}
