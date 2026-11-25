//! Строгий разбор исходной Uz1 без выполнения аргументов и без выбора правил.
//! Секции и повторные fake-файлы сохраняются по порядку. Пересекающиеся
//! секции не разрешаются автоматически: семантика e1-spike ещё не подтверждена.
use crate::strategy::LegacyUz1;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asset {
    GoogleTls,
    MaxTls,
    Stun,
    GoogleQuic,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub protocol: Protocol,
    pub ports: Vec<u16>,
    pub selected_hostlist: bool,
    pub ip_id_zero: bool,
    pub fake: bool,
    pub multisplit: bool,
    pub seq_overlap: Option<usize>,
    pub split_pos: Option<usize>,
    pub fooling_ts: bool,
    pub repeats: u8,
    pub overlap_pattern: Option<Asset>,
    pub fake_tls: Vec<Asset>,
    pub fake_http: Vec<Asset>,
    pub fake_quic: Vec<Asset>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uz1Plan {
    pub capture_tcp_ports: Vec<u16>,
    pub capture_udp_ports: Vec<u16>,
    pub sections: Vec<Section>,
}

fn ports(value: &str) -> Result<Vec<u16>, String> {
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for p in value.split(',') {
        let port = p.parse::<u16>().map_err(|_| "Некорректный порт Uz1")?;
        if port == 0 || !seen.insert(port) || result.len() >= 64 {
            return Err("Некорректный список портов Uz1".into());
        }
        result.push(port);
    }
    Ok(result)
}
fn asset(value: &str) -> Result<Asset, String> {
    match value {
        "{bin}\\tls_clienthello_www_google_com.bin" => Ok(Asset::GoogleTls),
        "{bin}\\tls_clienthello_max_ru.bin" => Ok(Asset::MaxTls),
        "{bin}\\stun.bin" => Ok(Asset::Stun),
        "{bin}\\quic_initial_www_google_com.bin" => Ok(Asset::GoogleQuic),
        _ => Err("Неизвестный шаблон Uz1: произвольные пути не разрешены".into()),
    }
}
fn set_once<T>(slot: &mut Option<T>, val: T) -> Result<(), String> {
    if slot.is_some() {
        return Err("Повтор несовместимого параметра Uz1".into());
    }
    *slot = Some(val);
    Ok(())
}
fn number(value: &str) -> Result<usize, String> {
    let n = value
        .parse::<usize>()
        .map_err(|_| "Некорректное число Uz1")?;
    if n == 0 || n > 65535 {
        return Err("Число Uz1 вне диапазона".into());
    }
    Ok(n)
}

struct Builder {
    protocol: Protocol,
    ports: Vec<u16>,
    selected_hostlist: bool,
    ip_id_zero: bool,
    mode: Option<(bool, bool)>,
    seq_overlap: Option<usize>,
    split_pos: Option<usize>,
    fooling_ts: bool,
    repeats: Option<u8>,
    overlap_pattern: Option<Asset>,
    fake_tls: Vec<Asset>,
    fake_http: Vec<Asset>,
    fake_quic: Vec<Asset>,
}
impl Builder {
    fn new(protocol: Protocol, ports: Vec<u16>) -> Self {
        Self {
            protocol,
            ports,
            selected_hostlist: false,
            ip_id_zero: false,
            mode: None,
            seq_overlap: None,
            split_pos: None,
            fooling_ts: false,
            repeats: None,
            overlap_pattern: None,
            fake_tls: vec![],
            fake_http: vec![],
            fake_quic: vec![],
        }
    }
    fn finish(self) -> Result<Section, String> {
        let (fake, multisplit) = self.mode.ok_or("Нет метода Uz1")?;
        let repeats = self.repeats.ok_or("Нет числа повторов Uz1")?;
        if !self.selected_hostlist {
            return Err("Секция Uz1 не ограничена выбранными целями".into());
        }
        match self.protocol {
            Protocol::Tcp
                if fake
                    && multisplit
                    && self.seq_overlap.is_some()
                    && self.split_pos.is_some()
                    && self.fooling_ts
                    && self.overlap_pattern.is_some()
                    && !self.fake_tls.is_empty()
                    && self.fake_quic.is_empty() => {}
            Protocol::Udp
                if fake
                    && !multisplit
                    && self.seq_overlap.is_none()
                    && self.split_pos.is_none()
                    && !self.fooling_ts
                    && !self.ip_id_zero
                    && self.overlap_pattern.is_none()
                    && self.fake_tls.is_empty()
                    && self.fake_http.is_empty()
                    && !self.fake_quic.is_empty() => {}
            _ => return Err("Неподдерживаемая комбинация параметров секции Uz1".into()),
        }
        Ok(Section {
            protocol: self.protocol,
            ports: self.ports,
            selected_hostlist: self.selected_hostlist,
            ip_id_zero: self.ip_id_zero,
            fake,
            multisplit,
            seq_overlap: self.seq_overlap,
            split_pos: self.split_pos,
            fooling_ts: self.fooling_ts,
            repeats,
            overlap_pattern: self.overlap_pattern,
            fake_tls: self.fake_tls,
            fake_http: self.fake_http,
            fake_quic: self.fake_quic,
        })
    }
}

impl Uz1Plan {
    /// Разбирает только известные параметры. Не подключается к сети, не читает
    /// файлы и не выполняет аргументы; неизвестные конструкции отклоняются.
    pub fn parse(profile: &LegacyUz1) -> Result<Self, String> {
        profile.validate()?;
        let mut tcp = None;
        let mut udp = None;
        let mut current: Option<Builder> = None;
        let mut sections = Vec::new();
        let mut after_new = false;
        for arg in &profile.args {
            if let Some(v) = arg.strip_prefix("--wf-tcp=") {
                if current.is_some() || !sections.is_empty() || after_new {
                    return Err("Глобальный параметр после начала секций Uz1".into());
                }
                set_once(&mut tcp, ports(v)?)?;
            } else if let Some(v) = arg.strip_prefix("--wf-udp=") {
                if current.is_some() || !sections.is_empty() || after_new {
                    return Err("Глобальный параметр после начала секций Uz1".into());
                }
                set_once(&mut udp, ports(v)?)?;
            } else if arg == "--new" {
                let prev = current.take().ok_or("Пустая секция Uz1")?;
                sections.push(prev.finish()?);
                if sections.len() >= 16 {
                    return Err("Слишком много секций Uz1".into());
                }
                after_new = true;
            } else if let Some((protocol, v)) = arg
                .strip_prefix("--filter-tcp=")
                .map(|v| (Protocol::Tcp, v))
                .or_else(|| {
                    arg.strip_prefix("--filter-udp=")
                        .map(|v| (Protocol::Udp, v))
                })
            {
                if current.is_some() {
                    return Err("Повторный filter без --new".into());
                }
                current = Some(Builder::new(protocol, ports(v)?));
                after_new = false;
            } else {
                let s = current.as_mut().ok_or("Параметр вне секции Uz1")?;
                if arg == "{hostlist}" {
                    if s.selected_hostlist {
                        return Err("Повтор hostlist Uz1".into());
                    }
                    s.selected_hostlist = true;
                } else if arg == "--ip-id=zero" {
                    if s.ip_id_zero {
                        return Err("Повтор ip-id Uz1".into());
                    }
                    s.ip_id_zero = true;
                } else if let Some(v) = arg.strip_prefix("--dpi-desync=") {
                    let mode = match v {
                        "fake" => (true, false),
                        "fake,multisplit" => (true, true),
                        _ => return Err("Неизвестный режим Uz1".into()),
                    };
                    set_once(&mut s.mode, mode)?;
                } else if let Some(v) = arg.strip_prefix("--dpi-desync-split-seqovl=") {
                    set_once(&mut s.seq_overlap, number(v)?)?;
                } else if let Some(v) = arg.strip_prefix("--dpi-desync-split-pos=") {
                    set_once(&mut s.split_pos, number(v)?)?;
                } else if arg == "--dpi-desync-fooling=ts" {
                    if s.fooling_ts {
                        return Err("Повтор fooling Uz1".into());
                    }
                    s.fooling_ts = true;
                } else if let Some(v) = arg.strip_prefix("--dpi-desync-repeats=") {
                    let n = number(v)?;
                    if n > 32 {
                        return Err("Слишком много повторов Uz1".into());
                    }
                    set_once(&mut s.repeats, n as u8)?;
                } else if let Some(v) = arg.strip_prefix("--dpi-desync-split-seqovl-pattern=") {
                    set_once(&mut s.overlap_pattern, asset(v)?)?;
                } else if let Some(v) = arg.strip_prefix("--dpi-desync-fake-tls=") {
                    s.fake_tls.push(asset(v)?);
                } else if let Some(v) = arg.strip_prefix("--dpi-desync-fake-http=") {
                    s.fake_http.push(asset(v)?);
                } else if let Some(v) = arg.strip_prefix("--dpi-desync-fake-quic=") {
                    s.fake_quic.push(asset(v)?);
                } else {
                    return Err(format!("Неподдерживаемый параметр Uz1: {arg}"));
                }
            }
        }
        if after_new {
            return Err("Пустая последняя секция Uz1".into());
        }
        sections.push(current.ok_or("Нет секций Uz1")?.finish()?);
        let tcp = tcp.ok_or("Нет wf-tcp Uz1")?;
        let udp = udp.ok_or("Нет wf-udp Uz1")?;
        if sections.iter().any(|s| {
            s.ports.iter().any(|p| {
                !match s.protocol {
                    Protocol::Tcp => &tcp,
                    Protocol::Udp => &udp,
                }
                .contains(p)
            })
        }) {
            return Err("Фильтр секции Uz1 выходит за область capture".into());
        }
        Ok(Self {
            capture_tcp_ports: tcp,
            capture_udp_ports: udp,
            sections,
        })
    }

    /// Возвращает все совпадения, ничего не решая о приоритете e1-spike.
    pub fn matching_sections(&self, protocol: Protocol, port: u16) -> Vec<usize> {
        self.sections
            .iter()
            .enumerate()
            .filter_map(|(i, s)| (s.protocol == protocol && s.ports.contains(&port)).then_some(i))
            .collect()
    }
}
