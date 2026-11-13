//! Консервативная модель сопоставления пятёрки соединения с процессом.
//! Результат — только кандидат: асинхронные события не доказывают принадлежность пакета.
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FlowKey {
    local: SocketAddr,
    remote: SocketAddr,
    protocol: Transport,
}

impl FlowKey {
    /// Адреса передаются уже ориентированными: локальная и удалённая сторона.
    /// Неоднозначные адреса и IPv6 с зоной не применяются для сопоставления.
    pub fn new(local: SocketAddr, remote: SocketAddr, protocol: Transport) -> Option<Self> {
        fn normalize(addr: SocketAddr) -> Option<SocketAddr> {
            if addr.port() == 0 {
                return None;
            }
            let ip = match addr {
                SocketAddr::V6(v6) if v6.scope_id() != 0 => return None,
                SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
                    Some(ip) => IpAddr::V4(ip),
                    None => IpAddr::V6(*v6.ip()),
                },
                SocketAddr::V4(v4) => IpAddr::V4(*v4.ip()),
            };
            if ip.is_unspecified() || ip.is_multicast() {
                return None;
            }
            if let IpAddr::V6(v6) = ip {
                if v6.segments()[0] & 0xffc0 == 0xfe80 {
                    return None;
                }
            }
            Some(SocketAddr::new(ip, addr.port()))
        }
        Some(Self {
            local: normalize(local)?,
            remote: normalize(remote)?,
            protocol,
        })
    }
}

/// Идентификатор создания берётся из независимой проверки ОС, не только из PID.
/// Создание этого объекта не выполняет настоящую проверку Windows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    pid: u32,
    creation_id: u64,
    image_name: String,
}
impl ProcessIdentity {
    pub fn new(pid: u32, creation_id: u64, image_name: &str) -> Option<Self> {
        let name = image_name.trim().to_ascii_lowercase();
        if pid == 0
            || creation_id == 0
            || name.len() <= 4
            || name.len() > 255
            || !name.ends_with(".exe")
            || name.starts_with('.')
            || name
                .bytes()
                .any(|b| b < 32 || b == 127 || b"\\/:*?\"<>|".contains(&b))
        {
            return None;
        }
        Some(Self {
            pid,
            creation_id,
            image_name: name,
        })
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn creation_id(&self) -> u64 {
        self.creation_id
    }
    pub fn image_name(&self) -> &str {
        &self.image_name
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Candidate {
    /// Это предварительное совпадение, а не подтверждённый владелец пакета.
    Tentative(ProcessIdentity),
    Unknown,
    Ambiguous,
    Stale,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackerError {
    OutOfOrder,
    Capacity,
    EndpointConflict,
    UnknownClose,
}

#[derive(Debug, Clone)]
struct Entry {
    process: ProcessIdentity,
    observed_at: u64,
}

/// Времена — монотонные единицы одного источника, не смешиваемые со временем Windows.
/// Ошибки порядка или потери событий отключают выдачу кандидатов до явного сброса.
pub struct FlowTracker {
    entries: BTreeMap<FlowKey, BTreeMap<u64, Entry>>,
    endpoints: BTreeMap<u64, FlowKey>,
    last_event: Option<u64>,
    max_entries: usize,
    max_age: u64,
    unavailable: bool,
}

impl FlowTracker {
    pub fn new(max_entries: usize, max_age: u64) -> Self {
        Self {
            entries: BTreeMap::new(),
            endpoints: BTreeMap::new(),
            last_event: None,
            max_entries,
            max_age,
            unavailable: false,
        }
    }
    fn advance(&mut self, at: u64) -> Result<(), TrackerError> {
        if self.last_event.is_some_and(|last| at < last) {
            self.unavailable = true;
            return Err(TrackerError::OutOfOrder);
        }
        self.last_event = Some(at);
        Ok(())
    }
    /// События должны поступать из одного упорядоченного источника после открытия handle.
    pub fn established(
        &mut self,
        key: FlowKey,
        endpoint: u64,
        process: ProcessIdentity,
        at: u64,
    ) -> Result<(), TrackerError> {
        self.advance(at)?;
        if endpoint == 0 {
            self.unavailable = true;
            return Err(TrackerError::EndpointConflict);
        }
        if let Some(existing_key) = self.endpoints.get(&endpoint) {
            let existing = self
                .entries
                .get(existing_key)
                .and_then(|v| v.get(&endpoint));
            if existing_key == &key && existing.is_some_and(|e| e.process == process) {
                return Ok(());
            }
            self.unavailable = true;
            return Err(TrackerError::EndpointConflict);
        }
        if self.endpoints.len() >= self.max_entries {
            self.unavailable = true;
            return Err(TrackerError::Capacity);
        }
        self.entries.entry(key.clone()).or_default().insert(
            endpoint,
            Entry {
                process,
                observed_at: at,
            },
        );
        self.endpoints.insert(endpoint, key);
        Ok(())
    }
    pub fn closed(&mut self, key: &FlowKey, endpoint: u64, at: u64) -> Result<(), TrackerError> {
        self.advance(at)?;
        if self.endpoints.get(&endpoint) != Some(key) {
            self.unavailable = true;
            return Err(TrackerError::UnknownClose);
        }
        self.endpoints.remove(&endpoint);
        if let Some(group) = self.entries.get_mut(key) {
            group.remove(&endpoint);
            if group.is_empty() {
                self.entries.remove(key);
            }
        }
        Ok(())
    }
    pub fn candidate(&self, key: &FlowKey, now: u64) -> Candidate {
        if self.unavailable {
            return Candidate::Unavailable;
        }
        if self.last_event.is_some_and(|last| now < last) {
            return Candidate::Stale;
        }
        let Some(group) = self.entries.get(key) else {
            return Candidate::Unknown;
        };
        if group
            .values()
            .any(|e| now < e.observed_at || now - e.observed_at > self.max_age)
        {
            return Candidate::Stale;
        }
        // Даже совпадающий PID не устраняет неоднозначность разных endpoint.
        if group.len() != 1 {
            return Candidate::Ambiguous;
        }
        Candidate::Tentative(group.values().next().expect("один элемент").process.clone())
    }
    /// При известной потере событий все прежние сопоставления становятся недостоверны.
    pub fn invalidate(&mut self) {
        self.unavailable = true;
    }

    /// Сброс допускается только на границе новой диагностической сессии.
    pub fn reset(&mut self) {
        self.entries.clear();
        self.endpoints.clear();
        self.last_event = None;
        self.unavailable = false;
    }
    pub fn is_available(&self) -> bool {
        !self.unavailable
    }
    pub fn len(&self) -> usize {
        self.endpoints.len()
    }
    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }
}

/// Сверка PID и времени создания проверяет жизнь процесса, но не делает кандидат
/// доказанным владельцем пакета: гонки и пропущенные события остаются возможны.
pub fn same_process(candidate: &ProcessIdentity, current: &ProcessIdentity) -> bool {
    candidate.pid == current.pid
        && candidate.creation_id == current.creation_id
        && candidate.image_name == current.image_name
}
