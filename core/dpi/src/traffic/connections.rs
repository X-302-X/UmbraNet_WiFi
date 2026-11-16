//! Изолированная офлайн-модель жизненного цикла клиентских TCP-потоков.
//! Не получает пакеты, не управляет драйвером и не доказывает их подлинность.
use std::collections::BTreeMap;
use std::mem::size_of;

use super::application::Evidence;
use super::stream::{StreamError, TcpPrefix, MAX_PREFIX_BYTES};
use crate::flow::tracker::{FlowKey, Transport};

const MAX_SLOTS: usize = 4096;
/// Ограничивает только память массивов префиксов, не накладные расходы таблицы.
const MAX_PREFIX_MEMORY: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    max_slots: usize,
    prefix_limit: usize,
    idle_timeout: u64,
    lifetime: u64,
    quarantine: u64,
}

impl Config {
    /// Временные интервалы и времена событий — монотонные единицы одного источника.
    pub fn new(
        max_slots: usize,
        prefix_limit: usize,
        idle_timeout: u64,
        lifetime: u64,
        quarantine: u64,
    ) -> Result<Self, Error> {
        let memory = max_slots
            .checked_mul(prefix_limit)
            .and_then(|n| n.checked_mul(size_of::<Option<u8>>()));
        if max_slots == 0
            || max_slots > MAX_SLOTS
            || prefix_limit == 0
            || prefix_limit > MAX_PREFIX_BYTES
            || memory.is_none_or(|n| n > MAX_PREFIX_MEMORY)
            || idle_timeout == 0
            || lifetime == 0
            || quarantine == 0
        {
            return Err(Error::InvalidConfig);
        }
        Ok(Self {
            max_slots,
            prefix_limit,
            idle_timeout,
            lifetime,
            quarantine,
        })
    }
}

/// Маркер экземпляра, а не доказательство того, что пакет относится к нему.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidConfig,
    InvalidProtocol,
    Unavailable,
    ClockWentBackwards,
    Capacity,
    KeyBusy,
    NotFound,
    StaleToken,
    WrongState,
    InvalidHandshake,
    Prefix(StreamError),
    TokenExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    AwaitingSynAck,
    AwaitingClientAck(u32),
    Established,
}

struct Active {
    token: Token,
    client_isn: u32,
    phase: Phase,
    prefix: TcpPrefix,
    created: u64,
    last_activity: u64,
}

enum Slot {
    Active(Active),
    Quarantined { since: u64 },
}

/// Один поток на ключ; закрытые ключи временно занимают слоты в карантине.
/// Эта модель не способна сама доказать корректность/порядок событий из сети.
pub struct Connections {
    config: Config,
    slots: BTreeMap<FlowKey, Slot>,
    last_time: Option<u64>,
    next_token: u64,
    unavailable: bool,
}

impl Connections {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            slots: BTreeMap::new(),
            last_time: None,
            next_token: 1,
            unavailable: false,
        }
    }

    fn advance(&mut self, now: u64) -> Result<(), Error> {
        if self.unavailable {
            return Err(Error::Unavailable);
        }
        if self.last_time.is_some_and(|last| now < last) {
            self.invalidate();
            return Err(Error::ClockWentBackwards);
        }
        self.last_time = Some(now);
        let cfg = self.config;
        self.slots.retain(|_, slot| match slot {
            Slot::Active(a)
                if now - a.created >= cfg.lifetime || now - a.last_activity >= cfg.idle_timeout =>
            {
                *slot = Slot::Quarantined { since: now };
                true
            }
            Slot::Quarantined { since } => now - *since < cfg.quarantine,
            _ => true,
        });
        Ok(())
    }

    /// Вызывается после наблюдения исходящего SYN без ACK на новом ключе.
    /// Ключ ориентирован как local/remote; направление проверяет вызывающий код.
    /// Повторный open по активному ключу неоднозначен и отправляет его в карантин,
    /// даже если это был безобидный повтор SYN.
    pub fn open(&mut self, key: FlowKey, client_isn: u32, now: u64) -> Result<Token, Error> {
        self.advance(now)?;
        if key.protocol() != Transport::Tcp {
            return Err(Error::InvalidProtocol);
        }
        if let Some(slot) = self.slots.get_mut(&key) {
            if matches!(slot, Slot::Active(_)) {
                *slot = Slot::Quarantined { since: now };
            }
            return Err(Error::KeyBusy);
        }
        if self.slots.len() >= self.config.max_slots {
            return Err(Error::Capacity);
        }
        let next = self.next_token.checked_add(1).ok_or_else(|| {
            self.invalidate();
            Error::TokenExhausted
        })?;
        let token = Token(self.next_token);
        self.next_token = next;
        let prefix = TcpPrefix::new(client_isn, self.config.prefix_limit).map_err(Error::Prefix)?;
        self.slots.insert(
            key,
            Slot::Active(Active {
                token,
                client_isn,
                phase: Phase::AwaitingSynAck,
                prefix,
                created: now,
                last_activity: now,
            }),
        );
        Ok(token)
    }

    fn active(&mut self, key: &FlowKey, token: Token) -> Result<&mut Active, Error> {
        match self.slots.get_mut(key) {
            Some(Slot::Active(a)) if a.token == token => Ok(a),
            Some(Slot::Active(_)) => Err(Error::StaleToken),
            _ => Err(Error::NotFound),
        }
    }

    /// Только входящий SYN+ACK с подтверждением исходящего SYN.
    pub fn syn_ack(
        &mut self,
        key: &FlowKey,
        token: Token,
        server_isn: u32,
        ack: u32,
        now: u64,
    ) -> Result<(), Error> {
        self.advance(now)?;
        let a = self.active(key, token)?;
        let valid = ack == a.client_isn.wrapping_add(1)
            && matches!(a.phase, Phase::AwaitingSynAck | Phase::AwaitingClientAck(_))
            && match a.phase {
                Phase::AwaitingClientAck(old) => old == server_isn,
                _ => true,
            };
        if !valid {
            self.retire(key, now);
            return Err(Error::InvalidHandshake);
        }
        a.phase = Phase::AwaitingClientAck(server_isn);
        a.last_activity = now;
        Ok(())
    }

    /// Только исходящий ACK без payload в ответ на наблюдавшийся SYN+ACK.
    pub fn client_ack(
        &mut self,
        key: &FlowKey,
        token: Token,
        seq: u32,
        ack: u32,
        now: u64,
    ) -> Result<(), Error> {
        self.advance(now)?;
        let a = self.active(key, token)?;
        let valid = match a.phase {
            Phase::AwaitingClientAck(server_isn) => {
                seq == a.client_isn.wrapping_add(1) && ack == server_isn.wrapping_add(1)
            }
            _ => false,
        };
        if !valid {
            self.retire(key, now);
            return Err(Error::InvalidHandshake);
        }
        a.phase = Phase::Established;
        a.last_activity = now;
        Ok(())
    }

    /// Только исходящие данные после модели handshake; sequence — первого байта.
    pub fn payload(
        &mut self,
        key: &FlowKey,
        token: Token,
        seq: u32,
        data: &[u8],
        now: u64,
    ) -> Result<(), Error> {
        self.advance(now)?;
        let a = self.active(key, token)?;
        if a.phase != Phase::Established {
            if !data.is_empty() {
                self.retire(key, now);
            }
            return Err(Error::WrongState);
        }
        if let Err(e) = a.prefix.insert(seq, data) {
            self.retire(key, now);
            return Err(Error::Prefix(e));
        }
        if !data.is_empty() {
            a.last_activity = now;
        }
        Ok(())
    }

    pub fn evidence(&mut self, key: &FlowKey, token: Token, now: u64) -> Result<Evidence, Error> {
        self.advance(now)?;
        let a = self.active(key, token)?;
        if a.phase != Phase::Established {
            return Err(Error::WrongState);
        }
        a.prefix.evidence().map_err(Error::Prefix)
    }

    /// FIN или RST любой стороны завершает наблюдение немедленно; полузакрытое
    /// соединение не поддерживается. Валидность флагов/sequence проверяет вызывающий код.
    pub fn close(&mut self, key: &FlowKey, token: Token, now: u64) -> Result<(), Error> {
        self.advance(now)?;
        self.active(key, token)?;
        self.retire(key, now);
        Ok(())
    }

    fn retire(&mut self, key: &FlowKey, now: u64) {
        self.slots
            .insert(key.clone(), Slot::Quarantined { since: now });
    }

    /// Позволяет проводить очистку даже при отсутствии новых сетевых событий.
    pub fn sweep(&mut self, now: u64) -> Result<(), Error> {
        self.advance(now)
    }

    /// При потере событий или ненадёжном источнике все данные отбрасываются.
    pub fn invalidate(&mut self) {
        self.slots.clear();
        self.unavailable = true;
    }

    /// Только при начале новой сессии наблюдения; номера token не переиспользуются.
    pub fn reset(&mut self) {
        self.slots.clear();
        self.last_time = None;
        self.unavailable = false;
    }

    /// Включает активные и находящиеся в карантине ключи.
    pub fn slots_used(&self) -> usize {
        self.slots.len()
    }
    pub fn is_available(&self) -> bool {
        !self.unavailable
    }
}
