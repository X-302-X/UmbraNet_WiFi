//! Офлайн-сборка начального участка одного направления TCP.
//! Не открывает сеть и не принимает решений о модификации пакетов.
use super::application::{inspect_tcp, Evidence};

/// Предел на один буфер; вызывающий код обязан отдельно ограничивать число потоков
/// и время их жизни. Этот тип не отслеживает соединения и не проверяет TCP handshake.
pub const MAX_PREFIX_BYTES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamError {
    InvalidLimit,
    OutsideWindow,
    ConflictingOverlap,
    Poisoned,
}

/// Начальный участок в направлении клиента. `syn_sequence` должен поступать из
/// проверенного SYN именно этого соединения, а не угадываться по первому payload.
/// Экземпляр нельзя переиспользовать для другого соединения или направления.
pub struct TcpPrefix {
    first_sequence: u32,
    bytes: Vec<Option<u8>>,
    contiguous: usize,
    poisoned: bool,
}

impl TcpPrefix {
    pub fn new(syn_sequence: u32, limit: usize) -> Result<Self, StreamError> {
        if limit == 0 || limit > MAX_PREFIX_BYTES {
            return Err(StreamError::InvalidLimit);
        }
        Ok(Self {
            first_sequence: syn_sequence.wrapping_add(1),
            bytes: vec![None; limit],
            contiguous: 0,
            poisoned: false,
        })
    }

    /// Принимает TCP sequence первого байта payload (с учётом SYN, если он есть).
    /// Повтор идентичных байтов допустим. Любая неоднозначность закрывает буфер.
    /// Вставки проверяются целиком до записи, так что частичного добавления нет.
    pub fn insert(&mut self, sequence: u32, payload: &[u8]) -> Result<(), StreamError> {
        if self.poisoned {
            return Err(StreamError::Poisoned);
        }
        if payload.is_empty() {
            return Ok(());
        }
        let offset = sequence.wrapping_sub(self.first_sequence) as usize;
        let end = offset.checked_add(payload.len());
        let end = match end {
            Some(end) if end <= self.bytes.len() => end,
            _ => {
                self.poisoned = true;
                return Err(StreamError::OutsideWindow);
            }
        };
        for (existing, incoming) in self.bytes[offset..end].iter().zip(payload) {
            if existing.is_some_and(|byte| byte != *incoming) {
                self.poisoned = true;
                return Err(StreamError::ConflictingOverlap);
            }
        }
        for (slot, byte) in self.bytes[offset..end].iter_mut().zip(payload) {
            *slot = Some(*byte);
        }
        while self.contiguous < self.bytes.len() && self.bytes[self.contiguous].is_some() {
            self.contiguous += 1;
        }
        Ok(())
    }

    /// Возвращает только непрерывные байты с начала потока.
    /// При конфликте либо выходе за границы предыдущий результат отзывается.
    pub fn prefix(&self) -> Result<Vec<u8>, StreamError> {
        if self.poisoned {
            return Err(StreamError::Poisoned);
        }
        Ok(self.bytes[..self.contiguous]
            .iter()
            .map(|b| b.expect("contiguous prefix contains no gaps"))
            .collect())
    }

    /// Предварительный признак, не доказательство доставки или принадлежности процесса.
    /// Сборка TLS handshake через несколько TLS records пока не поддерживается.
    pub fn evidence(&self) -> Result<Evidence, StreamError> {
        Ok(inspect_tcp(&self.prefix()?, true))
    }
}
