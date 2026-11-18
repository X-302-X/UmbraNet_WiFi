//! Офлайн-модель управления запуском. Не владеет ресурсами и не подключена к Tauri.
//! Вызывающий код обязан выполнять переходы и освобождать ресурсы в указанном порядке.
//! Ticket уникален только в рамках одного экземпляра Lifecycle; не заменяйте
//! экземпляр, пока могут прийти старые callbacks или остаться старые ресурсы.
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ticket(u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Starting,
    Cancelling,
    Running,
    Stopping,
    Faulted,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Busy,
    Faulted,
    Stale,
    WrongPhase,
    Exhausted,
    Poisoned,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartOutcome {
    RunningInModel,
    CleanupRequired,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopOutcome {
    AlreadyIdle,
    WaitingForStart,
    CleanupRequired(Ticket),
    WaitingForCleanup,
    Faulted,
}

#[derive(Debug, Clone, Copy)]
enum State {
    Idle,
    Starting(Ticket),
    Cancelling(Ticket),
    Running(Ticket),
    Stopping(Ticket),
    Faulted,
}
struct Inner {
    state: State,
    next: u64,
}
fn mismatch(state: State, ticket: Ticket) -> Error {
    match state {
        State::Starting(t) | State::Cancelling(t) | State::Running(t) | State::Stopping(t)
            if t != ticket =>
        {
            Error::Stale
        }
        _ => Error::WrongPhase,
    }
}

/// Все операции атомарны относительно других операций этой модели.
/// Модель не управляет WinDivert, потоками, их уничтожением или фактической передачей данных.
pub struct Lifecycle(Mutex<Inner>);
impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}
impl Lifecycle {
    pub fn new() -> Self {
        Self(Mutex::new(Inner {
            state: State::Idle,
            next: 1,
        }))
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner>, Error> {
        self.0.lock().map_err(|_| Error::Poisoned)
    }
    pub fn phase(&self) -> Result<Phase, Error> {
        Ok(match self.lock()?.state {
            State::Idle => Phase::Idle,
            State::Starting(_) => Phase::Starting,
            State::Cancelling(_) => Phase::Cancelling,
            State::Running(_) => Phase::Running,
            State::Stopping(_) => Phase::Stopping,
            State::Faulted => Phase::Faulted,
        })
    }
    /// Бронирует единственную попытку до открытия любых ресурсов.
    pub fn begin_start(&self) -> Result<Ticket, Error> {
        let mut inner = self.lock()?;
        match inner.state {
            State::Idle => {}
            State::Faulted => return Err(Error::Faulted),
            _ => return Err(Error::Busy),
        }
        let Some(next) = inner.next.checked_add(1) else {
            inner.state = State::Faulted;
            return Err(Error::Exhausted);
        };
        let ticket = Ticket(inner.next);
        inner.next = next;
        inner.state = State::Starting(ticket);
        Ok(ticket)
    }
    /// Только переход модели после подготовки; НЕ публикует ресурсы и не запускает worker.
    /// Будущая интеграция должна атомарно связать этот переход с передачей владения
    /// ресурсами и запуском worker, иначе возможна гонка с остановкой.
    /// При CleanupRequired ресурсы нельзя публиковать; требуется cleanup_complete.
    pub fn complete_start(&self, ticket: Ticket) -> Result<StartOutcome, Error> {
        let mut inner = self.lock()?;
        match inner.state {
            State::Starting(t) if t == ticket => {
                inner.state = State::Running(t);
                Ok(StartOutcome::RunningInModel)
            }
            State::Cancelling(t) if t == ticket => {
                inner.state = State::Stopping(t);
                Ok(StartOutcome::CleanupRequired)
            }
            state => Err(mismatch(state, ticket)),
        }
    }
    /// Ошибка подготовки: true только если ВСЕ ресурсы попытки уже освобождены.
    /// Если их состояние неизвестно, передать false: повторный запуск блокируется.
    pub fn start_failed(&self, ticket: Ticket, cleanup_confirmed: bool) -> Result<(), Error> {
        let mut inner = self.lock()?;
        match inner.state {
            State::Starting(t) | State::Cancelling(t) if t == ticket => {
                inner.state = if cleanup_confirmed {
                    State::Idle
                } else {
                    State::Faulted
                };
                Ok(())
            }
            state => Err(mismatch(state, ticket)),
        }
    }
    pub fn request_stop(&self) -> Result<StopOutcome, Error> {
        let mut inner = self.lock()?;
        Ok(match inner.state {
            State::Idle => StopOutcome::AlreadyIdle,
            State::Starting(t) => {
                inner.state = State::Cancelling(t);
                StopOutcome::WaitingForStart
            }
            State::Cancelling(_) => StopOutcome::WaitingForStart,
            State::Running(t) => {
                inner.state = State::Stopping(t);
                StopOutcome::CleanupRequired(t)
            }
            State::Stopping(_) => StopOutcome::WaitingForCleanup,
            State::Faulted => StopOutcome::Faulted,
        })
    }
    /// Вызывается при завершении worker; ресурсы ещё надо освободить.
    pub fn worker_exited(&self, ticket: Ticket) -> Result<StopOutcome, Error> {
        let mut inner = self.lock()?;
        match inner.state {
            State::Running(t) if t == ticket => {
                inner.state = State::Stopping(t);
                Ok(StopOutcome::CleanupRequired(t))
            }
            State::Stopping(t) if t == ticket => Ok(StopOutcome::WaitingForCleanup),
            state => Err(mismatch(state, ticket)),
        }
    }
    /// Завершающий владелец подтверждает shutdown, join и освобождение ВСЕХ ресурсов.
    /// Неуспех/неизвестное состояние блокирует последующие попытки.
    pub fn cleanup_complete(&self, ticket: Ticket, cleanup_confirmed: bool) -> Result<(), Error> {
        let mut inner = self.lock()?;
        match inner.state {
            State::Stopping(t) if t == ticket => {
                inner.state = if cleanup_confirmed {
                    State::Idle
                } else {
                    State::Faulted
                };
                Ok(())
            }
            state => Err(mismatch(state, ticket)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exhausted_generation_latches_fault() {
        let c = Lifecycle::new();
        c.0.lock().unwrap().next = u64::MAX;
        assert_eq!(c.begin_start(), Err(Error::Exhausted));
        assert_eq!(c.phase(), Ok(Phase::Faulted));
        assert_eq!(c.begin_start(), Err(Error::Faulted));
    }
    #[test]
    fn poisoned_mutex_fails_closed() {
        let c = std::sync::Arc::new(Lifecycle::new());
        let other = c.clone();
        let _ = std::thread::spawn(move || {
            let _guard = other.0.lock().unwrap();
            panic!("test poison");
        })
        .join();
        assert_eq!(c.begin_start(), Err(Error::Poisoned));
        assert_eq!(c.request_stop(), Err(Error::Poisoned));
    }
}
