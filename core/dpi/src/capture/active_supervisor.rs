//! Координация единственного владельца cleanup активного канала.
//! Не открывает WinDivert, не трогает общую службу и не доказывает доставку.
use super::active_stop::{ActiveChannel, Outcome, Worker};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultReport {
    pub owned_closed: bool,
    pub after_failed_user_shutdown: bool,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopClaim {
    User,
    Worker,
    AlreadyClaimed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Owner {
    Free,
    UserPending,
    UserCommitted,
    Worker,
}
struct State {
    owner: Owner,
    failed_user_shutdown: bool,
    report: Option<FaultReport>,
}

pub struct Supervisor {
    state: Mutex<State>,
    changed: Condvar,
}
impl Default for Supervisor {
    fn default() -> Self {
        Self::new()
    }
}
impl Supervisor {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                owner: Owner::Free,
                failed_user_shutdown: false,
                report: None,
            }),
            changed: Condvar::new(),
        }
    }
    /// Единственный победитель становится владельцем остановки; нельзя вызывать дважды.
    pub fn reserve_user_stop(&self) -> StopClaim {
        let Ok(mut state) = self.state.lock() else {
            return StopClaim::AlreadyClaimed;
        };
        match state.owner {
            Owner::Free => {
                state.owner = Owner::UserPending;
                StopClaim::User
            }
            Owner::Worker => StopClaim::Worker,
            Owner::UserPending | Owner::UserCommitted => StopClaim::AlreadyClaimed,
        }
    }

    /// Вызывается после выхода worker из цикла. Пока Stop не завершил shutdown,
    /// worker ждёт его результата: при успехе cleanup принадлежит Stop, при
    /// ошибке передаётся worker. При зависшем shutdown оба остаются busy.
    pub fn finish_worker(
        &self,
        channel: &impl ActiveChannel,
        stop: &AtomicBool,
        result: &Result<(), String>,
        notify_recovery: impl FnOnce(),
    ) -> Option<FaultReport> {
        let mut state = self.state.lock().ok()?;
        while state.owner == Owner::UserPending {
            state = self.changed.wait(state).ok()?;
        }
        if state.owner != Owner::Free {
            return None;
        }
        state.owner = Owner::Worker;
        let after_failed_user_shutdown = state.failed_user_shutdown;
        drop(state);
        stop.store(true, Ordering::Release);
        let _ = catch_unwind(AssertUnwindSafe(notify_recovery));
        let cause = match result {
            Ok(()) => "Рабочий поток DPI завершился неожиданно".to_string(),
            Err(error) => format!("Рабочий поток DPI завершился с ошибкой: {error}"),
        };
        // После неудачного Shutdown повторять вызов с неизвестным результатом
        // не нужно: рабочий цикл уже вышел, далее только проверенный close.
        let shutdown = if after_failed_user_shutdown {
            None
        } else {
            Some(catch_unwind(AssertUnwindSafe(|| channel.shutdown_recv())))
        };
        let close = catch_unwind(AssertUnwindSafe(|| channel.close_checked()));
        let (owned_closed, close_text) = match close {
            Ok(Ok(())) => (
                true,
                "Собственный канал закрыт; пакеты, оставшиеся в очереди, могли быть потеряны"
                    .to_string(),
            ),
            Ok(Err(e)) => (
                false,
                format!("Закрытие собственного канала не подтверждено: {e}"),
            ),
            Err(_) => (
                false,
                "Закрытие собственного канала не подтверждено: panic".to_string(),
            ),
        };
        let shutdown_text = match shutdown {
            None => Some("предыдущий Shutdown не подтверждён, повтор не выполнялся".to_string()),
            Some(Ok(Ok(()))) => None,
            Some(Ok(Err(e))) => Some(format!("ошибка остановки приёма: {e}")),
            Some(Err(_)) => Some("ошибка остановки приёма: panic".to_string()),
        };
        let report = FaultReport {
            owned_closed,
            after_failed_user_shutdown,
            message: format!(
                "{cause}; {}{close_text}; общая служба WinDivert автоматически не останавливалась",
                shutdown_text.map(|s| format!("{s}; ")).unwrap_or_default()
            ),
        };
        if let Ok(mut state) = self.state.lock() {
            state.report = Some(report.clone());
        }
        Some(report)
    }

    /// При ошибке Shutdown возвращает worker владельцу и освобождает право
    /// аварийного cleanup; ещё выполняющий I/O worker не закрываем извне.
    pub fn stop(
        &self,
        claim: StopClaim,
        channel: &impl ActiveChannel,
        flag: &AtomicBool,
        worker: Worker,
    ) -> Outcome {
        match claim {
            StopClaim::AlreadyClaimed => {
                return Outcome::ShutdownFailed {
                    worker,
                    error: "Остановка канала уже выполняется".into(),
                }
            }
            StopClaim::User => {
                flag.store(true, Ordering::Release);
                let shutdown = catch_unwind(AssertUnwindSafe(|| channel.shutdown_recv()));
                let failure = match shutdown {
                    Ok(Ok(())) => None,
                    Ok(Err(e)) => Some(format!("Не удалось остановить приём WinDivert: {e}")),
                    Err(_) => Some("Не удалось остановить приём WinDivert: panic".into()),
                };
                let Ok(mut state) = self.state.lock() else {
                    return Outcome::ShutdownFailed {
                        worker,
                        error: "Состояние остановки DPI недоступно после shutdown".into(),
                    };
                };
                if state.owner != Owner::UserPending {
                    return Outcome::ShutdownFailed {
                        worker,
                        error: "Владелец остановки DPI изменился неожиданно".into(),
                    };
                }
                state.owner = if failure.is_some() {
                    Owner::Free
                } else {
                    Owner::UserCommitted
                };
                if failure.is_some() {
                    state.failed_user_shutdown = true;
                }
                self.changed.notify_all();
                drop(state);
                if let Some(error) = failure {
                    return Outcome::ShutdownFailed { worker, error };
                }
                let worker_error = match worker.join() {
                    Ok(Ok(())) => None,
                    Ok(Err(e)) => Some(format!("Ошибка потока DPI: {e}")),
                    Err(_) => Some("Ошибка потока DPI (panic)".to_string()),
                };
                return match channel.close_checked() {
                    Ok(()) => Outcome::Closed { worker_error },
                    Err(error) => Outcome::CloseFailed {
                        error: format!(
                            "Не удалось подтвердить закрытие WinDivert: {error}{}",
                            worker_error.map(|s| format!("; {s}")).unwrap_or_default()
                        ),
                    },
                };
            }
            StopClaim::Worker => {}
        }
        flag.store(true, Ordering::Release);
        let result = worker.join();
        let report = self
            .state
            .lock()
            .ok()
            .and_then(|state| state.report.clone())
            .map(|mut report| {
                if result.is_err() {
                    report
                        .message
                        .push_str("; panic рабочего потока после автоочистки");
                }
                report
            });
        match report {
            Some(report) if report.owned_closed => Outcome::Closed {
                worker_error: Some(report.message),
            },
            Some(report) => Outcome::CloseFailed {
                error: report.message,
            },
            None => Outcome::CloseFailed {
                error: format!(
                    "Автоматическая очистка DPI не подтверждена{}",
                    if result.is_err() {
                        ": panic потока"
                    } else {
                        ""
                    }
                ),
            },
        }
    }
}
