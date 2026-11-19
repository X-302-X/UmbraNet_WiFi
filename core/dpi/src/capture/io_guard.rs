//! Синхронизация реальных операций с handle. Close не пересекается с I/O.
use std::{io, sync::Mutex};

#[derive(Default)]
struct State {
    in_flight: usize,
    close_attempted: bool,
}
#[derive(Default)]
pub(super) struct HandleIo(Mutex<State>);
pub(super) struct Operation<'a>(&'a HandleIo);
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        let mut state = self.0 .0.lock().unwrap_or_else(|p| p.into_inner());
        state.in_flight -= 1;
    }
}
impl HandleIo {
    pub(super) fn begin(&self) -> io::Result<Operation<'_>> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("Состояние WinDivert недоступно"))?;
        if state.close_attempted {
            return Err(io::Error::other("WinDivert уже закрывается или закрыт"));
        }
        state.in_flight = state
            .in_flight
            .checked_add(1)
            .ok_or_else(|| io::Error::other("Слишком много операций WinDivert"))?;
        drop(state);
        Ok(Operation(self))
    }
    /// При ошибке ОС результат остаётся неизвестным; автоматического повтора нет.
    pub(super) fn close_checked(&self, close: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        {
            let mut state = self
                .0
                .lock()
                .map_err(|_| io::Error::other("Состояние WinDivert недоступно"))?;
            if state.close_attempted {
                return Err(io::Error::other("Закрытие WinDivert уже запрашивалось"));
            }
            if state.in_flight != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Операции WinDivert ещё выполняются",
                ));
            }
            state.close_attempted = true;
        }
        close()
    }
    /// Последняя страховка только для Drop, не считается подтверждённым закрытием.
    pub(super) fn close_on_drop(&mut self, close: impl FnOnce()) {
        let state = self.0.get_mut().unwrap_or_else(|p| p.into_inner());
        if !state.close_attempted {
            state.close_attempted = true;
            close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Barrier,
    };
    use std::thread;
    #[test]
    fn close_is_blocked_during_io_and_disallows_new_io() {
        let gate = Arc::new(HandleIo::default());
        let start = Arc::new(Barrier::new(2));
        let end = Arc::new(Barrier::new(2));
        let (g, a, b) = (gate.clone(), start.clone(), end.clone());
        let thread = thread::spawn(move || {
            let _op = g.begin().unwrap();
            a.wait();
            b.wait();
        });
        start.wait();
        assert_eq!(
            gate.close_checked(|| panic!("must not close"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        end.wait();
        thread.join().unwrap();
        gate.close_checked(|| Ok(())).unwrap();
        assert!(gate.begin().is_err());
        assert!(gate.close_checked(|| panic!("second close")).is_err());
    }
    #[test]
    fn failed_close_is_not_retried_even_by_drop_fallback() {
        let calls = AtomicUsize::new(0);
        let mut gate = HandleIo::default();
        assert!(gate
            .close_checked(|| {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::other("failed"))
            })
            .is_err());
        assert!(gate.begin().is_err());
        gate.close_on_drop(|| {
            calls.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn drop_fallback_calls_once_when_no_checked_close() {
        let mut gate = HandleIo::default();
        let mut calls = 0;
        gate.close_on_drop(|| calls += 1);
        gate.close_on_drop(|| calls += 1);
        assert_eq!(calls, 1);
    }
}
