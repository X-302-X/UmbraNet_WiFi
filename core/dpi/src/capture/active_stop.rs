//! Завершение конкретного активного канала и его worker. Вызывать в фоновом
//! потоке: вызовы драйвера и join могут зависнуть; владелец должен оставаться busy.
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

pub trait ActiveChannel {
    fn shutdown_recv(&self) -> io::Result<()>;
    fn close_checked(&self) -> io::Result<()>;
}

pub type Worker = JoinHandle<Result<(), String>>;
pub enum Outcome {
    /// Shutdown не подтверждён. Worker возвращён владельцу и может ещё работать.
    ShutdownFailed { worker: Worker, error: String },
    /// Worker завершился, однако закрытие handle не подтверждено.
    CloseFailed { error: String },
    /// Handle закрыт, но в worker могла возникнуть ошибка обработки/отправки.
    Closed { worker_error: Option<String> },
}

pub fn stop_owned(channel: &impl ActiveChannel, flag: &AtomicBool, worker: Worker) -> Outcome {
    flag.store(true, Ordering::Release);
    if let Err(error) = channel.shutdown_recv() {
        return Outcome::ShutdownFailed {
            worker,
            error: format!("Не удалось остановить приём WinDivert: {error}"),
        };
    }
    let worker_error = match worker.join() {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(format!("Ошибка потока DPI: {error}")),
        Err(_) => Some("Ошибка потока DPI (panic)".to_string()),
    };
    if let Err(error) = channel.close_checked() {
        let suffix = worker_error
            .map(|text| format!("; {text}"))
            .unwrap_or_default();
        return Outcome::CloseFailed {
            error: format!("Не удалось подтвердить закрытие WinDivert: {error}{suffix}"),
        };
    }
    Outcome::Closed { worker_error }
}

#[cfg(all(windows, target_arch = "x86_64"))]
impl ActiveChannel for super::windivert::DivertChannel {
    fn shutdown_recv(&self) -> io::Result<()> {
        self.shutdown()
    }
    fn close_checked(&self) -> io::Result<()> {
        super::windivert::DivertChannel::close_checked(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    struct Fake {
        shutdown_fail: bool,
        close_fail: bool,
        calls: AtomicUsize,
    }
    impl ActiveChannel for Fake {
        fn shutdown_recv(&self) -> io::Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.shutdown_fail {
                Err(io::Error::other("shutdown failure"))
            } else {
                Ok(())
            }
        }
        fn close_checked(&self) -> io::Result<()> {
            self.calls.fetch_add(10, Ordering::SeqCst);
            if self.close_fail {
                Err(io::Error::other("close failure"))
            } else {
                Ok(())
            }
        }
    }
    fn fake(shutdown_fail: bool, close_fail: bool) -> Fake {
        Fake {
            shutdown_fail,
            close_fail,
            calls: AtomicUsize::new(0),
        }
    }
    #[test]
    fn signals_then_joins_and_closes() {
        let flag = Arc::new(AtomicBool::new(false));
        let f = flag.clone();
        let worker = std::thread::spawn(move || {
            while !f.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            Ok(())
        });
        let channel = fake(false, false);
        assert!(matches!(
            stop_owned(&channel, &flag, worker),
            Outcome::Closed { worker_error: None }
        ));
        assert_eq!(channel.calls.load(Ordering::SeqCst), 11);
    }
    #[test]
    fn close_waits_for_worker_exit() {
        struct Delayed {
            shutdown_tx: std::sync::mpsc::Sender<()>,
            closed: AtomicUsize,
        }
        impl ActiveChannel for Delayed {
            fn shutdown_recv(&self) -> io::Result<()> {
                self.shutdown_tx.send(()).unwrap();
                Ok(())
            }
            fn close_checked(&self) -> io::Result<()> {
                self.closed.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }
        let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();
        let (finish_tx, finish_rx) = std::sync::mpsc::channel();
        let channel = Arc::new(Delayed {
            shutdown_tx,
            closed: AtomicUsize::new(0),
        });
        let c = channel.clone();
        let worker = std::thread::spawn(move || {
            finish_rx.recv().unwrap();
            Ok(())
        });
        let stopper = std::thread::spawn(move || stop_owned(&*c, &AtomicBool::new(false), worker));
        shutdown_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert_eq!(channel.closed.load(Ordering::SeqCst), 0);
        finish_tx.send(()).unwrap();
        assert!(matches!(stopper.join().unwrap(), Outcome::Closed { .. }));
        assert_eq!(channel.closed.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn shutdown_failure_returns_worker_without_closing() {
        let flag = AtomicBool::new(false);
        let channel = fake(true, false);
        let worker = std::thread::spawn(|| Ok(()));
        match stop_owned(&channel, &flag, worker) {
            Outcome::ShutdownFailed { worker, error } => {
                assert!(error.contains("shutdown failure"));
                worker.join().unwrap().unwrap();
            }
            _ => panic!("shutdown failure hidden"),
        }
        assert!(flag.load(Ordering::Acquire));
        assert_eq!(channel.calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn worker_errors_do_not_hide_close_errors() {
        let flag = AtomicBool::new(false);
        let channel = fake(false, true);
        let worker = std::thread::spawn(|| Err("send failure".into()));
        match stop_owned(&channel, &flag, worker) {
            Outcome::CloseFailed { error } => {
                assert!(error.contains("close failure"));
                assert!(error.contains("send failure"));
            }
            _ => panic!("failure hidden"),
        }
    }
    #[test]
    fn worker_panic_is_reported_even_after_close() {
        let flag = AtomicBool::new(false);
        let channel = fake(false, false);
        let worker = std::thread::spawn(|| -> Result<(), String> { panic!("worker panic") });
        match stop_owned(&channel, &flag, worker) {
            Outcome::Closed {
                worker_error: Some(error),
            } => assert!(error.contains("panic")),
            _ => panic!("worker panic hidden"),
        }
        assert_eq!(channel.calls.load(Ordering::SeqCst), 11);
    }
    #[test]
    fn worker_error_after_checked_close_is_retained() {
        let flag = AtomicBool::new(false);
        let channel = fake(false, false);
        let worker = std::thread::spawn(|| Err("send failure".into()));
        match stop_owned(&channel, &flag, worker) {
            Outcome::Closed {
                worker_error: Some(e),
            } => assert!(e.contains("send failure")),
            _ => panic!("worker failure hidden"),
        }
    }
}
