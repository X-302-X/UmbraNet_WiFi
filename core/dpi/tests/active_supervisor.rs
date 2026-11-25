use std::io;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Barrier,
};
use std::thread;
use umbranet_dpi::capture::{
    active_stop::{ActiveChannel, Outcome},
    active_supervisor::{StopClaim, Supervisor},
};

struct Fake {
    shutdown: AtomicUsize,
    close: AtomicUsize,
    shutdown_fail: bool,
    close_fail: bool,
}
impl Fake {
    fn new(shutdown_fail: bool, close_fail: bool) -> Self {
        Self {
            shutdown: AtomicUsize::new(0),
            close: AtomicUsize::new(0),
            shutdown_fail,
            close_fail,
        }
    }
}
impl ActiveChannel for Fake {
    fn shutdown_recv(&self) -> io::Result<()> {
        self.shutdown.fetch_add(1, Ordering::SeqCst);
        if self.shutdown_fail {
            Err(io::Error::other("shutdown failed"))
        } else {
            Ok(())
        }
    }
    fn close_checked(&self) -> io::Result<()> {
        self.close.fetch_add(1, Ordering::SeqCst);
        if self.close_fail {
            Err(io::Error::other("close failed"))
        } else {
            Ok(())
        }
    }
}

#[test]
fn unexpected_worker_exit_closes_owned_channel_and_reports_error() {
    let s = Supervisor::new();
    let f = Fake::new(false, false);
    let flag = AtomicBool::new(false);
    let noticed = AtomicBool::new(false);
    let report = s
        .finish_worker(&f, &flag, &Err("recv failed".into()), || {
            assert_eq!(f.shutdown.load(Ordering::SeqCst), 0);
            noticed.store(true, Ordering::SeqCst);
        })
        .unwrap();
    assert!(report.owned_closed && flag.load(Ordering::SeqCst) && noticed.load(Ordering::SeqCst));
    assert!(
        report.message.contains("recv failed")
            && report.message.contains("не останавливалась")
            && report.message.contains("потеряны")
    );
    assert_eq!(f.shutdown.load(Ordering::SeqCst), 1);
    assert_eq!(f.close.load(Ordering::SeqCst), 1);
    assert!(s
        .finish_worker(&f, &flag, &Ok(()), || panic!("duplicate notification"))
        .is_none());
    assert_eq!(s.reserve_user_stop(), StopClaim::Worker);
}
#[test]
fn user_stop_reservation_prevents_worker_cleanup() {
    let s = Arc::new(Supervisor::new());
    let f = Arc::new(Fake::new(false, false));
    let flag = Arc::new(AtomicBool::new(false));
    assert_eq!(s.reserve_user_stop(), StopClaim::User);
    assert_eq!(s.reserve_user_stop(), StopClaim::AlreadyClaimed);
    let (ss, ff, stop) = (s.clone(), f.clone(), flag.clone());
    let worker = thread::spawn(move || {
        assert!(ss
            .finish_worker(&*ff, &stop, &Err("error".into()), || panic!(
                "user owns cleanup"
            ))
            .is_none());
        Err("worker failure".into())
    });
    match s.stop(StopClaim::User, &*f, &flag, worker) {
        Outcome::Closed {
            worker_error: Some(e),
        } => assert!(e.contains("worker failure")),
        _ => panic!("error lost"),
    }
    assert_eq!(f.shutdown.load(Ordering::SeqCst), 1);
    assert_eq!(f.close.load(Ordering::SeqCst), 1);
}
#[test]
fn failed_shutdown_still_attempts_close_and_both_errors_are_reported() {
    let s = Supervisor::new();
    let f = Fake::new(true, true);
    let flag = AtomicBool::new(false);
    let report = s
        .finish_worker(&f, &flag, &Err("recv".into()), || {})
        .unwrap();
    assert!(!report.owned_closed);
    assert!(
        report.message.contains("recv")
            && report.message.contains("shutdown failed")
            && report.message.contains("close failed")
    );
    assert_eq!(f.shutdown.load(Ordering::SeqCst), 1);
    assert_eq!(f.close.load(Ordering::SeqCst), 1);
}
#[test]
fn shutdown_failed_but_checked_close_can_still_be_reported_closed() {
    let s = Supervisor::new();
    let f = Fake::new(true, false);
    let flag = AtomicBool::new(false);
    let report = s.finish_worker(&f, &flag, &Ok(()), || {}).unwrap();
    assert!(report.owned_closed && report.message.contains("shutdown failed"));
}
#[test]
fn notification_panic_does_not_prevent_cleanup() {
    let s = Supervisor::new();
    let f = Fake::new(false, false);
    let flag = AtomicBool::new(false);
    let report = s
        .finish_worker(&f, &flag, &Err("error".into()), || panic!("notification"))
        .unwrap();
    assert!(report.owned_closed);
    assert_eq!(f.shutdown.load(Ordering::SeqCst), 1);
    assert_eq!(f.close.load(Ordering::SeqCst), 1);
}
#[test]
fn panics_in_shutdown_and_close_are_reported_and_not_retried() {
    struct Panics(AtomicUsize);
    impl ActiveChannel for Panics {
        fn shutdown_recv(&self) -> io::Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            panic!("shutdown panic");
        }
        fn close_checked(&self) -> io::Result<()> {
            self.0.fetch_add(10, Ordering::SeqCst);
            panic!("close panic");
        }
    }
    let s = Supervisor::new();
    let f = Panics(AtomicUsize::new(0));
    let flag = AtomicBool::new(false);
    let report = s
        .finish_worker(&f, &flag, &Err("worker failure".into()), || {})
        .unwrap();
    assert!(!report.owned_closed);
    assert!(report.message.contains("ошибка остановки приёма: panic"));
    assert!(report
        .message
        .contains("Закрытие собственного канала не подтверждено: panic"));
    assert_eq!(f.0.load(Ordering::SeqCst), 11);
}
#[test]
fn worker_and_stop_race_has_exactly_one_owner_and_one_close() {
    for _ in 0..200 {
        let s = Arc::new(Supervisor::new());
        let c = Arc::new(Fake::new(false, false));
        let flag = Arc::new(AtomicBool::new(false));
        let barrier = Arc::new(Barrier::new(2));
        let (ss, cc, ff, bb) = (s.clone(), c.clone(), flag.clone(), barrier.clone());
        let worker = thread::spawn(move || {
            bb.wait();
            ss.finish_worker(&*cc, &ff, &Err("unexpected".into()), || {});
            Err("unexpected".into())
        });
        barrier.wait();
        let claim = s.reserve_user_stop();
        assert!(matches!(claim, StopClaim::User | StopClaim::Worker));
        assert!(matches!(
            s.stop(claim, &*c, &flag, worker),
            Outcome::Closed {
                worker_error: Some(_)
            }
        ));
        assert_eq!(c.shutdown.load(Ordering::SeqCst), 1);
        assert_eq!(c.close.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn failed_user_shutdown_hands_cleanup_to_worker_even_when_worker_exits_first() {
    use std::sync::{mpsc, Mutex};
    struct FailFirst {
        calls: AtomicUsize,
        closes: AtomicUsize,
        entered: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }
    impl ActiveChannel for FailFirst {
        fn shutdown_recv(&self) -> io::Result<()> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                self.entered.send(()).unwrap();
                self.release.lock().unwrap().recv().unwrap();
                Err(io::Error::other("first shutdown failed"))
            } else {
                Ok(())
            }
        }
        fn close_checked(&self) -> io::Result<()> {
            self.closes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let channel = Arc::new(FailFirst {
        calls: AtomicUsize::new(0),
        closes: AtomicUsize::new(0),
        entered: entered_tx,
        release: Mutex::new(release_rx),
    });
    let supervisor = Arc::new(Supervisor::new());
    let flag = Arc::new(AtomicBool::new(false));
    let (attempt_tx, attempt_rx) = mpsc::channel();
    let (report_tx, report_rx) = mpsc::channel();
    let (s, c, f) = (supervisor.clone(), channel.clone(), flag.clone());
    let claim = supervisor.reserve_user_stop();
    let worker = thread::spawn(move || {
        attempt_tx.send(()).unwrap();
        let report = s
            .finish_worker(&*c, &f, &Err("recv failed".into()), || {})
            .unwrap();
        report_tx.send(report).unwrap();
        Err("recv failed".into())
    });
    let (s, c, f) = (supervisor.clone(), channel.clone(), flag.clone());
    let stopper = thread::spawn(move || s.stop(claim, &*c, &f, worker));
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    attempt_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    assert!(
        report_rx.try_recv().is_err(),
        "worker must wait while shutdown is pending"
    );
    assert_eq!(channel.closes.load(Ordering::SeqCst), 0);
    release_tx.send(()).unwrap();
    let worker = match stopper.join().unwrap() {
        Outcome::ShutdownFailed { worker, error } => {
            assert!(error.contains("first shutdown failed"));
            worker
        }
        _ => panic!("shutdown failure hidden"),
    };
    let report = report_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    assert!(report.after_failed_user_shutdown && report.owned_closed);
    assert!(worker.join().unwrap().is_err());
    assert_eq!(channel.calls.load(Ordering::SeqCst), 1);
    assert_eq!(channel.closes.load(Ordering::SeqCst), 1);
}
