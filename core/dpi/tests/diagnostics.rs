use std::collections::{BTreeSet, VecDeque};
use std::io;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use umbranet_dpi::{
    capture::CapturePlan,
    catalog::Catalog,
    diagnostics::session::{Backend, Diagnostics, Observation, Observer, Phase},
    selection::Selection,
    strategy::Strategy,
};

#[derive(Default)]
struct Queue {
    events: VecDeque<Option<Observation>>,
    stopped: bool,
    fail_stop: bool,
}
#[derive(Default)]
struct FakeObserver {
    state: Mutex<Queue>,
    changed: Condvar,
}
impl FakeObserver {
    fn send(&self, event: Option<Observation>) {
        self.state.lock().unwrap().events.push_back(event);
        self.changed.notify_all();
    }
}
impl Observer for FakeObserver {
    fn receive(&self) -> io::Result<Option<Observation>> {
        let mut state = self.state.lock().unwrap();
        loop {
            if state.stopped {
                // Имитируем ERROR_NO_DATA, который WinDivert возвращает после shutdown.
                return Err(io::Error::from_raw_os_error(232));
            }
            if let Some(event) = state.events.pop_front() {
                return Ok(event);
            }
            state = self.changed.wait(state).unwrap();
        }
    }
    fn shutdown(&self) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        if state.fail_stop {
            return Err(io::Error::other("test stop failure"));
        }
        state.stopped = true;
        self.changed.notify_all();
        Ok(())
    }
}
struct FakeBackend {
    source: Arc<FakeObserver>,
    open_fails: bool,
}
impl Backend for FakeBackend {
    fn open(&self, _: &CapturePlan) -> io::Result<Arc<dyn Observer>> {
        if self.open_fails {
            Err(io::Error::new(io::ErrorKind::NotFound, "missing driver"))
        } else {
            Ok(self.source.clone())
        }
    }
    fn process_name(&self, pid: u32) -> io::Result<String> {
        match pid {
            42 => Ok("discord.exe".into()),
            43 => Ok("other.exe".into()),
            _ => Err(io::Error::new(io::ErrorKind::NotFound, "gone")),
        }
    }
}
fn plan() -> CapturePlan {
    let c = Catalog::from_json(include_str!("../services.json")).unwrap();
    let st = Strategy::from_json(include_str!("../../../strtegs_Uz/pass-through.json")).unwrap();
    let mut s = Selection::default();
    s.set_service(&c, "discord", true).unwrap();
    CapturePlan::from_snapshot(&s.snapshot(&c, &st).unwrap()).unwrap()
}
fn wait_for(f: impl Fn() -> bool) {
    let end = Instant::now() + Duration::from_secs(2);
    while !f() {
        assert!(
            Instant::now() < end,
            "diagnostic did not reach expected state"
        );
        thread::sleep(Duration::from_millis(5));
    }
}
fn backend(source: &Arc<FakeObserver>, fail: bool) -> Arc<dyn Backend> {
    Arc::new(FakeBackend {
        source: source.clone(),
        open_fails: fail,
    })
}

#[test]
fn explicit_start_counts_without_exposing_pid_or_names_and_stops() {
    let source = Arc::new(FakeObserver::default());
    let d = Diagnostics::new(Duration::from_secs(2));
    assert_eq!(d.view().unwrap().phase, Phase::Idle);
    d.start(
        backend(&source, false),
        plan(),
        BTreeSet::from(["discord.exe".into()]),
    )
    .unwrap();
    wait_for(|| d.view().unwrap().phase == Phase::Running);
    assert!(d
        .start(backend(&source, false), plan(), BTreeSet::new())
        .is_err());
    source.send(Some(Observation {
        established: true,
        pid: 42,
    }));
    source.send(Some(Observation {
        established: true,
        pid: 43,
    }));
    source.send(Some(Observation {
        established: true,
        pid: 44,
    }));
    source.send(Some(Observation {
        established: false,
        pid: 42,
    }));
    source.send(None);
    wait_for(|| d.view().unwrap().ignored == 1);
    let view = d.view().unwrap();
    assert_eq!(
        (
            view.established,
            view.deleted,
            view.identified,
            view.unresolved,
            view.selected_process
        ),
        (3, 1, 2, 1, 1)
    );
    let json = serde_json::to_string(&view).unwrap();
    assert!(!json.contains("discord.exe"));
    assert!(!json.contains("other.exe"));
    assert!(!json.contains("pid"));
    d.stop().unwrap();
    wait_for(|| !d.view().unwrap().busy);
    assert_eq!(d.view().unwrap().phase, Phase::Finished);
}
#[test]
fn timer_stops_even_when_no_events_arrive() {
    let source = Arc::new(FakeObserver::default());
    let d = Diagnostics::new(Duration::from_millis(80));
    d.start(backend(&source, false), plan(), BTreeSet::new())
        .unwrap();
    wait_for(|| !d.view().unwrap().busy);
    assert_eq!(d.view().unwrap().phase, Phase::Finished);
    assert!(source.state.lock().unwrap().stopped);
}
#[test]
fn open_failure_is_reported_and_does_not_claim_success() {
    let source = Arc::new(FakeObserver::default());
    let d = Diagnostics::new(Duration::from_secs(1));
    d.start(backend(&source, true), plan(), BTreeSet::new())
        .unwrap();
    wait_for(|| !d.view().unwrap().busy);
    let view = d.view().unwrap();
    assert_eq!(view.phase, Phase::Error);
    assert!(view.message.unwrap().contains("missing driver"));
}
#[test]
fn failed_shutdown_is_not_reported_as_success() {
    let source = Arc::new(FakeObserver::default());
    source.state.lock().unwrap().fail_stop = true;
    let d = Diagnostics::new(Duration::from_secs(2));
    d.start(backend(&source, false), plan(), BTreeSet::new())
        .unwrap();
    wait_for(|| d.view().unwrap().phase == Phase::Running);
    d.stop().unwrap();
    wait_for(|| d.view().unwrap().phase == Phase::StopFailed);
    let view = d.view().unwrap();
    assert!(view.busy);
    assert!(view.message.unwrap().contains("Повторный запуск"));
    {
        let mut state = source.state.lock().unwrap();
        state.fail_stop = false;
        state.stopped = true;
    }
    source.changed.notify_all();
    // Даже после выхода worker не подменяем неудачный shutdown успехом.
    wait_for(|| Arc::strong_count(&source) <= 2);
    assert_eq!(d.view().unwrap().phase, Phase::StopFailed);
    assert!(d.view().unwrap().busy);
    assert!(d
        .start(backend(&source, false), plan(), BTreeSet::new())
        .is_err());
}

struct SlowBackend {
    source: Arc<FakeObserver>,
    gate: Arc<(Mutex<bool>, Condvar)>,
}
impl Backend for SlowBackend {
    fn open(&self, _: &CapturePlan) -> io::Result<Arc<dyn Observer>> {
        let (lock, wake) = &*self.gate;
        let mut proceed = lock.lock().unwrap();
        while !*proceed {
            proceed = wake.wait(proceed).unwrap();
        }
        Ok(self.source.clone())
    }
    fn process_name(&self, _: u32) -> io::Result<String> {
        Ok("test.exe".into())
    }
}

#[test]
fn stop_during_open_never_enters_running_state() {
    let source = Arc::new(FakeObserver::default());
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let d = Diagnostics::new(Duration::from_secs(1));
    d.start(
        Arc::new(SlowBackend {
            source,
            gate: gate.clone(),
        }),
        plan(),
        BTreeSet::new(),
    )
    .unwrap();
    d.stop().unwrap();
    assert_eq!(d.view().unwrap().phase, Phase::Stopping);
    let (lock, wake) = &*gate;
    *lock.lock().unwrap() = true;
    wake.notify_all();
    wait_for(|| !d.view().unwrap().busy);
    assert_eq!(d.view().unwrap().phase, Phase::Finished);
    assert_eq!(d.view().unwrap().established, 0);
}

struct DelayedShutdown {
    source: FakeObserver,
    gate: Arc<(Mutex<bool>, Condvar)>,
    fail: bool,
}
impl Observer for DelayedShutdown {
    fn receive(&self) -> io::Result<Option<Observation>> {
        self.source.receive()
    }
    fn shutdown(&self) -> io::Result<()> {
        self.source.shutdown()?;
        let (lock, wake) = &*self.gate;
        let mut release = lock.lock().unwrap();
        while !*release {
            release = wake.wait(release).unwrap();
        }
        if self.fail {
            Err(io::Error::other("delayed shutdown failure"))
        } else {
            Ok(())
        }
    }
}
struct DelayedBackend(Arc<DelayedShutdown>);
impl Backend for DelayedBackend {
    fn open(&self, _: &CapturePlan) -> io::Result<Arc<dyn Observer>> {
        Ok(self.0.clone())
    }
    fn process_name(&self, _: u32) -> io::Result<String> {
        Ok("test.exe".into())
    }
}
#[test]
fn session_remains_busy_until_shutdown_finishes_even_if_receive_has_exited() {
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let source = Arc::new(DelayedShutdown {
        source: FakeObserver::default(),
        gate: gate.clone(),
        fail: false,
    });
    let d = Arc::new(Diagnostics::new(Duration::from_secs(5)));
    d.start(
        Arc::new(DelayedBackend(source.clone())),
        plan(),
        BTreeSet::new(),
    )
    .unwrap();
    wait_for(|| d.view().unwrap().phase == Phase::Running);
    let stopper = {
        let d = d.clone();
        thread::spawn(move || d.stop())
    };
    wait_for(|| source.source.state.lock().unwrap().stopped);
    thread::sleep(Duration::from_millis(50));
    assert!(d.view().unwrap().busy);
    assert!(d
        .start(
            backend(&Arc::new(FakeObserver::default()), false),
            plan(),
            BTreeSet::new()
        )
        .is_err());
    let (lock, wake) = &*gate;
    *lock.lock().unwrap() = true;
    wake.notify_all();
    stopper.join().unwrap().unwrap();
    wait_for(|| !d.view().unwrap().busy);
    assert_eq!(d.view().unwrap().phase, Phase::Finished);
}

#[test]
fn delayed_shutdown_failure_is_not_hidden_by_early_worker_exit() {
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let source = Arc::new(DelayedShutdown {
        source: FakeObserver::default(),
        gate: gate.clone(),
        fail: true,
    });
    let d = Arc::new(Diagnostics::new(Duration::from_secs(5)));
    d.start(
        Arc::new(DelayedBackend(source.clone())),
        plan(),
        BTreeSet::new(),
    )
    .unwrap();
    wait_for(|| d.view().unwrap().phase == Phase::Running);
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let stop = {
        let d = d.clone();
        thread::spawn(move || done_tx.send(d.stop()).unwrap())
    };
    // Stop возвращает управление, хотя Shutdown всё ещё ждёт gate.
    done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("stop blocked")
        .unwrap();
    stop.join().unwrap();
    wait_for(|| source.source.state.lock().unwrap().stopped);
    // Backend и receive worker отпустили ссылки, а Shutdown ещё удерживает свою.
    wait_for(|| Arc::strong_count(&source) <= 3);
    assert_eq!(d.view().unwrap().phase, Phase::Stopping);
    assert!(d.view().unwrap().busy);
    let (lock, wake) = &*gate;
    *lock.lock().unwrap() = true;
    wake.notify_all();
    wait_for(|| d.view().unwrap().phase == Phase::StopFailed);
    let view = d.view().unwrap();
    assert!(view.busy);
    assert!(view.message.unwrap().contains("delayed shutdown failure"));
    assert!(d
        .start(
            backend(&Arc::new(FakeObserver::default()), false),
            plan(),
            BTreeSet::new()
        )
        .is_err());
}

struct UnexpectedReceiveError {
    gate: Mutex<(bool, bool)>,
    cv: Condvar,
    fail_shutdown: bool,
    panic_shutdown: bool,
}
impl Observer for UnexpectedReceiveError {
    fn receive(&self) -> io::Result<Option<Observation>> {
        let mut s = self.gate.lock().unwrap();
        s.0 = true;
        self.cv.notify_all();
        while !s.1 {
            s = self.cv.wait(s).unwrap();
        }
        Err(io::Error::from_raw_os_error(5))
    }
    fn shutdown(&self) -> io::Result<()> {
        let mut s = self.gate.lock().unwrap();
        s.1 = true;
        self.cv.notify_all();
        drop(s);
        if self.panic_shutdown {
            panic!("mock shutdown panic");
        }
        if self.fail_shutdown {
            Err(io::Error::other("shutdown failed too"))
        } else {
            Ok(())
        }
    }
}
struct UnexpectedBackend(Arc<UnexpectedReceiveError>);
impl Backend for UnexpectedBackend {
    fn open(&self, _: &CapturePlan) -> io::Result<Arc<dyn Observer>> {
        Ok(self.0.clone())
    }
    fn process_name(&self, _: u32) -> io::Result<String> {
        Ok("test.exe".into())
    }
}
#[test]
fn unexpected_receive_error_during_stop_is_reported_not_hidden() {
    let source = Arc::new(UnexpectedReceiveError {
        gate: Mutex::new((false, false)),
        cv: Condvar::new(),
        fail_shutdown: false,
        panic_shutdown: false,
    });
    let d = Diagnostics::new(Duration::from_secs(5));
    d.start(
        Arc::new(UnexpectedBackend(source.clone())),
        plan(),
        BTreeSet::new(),
    )
    .unwrap();
    wait_for(|| source.gate.lock().unwrap().0);
    d.stop().unwrap();
    wait_for(|| !d.view().unwrap().busy);
    let view = d.view().unwrap();
    assert_eq!(view.phase, Phase::Error);
    assert!(view
        .message
        .unwrap()
        .contains("Не удалось получить событие"));
}

#[test]
fn concurrent_shutdown_and_receive_failures_are_both_visible() {
    let source = Arc::new(UnexpectedReceiveError {
        gate: Mutex::new((false, false)),
        cv: Condvar::new(),
        fail_shutdown: true,
        panic_shutdown: false,
    });
    let d = Diagnostics::new(Duration::from_secs(5));
    d.start(
        Arc::new(UnexpectedBackend(source.clone())),
        plan(),
        BTreeSet::new(),
    )
    .unwrap();
    wait_for(|| source.gate.lock().unwrap().0);
    d.stop().unwrap();
    wait_for(|| {
        let v = d.view().unwrap();
        v.phase == Phase::StopFailed
            && v.message.as_deref().is_some_and(|m| {
                m.contains("shutdown failed too") && m.contains("Не удалось получить событие")
            })
    });
    assert!(d.view().unwrap().busy);
    assert!(d
        .start(
            backend(&Arc::new(FakeObserver::default()), false),
            plan(),
            BTreeSet::new()
        )
        .is_err());
}

#[test]
fn shutdown_panic_is_reported_and_worker_error_is_not_hidden() {
    let source = Arc::new(UnexpectedReceiveError {
        gate: Mutex::new((false, false)),
        cv: Condvar::new(),
        fail_shutdown: false,
        panic_shutdown: true,
    });
    let d = Diagnostics::new(Duration::from_secs(5));
    d.start(
        Arc::new(UnexpectedBackend(source.clone())),
        plan(),
        BTreeSet::new(),
    )
    .unwrap();
    wait_for(|| source.gate.lock().unwrap().0);
    d.stop().unwrap();
    wait_for(|| {
        let v = d.view().unwrap();
        v.phase == Phase::StopFailed
            && v.message
                .as_deref()
                .is_some_and(|m| m.contains("panic") && m.contains("Не удалось получить событие"))
    });
    assert!(d.view().unwrap().busy);
    assert_eq!(d.stop().unwrap().phase, Phase::StopFailed);
}

struct SlowFailedOpen {
    gate: Arc<(Mutex<(bool, bool)>, Condvar)>,
}
impl Backend for SlowFailedOpen {
    fn open(&self, _: &CapturePlan) -> io::Result<Arc<dyn Observer>> {
        let (lock, cv) = &*self.gate;
        let mut s = lock.lock().unwrap();
        s.0 = true;
        cv.notify_all();
        while !s.1 {
            s = cv.wait(s).unwrap();
        }
        Err(io::Error::other("open failed after cancel"))
    }
    fn process_name(&self, _: u32) -> io::Result<String> {
        Ok("test.exe".into())
    }
}
#[test]
fn cancelled_open_failure_is_not_reported_as_success() {
    let gate = Arc::new((Mutex::new((false, false)), Condvar::new()));
    let d = Diagnostics::new(Duration::from_secs(5));
    d.start(
        Arc::new(SlowFailedOpen { gate: gate.clone() }),
        plan(),
        BTreeSet::new(),
    )
    .unwrap();
    wait_for(|| gate.0.lock().unwrap().0);
    d.stop().unwrap();
    {
        let mut s = gate.0.lock().unwrap();
        s.1 = true;
        gate.1.notify_all();
    }
    wait_for(|| !d.view().unwrap().busy);
    let view = d.view().unwrap();
    assert_eq!(view.phase, Phase::Error);
    assert!(view.message.unwrap().contains("open failed after cancel"));
}
