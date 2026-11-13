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
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "stopped"));
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
    let view = d.view().unwrap();
    assert_eq!(view.phase, Phase::StopFailed);
    assert!(view.busy);
    assert!(view.message.unwrap().contains("Закройте программу"));
    {
        let mut state = source.state.lock().unwrap();
        state.fail_stop = false;
        state.stopped = true;
    }
    source.changed.notify_all();
    wait_for(|| !d.view().unwrap().busy);
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
        Ok(())
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
