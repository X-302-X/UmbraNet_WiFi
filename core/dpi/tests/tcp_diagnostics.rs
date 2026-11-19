use std::{
    collections::{BTreeSet, VecDeque},
    io,
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant},
};
use umbranet_dpi::{
    capture::{address::WinDivertAddress, CapturePlan},
    diagnostics::{
        session::{Backend, DiagnosticEvent, Diagnostics, Kind, Observation, Observer, Phase},
        tcp_stats::PacketFacts,
    },
};

#[derive(Default)]
struct Queue {
    events: VecDeque<DiagnosticEvent>,
    stopped: bool,
}
#[derive(Default)]
struct Source {
    queue: Mutex<Queue>,
    wake: Condvar,
}
impl Source {
    fn send(&self, event: DiagnosticEvent) {
        self.queue.lock().unwrap().events.push_back(event);
        self.wake.notify_all();
    }
}
impl Observer for Source {
    fn receive(&self) -> io::Result<Option<Observation>> {
        panic!("wrong receive method")
    }
    fn receive_event(&self) -> io::Result<DiagnosticEvent> {
        let mut q = self.queue.lock().unwrap();
        loop {
            if q.stopped {
                return Err(io::Error::from_raw_os_error(232));
            }
            if let Some(e) = q.events.pop_front() {
                return Ok(e);
            }
            q = self.wake.wait(q).unwrap();
        }
    }
    fn shutdown(&self) -> io::Result<()> {
        self.queue.lock().unwrap().stopped = true;
        self.wake.notify_all();
        Ok(())
    }
    fn close(&self) -> io::Result<()> {
        Ok(())
    }
}
struct Fake(Arc<Source>);
impl Backend for Fake {
    fn kind(&self) -> Kind {
        Kind::TcpMetadata
    }
    fn open(&self, _: &CapturePlan) -> io::Result<Arc<dyn Observer>> {
        Ok(self.0.clone())
    }
    fn process_name(&self, _: u32) -> io::Result<String> {
        panic!("TCP metadata must not resolve processes")
    }
}
fn wait_for(f: impl Fn() -> bool) {
    let limit = Instant::now() + Duration::from_secs(2);
    while !f() {
        assert!(Instant::now() < limit);
        thread::sleep(Duration::from_millis(5));
    }
}
fn packet() -> Vec<u8> {
    let hex =
        "4500002b007b000040068e1bc0000201c63364029c4001bb00000064000001f5501804d25a090000616263";
    hex.as_bytes()
        .chunks_exact(2)
        .map(|n| u8::from_str_radix(std::str::from_utf8(n).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn tcp_diagnostic_only_counts_aggregate_facts_and_stops() {
    let d = Diagnostics::new(Duration::from_secs(2));
    let s = Arc::new(Source::default());
    d.start(
        Arc::new(Fake(s.clone())),
        CapturePlan::tcp_metadata_diagnostic(),
        BTreeSet::new(),
    )
    .unwrap();
    wait_for(|| d.view().unwrap().phase == Phase::Running);
    let raw = packet();
    let addr = WinDivertAddress::default();
    s.send(DiagnosticEvent::Tcp(PacketFacts::from_packet(&raw, &addr)));
    wait_for(|| d.view().unwrap().tcp_stats.inbound.total == 1);
    let v = d.view().unwrap();
    assert_eq!(v.kind, Kind::TcpMetadata);
    assert!(v.events.is_empty());
    assert_eq!(v.tcp_stats.inbound.tcp_checksum.flag_unset_valid, 1);
    let json = serde_json::to_string(&v).unwrap();
    for forbidden in ["192.0.2.1", "198.51.100.2", "616263", "example.com"] {
        assert!(!json.contains(forbidden));
    }
    d.stop().unwrap();
    wait_for(|| !d.view().unwrap().busy);
    assert_eq!(d.view().unwrap().phase, Phase::Finished);
}
#[test]
fn tcp_backend_unexpected_flow_event_cannot_populate_journal() {
    let d = Diagnostics::new(Duration::from_secs(2));
    let s = Arc::new(Source::default());
    d.start(
        Arc::new(Fake(s.clone())),
        CapturePlan::tcp_metadata_diagnostic(),
        BTreeSet::new(),
    )
    .unwrap();
    wait_for(|| d.view().unwrap().phase == Phase::Running);
    s.send(DiagnosticEvent::Flow(Some(Observation {
        established: true,
        pid: 999,
        connection: None,
    })));
    wait_for(|| !d.view().unwrap().busy);
    let v = d.view().unwrap();
    assert_eq!(v.phase, Phase::Error);
    assert!(v.events.is_empty());
    assert!(v.message.unwrap().contains("тип диагностики"));
}

#[test]
fn tcp_timer_and_shared_session_exclude_other_start() {
    let d = Diagnostics::new(Duration::from_millis(80));
    let s = Arc::new(Source::default());
    let plan = CapturePlan::tcp_metadata_diagnostic();
    d.start(Arc::new(Fake(s.clone())), plan, BTreeSet::new())
        .unwrap();
    wait_for(|| d.view().unwrap().phase == Phase::Running);
    assert!(d
        .start(
            Arc::new(Fake(Arc::new(Source::default()))),
            plan,
            BTreeSet::new()
        )
        .is_err());
    wait_for(|| !d.view().unwrap().busy);
    assert_eq!(d.view().unwrap().phase, Phase::Finished);
    assert!(s.queue.lock().unwrap().stopped);
}
