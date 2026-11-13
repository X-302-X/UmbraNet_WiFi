use crate::capture::{windivert::FlowListener, CapturePlan};
use crate::diagnostics::session::{Backend, Observation, Observer};
use crate::flow::{windows_process::current_process_info, wire::FlowEventKind};
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

pub struct WindowsBackend {
    dll_path: PathBuf,
}
impl WindowsBackend {
    pub fn new(dll_path: PathBuf) -> Self {
        Self { dll_path }
    }
}
struct FlowObserver(FlowListener);
impl Observer for FlowObserver {
    fn receive(&self) -> io::Result<Option<Observation>> {
        Ok(self.0.receive()?.map(|event| Observation {
            established: event.kind == FlowEventKind::Established,
            pid: event.pid,
        }))
    }
    fn shutdown(&self) -> io::Result<()> {
        self.0.shutdown()
    }
}
impl Backend for WindowsBackend {
    fn open(&self, plan: &CapturePlan) -> io::Result<Arc<dyn Observer>> {
        Ok(Arc::new(FlowObserver(FlowListener::open(
            &self.dll_path,
            plan,
        )?)))
    }
    fn process_name(&self, pid: u32) -> io::Result<String> {
        Ok(current_process_info(pid)?.image_name().to_string())
    }
}
