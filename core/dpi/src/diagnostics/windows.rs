use crate::capture::{windivert::FlowListener, CapturePlan};
use crate::diagnostics::session::{Backend, Connection, Observation, Observer};
use crate::flow::{tracker::Transport, windows_process::current_process_info, wire::FlowEventKind};
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
            connection: Some(Connection {
                local: event.key.local(),
                remote: event.key.remote(),
                protocol: match event.key.protocol() {
                    Transport::Tcp => "TCP",
                    Transport::Udp => "UDP",
                },
            }),
        }))
    }
    fn shutdown(&self) -> io::Result<()> {
        self.0.shutdown()
    }
    fn close(&self) -> io::Result<()> {
        self.0.close_checked()
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

/// Только SNIFF/RECV_ONLY; на диске и в журналах нет содержимого пакетов.
pub struct TcpMetadataBackend {
    dll_path: PathBuf,
}
impl TcpMetadataBackend {
    pub fn new(dll_path: PathBuf) -> Self {
        Self { dll_path }
    }
}
struct TcpMetadataObserver(crate::capture::windivert::Sniffer);
impl Observer for TcpMetadataObserver {
    fn receive(&self) -> io::Result<Option<Observation>> {
        Err(io::Error::other("Неверный тип источника TCP-диагностики"))
    }
    fn receive_event(&self) -> io::Result<crate::diagnostics::session::DiagnosticEvent> {
        let (packet, addr) = self.0.receive_with_address()?;
        let facts = crate::diagnostics::tcp_stats::PacketFacts::from_packet(&packet, &addr);
        // packet/addr не покидают функцию и не попадают в View/журнал.
        Ok(crate::diagnostics::session::DiagnosticEvent::Tcp(facts))
    }
    fn shutdown(&self) -> io::Result<()> {
        self.0.shutdown()
    }
    fn close(&self) -> io::Result<()> {
        self.0.close_checked()
    }
}
impl Backend for TcpMetadataBackend {
    fn kind(&self) -> crate::diagnostics::session::Kind {
        crate::diagnostics::session::Kind::TcpMetadata
    }
    fn open(&self, _: &CapturePlan) -> io::Result<Arc<dyn Observer>> {
        Ok(Arc::new(TcpMetadataObserver(
            crate::capture::windivert::Sniffer::open_tcp_metadata(&self.dll_path)?,
        )))
    }
    fn process_name(&self, _: u32) -> io::Result<String> {
        Err(io::Error::other("Процессы в TCP-проверке не определяются"))
    }
}
