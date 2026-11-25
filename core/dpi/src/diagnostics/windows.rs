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
struct TcpMetadataObserver {
    sniffer: crate::capture::windivert::Sniffer,
    budget: crate::diagnostics::tcp_stats::Ipv4SampleBudget,
}
impl Observer for TcpMetadataObserver {
    fn receive(&self) -> io::Result<Option<Observation>> {
        Err(io::Error::other("Неверный тип источника TCP-диагностики"))
    }
    fn receive_event(&self) -> io::Result<crate::diagnostics::session::DiagnosticEvent> {
        use crate::diagnostics::tcp_stats::Ipv4NativeComparison;
        let (packet, addr) = self.sniffer.receive_with_address()?;
        let mut facts = crate::diagnostics::tcp_stats::PacketFacts::from_packet(&packet, &addr);
        // Ограниченная выборка: DLL обрабатывает лишь временную копию, не сеть.
        // Никакие адреса, checksum или payload не сохраняются в результат.
        if facts.needs_ipv4_native_comparison() && self.budget.try_take() {
            let comparison = match self.sniffer.compare_ipv4_checksum(&packet) {
                Ok(true) => Ipv4NativeComparison::Same,
                Ok(false) => Ipv4NativeComparison::Different,
                Err(_) => Ipv4NativeComparison::Unavailable,
            };
            facts.set_ipv4_native_comparison(comparison);
        }
        // packet/addr не покидают функцию и не попадают в View/журнал.
        Ok(crate::diagnostics::session::DiagnosticEvent::Tcp(facts))
    }
    fn shutdown(&self) -> io::Result<()> {
        self.sniffer.shutdown()
    }
    fn close(&self) -> io::Result<()> {
        self.sniffer.close_checked()
    }
}
impl Backend for TcpMetadataBackend {
    fn kind(&self) -> crate::diagnostics::session::Kind {
        crate::diagnostics::session::Kind::TcpMetadata
    }
    fn open(&self, _: &CapturePlan) -> io::Result<Arc<dyn Observer>> {
        Ok(Arc::new(TcpMetadataObserver {
            sniffer: crate::capture::windivert::Sniffer::open_tcp_metadata(&self.dll_path)?,
            budget: crate::diagnostics::tcp_stats::Ipv4SampleBudget::default(),
        }))
    }
    fn process_name(&self, _: u32) -> io::Result<String> {
        Err(io::Error::other("Процессы в TCP-проверке не определяются"))
    }
}
