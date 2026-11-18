use crate::capture::CapturePlan;
use serde::Serialize;
use std::collections::{BTreeSet, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct Observation {
    pub established: bool,
    pub pid: u32,
    pub connection: Option<Connection>,
}

#[derive(Debug, Clone, Copy)]
pub struct Connection {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub protocol: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowLog {
    pub sequence: u64,
    pub observed_ms: u64,
    pub established: bool,
    pub pid: u32,
    pub process: Option<String>,
    pub selected_process: bool,
    pub protocol: Option<String>,
    pub local_ip: Option<String>,
    pub local_port: Option<u16>,
    pub remote_ip: Option<String>,
    pub remote_port: Option<u16>,
}
const FLOW_LOG_LIMIT: usize = 200;

pub trait Observer: Send + Sync + 'static {
    fn receive(&self) -> io::Result<Option<Observation>>;
    fn shutdown(&self) -> io::Result<()>;
    /// Вызывается после завершения receive и shutdown, вне блокировки состояния.
    fn close(&self) -> io::Result<()>;
}
pub trait Backend: Send + Sync + 'static {
    fn open(&self, plan: &CapturePlan) -> io::Result<Arc<dyn Observer>>;
    /// Текущий снимок, не подтверждающий, что PID не был переиспользован.
    fn process_name(&self, pid: u32) -> io::Result<String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Idle,
    Starting,
    Running,
    Stopping,
    Finished,
    Error,
    StopFailed,
}

#[derive(Debug, Clone, Serialize)]
pub struct View {
    pub phase: Phase,
    pub busy: bool,
    pub established: u64,
    pub deleted: u64,
    pub identified: u64,
    pub unresolved: u64,
    pub selected_process: u64,
    pub ignored: u64,
    pub duration_seconds: u64,
    pub message: Option<String>,
    pub session_id: u64,
    pub events_dropped: u64,
    pub events: VecDeque<FlowLog>,
}
impl Default for View {
    fn default() -> Self {
        Self {
            phase: Phase::Idle,
            busy: false,
            established: 0,
            deleted: 0,
            identified: 0,
            unresolved: 0,
            selected_process: 0,
            ignored: 0,
            duration_seconds: 30,
            message: None,
            session_id: 0,
            events_dropped: 0,
            events: VecDeque::new(),
        }
    }
}
struct State {
    view: View,
    session_id: u64,
    requested_stop: bool,
    source: Option<Arc<dyn Observer>>,
    shutdown_in_flight: bool,
    closing: bool,
    pending_finish: Option<Option<String>>,
}
struct Shared {
    state: Mutex<State>,
}

/// Одна сессия на приложение; источник открывается только после явного start.
pub struct Diagnostics {
    shared: Arc<Shared>,
    duration: Duration,
}
impl Diagnostics {
    pub fn new(duration: Duration) -> Self {
        Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    view: View::default(),
                    session_id: 0,
                    requested_stop: false,
                    source: None,
                    shutdown_in_flight: false,
                    closing: false,
                    pending_finish: None,
                }),
            }),
            duration,
        }
    }
    pub fn view(&self) -> Result<View, String> {
        self.shared
            .state
            .lock()
            .map(|s| s.view.clone())
            .map_err(|_| "Состояние диагностики недоступно".into())
    }
    pub fn start(
        &self,
        backend: Arc<dyn Backend>,
        plan: CapturePlan,
        selected: BTreeSet<String>,
    ) -> Result<View, String> {
        let session_id = {
            let mut s = self
                .shared
                .state
                .lock()
                .map_err(|_| "Состояние диагностики недоступно")?;
            if s.view.busy {
                return Err("Диагностика уже запущена или останавливается".into());
            }
            s.session_id = s.session_id.wrapping_add(1);
            s.requested_stop = false;
            s.source = None;
            s.shutdown_in_flight = false;
            s.closing = false;
            s.pending_finish = None;
            s.view = View {
                phase: Phase::Starting,
                busy: true,
                session_id: s.session_id,
                duration_seconds: self.duration.as_secs(),
                ..View::default()
            };
            s.session_id
        };
        let shared = self.shared.clone();
        let duration = self.duration;
        if let Err(error) = thread::Builder::new()
            .name("umbra-flow-diagnostic".into())
            .spawn(move || {
                let panic_shared = shared.clone();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run(shared, session_id, backend, plan, selected, duration)
                }));
                if result.is_err() {
                    finish(
                        &panic_shared,
                        session_id,
                        Some("Ошибка потока проверки (panic)".into()),
                    );
                }
            })
        {
            let mut s = self
                .shared
                .state
                .lock()
                .map_err(|_| "Состояние диагностики недоступно")?;
            s.view.phase = Phase::Error;
            s.view.busy = false;
            s.view.message = Some(format!("Не удалось запустить проверку: {error}"));
            return Err(s.view.message.clone().unwrap_or_default());
        }
        self.view()
    }
    pub fn stop(&self) -> Result<View, String> {
        request_stop(&self.shared, None)?;
        self.view()
    }
    /// Удаляет историю наблюдений из памяти, не сбрасывая счётчики и сессию.
    pub fn clear_events(&self) -> Result<(), String> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| "Состояние диагностики недоступно")?;
        state.view.events.clear();
        Ok(())
    }
}
impl Drop for Diagnostics {
    fn drop(&mut self) {
        let _ = request_stop(&self.shared, None);
    }
}

fn request_stop(shared: &Arc<Shared>, expected_id: Option<u64>) -> Result<(), String> {
    let (session_id, source) = {
        let mut state = shared
            .state
            .lock()
            .map_err(|_| "Состояние диагностики недоступно")?;
        if !state.view.busy
            || expected_id.is_some_and(|id| id != state.session_id)
            || state.requested_stop
        {
            return Ok(());
        }
        state.requested_stop = true;
        state.view.phase = Phase::Stopping;
        let source = state.source.clone();
        state.shutdown_in_flight = source.is_some();
        (state.session_id, source)
    };
    if let Some(source) = source {
        // Shutdown может блокироваться; не выполняем его в вызывающем потоке UI.
        let worker_shared = shared.clone();
        let spawned = thread::Builder::new()
            .name("umbra-flow-shutdown".into())
            .spawn(move || {
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| source.shutdown()));
                // Ссылка операции не должна пережить обработку её результата.
                drop(source);
                let failure = match result {
                    Ok(Ok(())) => None,
                    Ok(Err(error)) => {
                        Some(format!("Не удалось остановить получение событий: {error}"))
                    }
                    Err(_) => Some("Ошибка при остановке получения событий (panic)".to_string()),
                };
                let success = failure.is_none();
                if let Ok(mut state) = worker_shared.state.lock() {
                    if state.session_id != session_id { return; }
                    state.shutdown_in_flight = false;
                    if let Some(message) = failure {
                        state.view.phase = Phase::StopFailed;
                        let worker_error = state.pending_finish.as_ref().and_then(|e| e.as_deref());
                        state.view.message = Some(match worker_error {
                            Some(worker_error) => format!("{message}; {worker_error}. Повторный запуск диагностики заблокирован."),
                            None => format!("{message}. Повторный запуск диагностики заблокирован."),
                        });
                    }
                }
                if success { close_if_ready(&worker_shared, session_id); }
            });
        if let Err(error) = spawned {
            let mut state = shared
                .state
                .lock()
                .map_err(|_| "Состояние диагностики недоступно")?;
            if state.session_id == session_id {
                state.shutdown_in_flight = false;
                state.view.phase = Phase::StopFailed;
                let worker_error = state.pending_finish.as_ref().and_then(|e| e.as_deref());
                state.view.message = Some(match worker_error {
                    Some(worker_error) => format!("Не удалось запустить остановку: {error}; {worker_error}. Повторный запуск диагностики заблокирован."),
                    None => format!("Не удалось запустить остановку: {error}. Повторный запуск диагностики заблокирован."),
                });
            }
            return Err(format!("Не удалось запустить остановку: {error}"));
        }
    }
    Ok(())
}

// Called by worker/shutdown threads only; close and destruction may block.
fn close_if_ready(shared: &Arc<Shared>, session_id: u64) {
    let (source, worker_error) = {
        let Ok(mut state) = shared.state.lock() else {
            return;
        };
        if state.session_id != session_id
            || state.shutdown_in_flight
            || state.closing
            || state.view.phase == Phase::StopFailed
            || state.pending_finish.is_none()
        {
            return;
        }
        let worker_error = state.pending_finish.take().unwrap();
        let Some(source) = state.source.clone() else {
            state.view.busy = false;
            state.view.phase = if worker_error.is_some() {
                Phase::Error
            } else {
                Phase::Finished
            };
            state.view.message = worker_error;
            return;
        };
        // No new shutdown may begin after close has been reserved.
        state.requested_stop = true;
        state.closing = true;
        state.view.phase = Phase::Stopping;
        (source, worker_error)
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| source.close()));
    drop(source);
    let failure = match result {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(format!("Не удалось закрыть WinDivert: {error}")),
        Err(_) => Some("Ошибка закрытия WinDivert (panic)".to_string()),
    };
    if let Some(failure) = failure {
        if let Ok(mut state) = shared.state.lock() {
            if state.session_id != session_id {
                return;
            }
            state.closing = false;
            state.view.phase = Phase::StopFailed;
            state.view.message = Some(match worker_error {
                Some(error) => {
                    format!("{failure}; {error}. Повторный запуск диагностики заблокирован.")
                }
                None => format!("{failure}. Повторный запуск диагностики заблокирован."),
            });
        }
        return;
    }
    // Drop the last state-owned reference outside the lock, and keep busy until
    // its destructor has returned; CloseHandle success does not prove driver unload.
    let owned = {
        let Ok(mut state) = shared.state.lock() else {
            return;
        };
        if state.session_id != session_id {
            return;
        }
        state.source.take()
    };
    drop(owned);
    if let Ok(mut state) = shared.state.lock() {
        if state.session_id != session_id {
            return;
        }
        state.closing = false;
        state.view.busy = false;
        state.view.phase = if worker_error.is_some() {
            Phase::Error
        } else {
            Phase::Finished
        };
        state.view.message = worker_error;
    }
}

fn finish(shared: &Arc<Shared>, session_id: u64, error: Option<String>) {
    if let Ok(mut state) = shared.state.lock() {
        if state.session_id != session_id {
            return;
        }
        if state.view.phase == Phase::StopFailed {
            if let Some(worker_error) = error.as_deref() {
                let previous = state.view.message.as_deref().unwrap_or("Ошибка остановки");
                state.view.message = Some(format!("{previous} {worker_error}"));
            }
            state.pending_finish = Some(error);
            return;
        }
        state.pending_finish = Some(error);
    } else {
        return;
    }
    close_if_ready(shared, session_id);
}

fn run(
    shared: Arc<Shared>,
    session_id: u64,
    backend: Arc<dyn Backend>,
    plan: CapturePlan,
    selected: BTreeSet<String>,
    duration: Duration,
) {
    let (timer_done, timer_wait) = mpsc::channel::<()>();
    let timer_shared = shared.clone();
    let timer = thread::Builder::new()
        .name("umbra-flow-timer".into())
        .spawn(move || {
            if timer_wait.recv_timeout(duration) == Err(mpsc::RecvTimeoutError::Timeout) {
                let _ = request_stop(&timer_shared, Some(session_id));
            }
        });
    if let Err(error) = timer {
        finish(
            &shared,
            session_id,
            Some(format!("Не удалось запустить таймер: {error}")),
        );
        return;
    }
    let source = match backend.open(&plan) {
        Ok(source) => source,
        Err(error) => {
            let _ = timer_done.send(());
            // Даже при отмене сохраняем ошибку открытия, а не выдаём успех.
            finish(
                &shared,
                session_id,
                Some(format!("Не удалось открыть WinDivert: {error}")),
            );
            return;
        }
    };
    let cancelled = match shared.state.lock() {
        Ok(mut s) if s.session_id == session_id => {
            s.source = Some(source.clone());
            if s.requested_stop {
                true
            } else {
                s.view.phase = Phase::Running;
                false
            }
        }
        _ => true,
    };
    if cancelled {
        drop(source);
        let _ = timer_done.send(());
        finish(&shared, session_id, None);
        return;
    }
    let mut failure = None;
    loop {
        let stopping = shared
            .state
            .lock()
            .map(|s| s.requested_stop || s.session_id != session_id)
            .unwrap_or(true);
        if stopping {
            break;
        }
        let event = match source.receive() {
            Ok(event) => event,
            Err(error) => {
                let stopping = shared
                    .state
                    .lock()
                    .map(|s| s.requested_stop)
                    .unwrap_or(true);
                // После WinDivertShutdown(RECV) ожидается ERROR_NO_DATA (232).
                // Остальные ошибки нельзя превращать в успех только из-за Stop.
                if !stopping || error.raw_os_error() != Some(232) {
                    failure = Some(format!("Не удалось получить событие: {error}"));
                }
                break;
            }
        };
        let process = event
            .filter(|e| e.established)
            .map(|e| backend.process_name(e.pid));
        if let Ok(mut s) = shared.state.lock() {
            if s.session_id != session_id || s.requested_stop {
                break;
            }
            if let Some(e) = event {
                let name = process.as_ref().and_then(|p| p.as_ref().ok()).cloned();
                let selected_process = name
                    .as_ref()
                    .is_some_and(|n| selected.contains(&n.to_ascii_lowercase()));
                let sequence = s
                    .view
                    .established
                    .saturating_add(s.view.deleted)
                    .saturating_add(1);
                let observed_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                    .unwrap_or(0);
                if s.view.events.len() == FLOW_LOG_LIMIT {
                    s.view.events.pop_front();
                    s.view.events_dropped = s.view.events_dropped.saturating_add(1);
                }
                s.view.events.push_back(FlowLog {
                    sequence,
                    observed_ms,
                    established: e.established,
                    pid: e.pid,
                    process: name,
                    selected_process,
                    protocol: e.connection.map(|c| c.protocol.to_string()),
                    local_ip: e.connection.map(|c| c.local.ip().to_string()),
                    local_port: e.connection.map(|c| c.local.port()),
                    remote_ip: e.connection.map(|c| c.remote.ip().to_string()),
                    remote_port: e.connection.map(|c| c.remote.port()),
                });
            }
            match event {
                Some(e) if e.established => {
                    s.view.established = s.view.established.saturating_add(1);
                    match process {
                        Some(Ok(name)) => {
                            s.view.identified = s.view.identified.saturating_add(1);
                            if selected.contains(&name.to_ascii_lowercase()) {
                                s.view.selected_process = s.view.selected_process.saturating_add(1);
                            }
                        }
                        _ => s.view.unresolved = s.view.unresolved.saturating_add(1),
                    }
                }
                Some(_) => s.view.deleted = s.view.deleted.saturating_add(1),
                None => s.view.ignored = s.view.ignored.saturating_add(1),
            }
        } else {
            break;
        }
    }
    // При неудачном shutdown владелец в состоянии остаётся удержанным;
    // при успешном завершении finalize снимет последнюю известную ссылку.
    drop(source);
    let _ = timer_done.send(());
    finish(&shared, session_id, failure);
}
