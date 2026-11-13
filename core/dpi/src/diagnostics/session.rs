use crate::capture::CapturePlan;
use serde::Serialize;
use std::collections::BTreeSet;
use std::io;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct Observation {
    pub established: bool,
    pub pid: u32,
}

pub trait Observer: Send + Sync + 'static {
    fn receive(&self) -> io::Result<Option<Observation>>;
    fn shutdown(&self) -> io::Result<()>;
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
        }
    }
}
struct State {
    view: View,
    session_id: u64,
    requested_stop: bool,
    source: Option<Arc<dyn Observer>>,
    shutdown_in_flight: bool,
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
            s.pending_finish = None;
            s.view = View {
                phase: Phase::Starting,
                busy: true,
                duration_seconds: self.duration.as_secs(),
                ..View::default()
            };
            s.session_id
        };
        let shared = self.shared.clone();
        let duration = self.duration;
        if let Err(error) = thread::Builder::new()
            .name("umbra-flow-diagnostic".into())
            .spawn(move || run(shared, session_id, backend, plan, selected, duration))
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
        let result = source.shutdown();
        // Последний клонированный handle должен быть освобождён до объявления конца сессии.
        drop(source);
        let mut state = shared
            .state
            .lock()
            .map_err(|_| "Состояние диагностики недоступно")?;
        if state.session_id == session_id {
            state.shutdown_in_flight = false;
            if let Some(error) = state.pending_finish.take() {
                finalize(&mut state, error);
            } else if let Err(error) = result {
                state.view.phase = Phase::StopFailed;
                state.view.message = Some(format!(
                    "Не удалось остановить получение событий: {error}. Закройте программу."
                ));
            }
        }
    }
    Ok(())
}

fn finalize(state: &mut State, error: Option<String>) {
    state.source = None;
    state.view.busy = false;
    if let Some(error) = error {
        state.view.phase = Phase::Error;
        state.view.message = Some(error);
    } else {
        state.view.phase = Phase::Finished;
        state.view.message = None;
    }
}

fn finish(shared: &Arc<Shared>, session_id: u64, error: Option<String>) {
    if let Ok(mut state) = shared.state.lock() {
        if state.session_id != session_id {
            return;
        }
        if state.shutdown_in_flight {
            state.pending_finish = Some(error);
        } else {
            finalize(&mut state, error);
        }
    }
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
            let cancelled = shared
                .state
                .lock()
                .map(|s| s.requested_stop)
                .unwrap_or(false);
            finish(
                &shared,
                session_id,
                if cancelled {
                    None
                } else {
                    Some(format!("Не удалось открыть WinDivert: {error}"))
                },
            );
            return;
        }
    };
    let cancelled = match shared.state.lock() {
        Ok(mut s) if s.session_id == session_id => {
            if s.requested_stop {
                true
            } else {
                s.source = Some(source.clone());
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
                if !stopping {
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
    // Убираем handle из состояния до уведомления об окончании.
    if let Ok(mut s) = shared.state.lock() {
        if s.session_id == session_id {
            s.source = None;
        }
    }
    drop(source);
    let _ = timer_done.send(());
    finish(&shared, session_id, failure);
}
