use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::State;
#[cfg(all(windows, target_arch = "x86_64"))]
use umbranet_dpi::layout::AppPaths;
use umbranet_dpi::store::{Store, View};

pub struct DpiState(Mutex<Result<Store, String>>);

impl DpiState {
    pub fn new() -> Self {
        let store = app_root().and_then(|root| Store::open_portable(&root));
        Self(Mutex::new(store))
    }
}

pub(crate) fn app_root() -> Result<PathBuf, String> {
    if cfg!(debug_assertions) {
        return Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".."));
    }
    std::env::current_exe()
        .map_err(|e| format!("Не удалось определить папку программы: {e}"))?
        .parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| "Не удалось определить папку программы".into())
}

#[tauri::command]
pub fn dpi_get(state: State<'_, DpiState>) -> Result<View, String> {
    let locked = state
        .0
        .lock()
        .map_err(|_| "Хранилище DPI недоступно".to_string())?;
    match &*locked {
        Ok(store) => store.view(),
        Err(error) => Err(error.clone()),
    }
}

#[tauri::command]
pub async fn dpi_apply(
    state: State<'_, DpiState>,
    action: String,
    value: String,
    enabled: bool,
) -> Result<View, String> {
    let mut locked = state
        .0
        .lock()
        .map_err(|_| "Хранилище DPI недоступно".to_string())?;
    match &mut *locked {
        Ok(store) => store.apply(&action, &value, enabled),
        Err(error) => Err(error.clone()),
    }
}

#[derive(Clone)]
struct StopView {
    phase: &'static str, // idle, recovering, stopping, complete, failed
    message: Option<String>,
    owned_closed: bool,
    auto_fault: bool,
    service_status: Option<&'static str>,
}
impl StopView {
    fn json(&self) -> serde_json::Value {
        serde_json::json!({"phase":self.phase, "message":self.message,
            "owned_closed":self.owned_closed, "auto_fault":self.auto_fault, "service_status":self.service_status})
    }
}
pub struct DiagnosticState(
    Arc<umbranet_dpi::diagnostics::session::Diagnostics>,
    Arc<Mutex<StopView>>,
);
impl DiagnosticState {
    pub fn new() -> Self {
        Self(
            Arc::new(umbranet_dpi::diagnostics::session::Diagnostics::new(
                std::time::Duration::from_secs(30),
            )),
            Arc::new(Mutex::new(StopView {
                phase: "idle",
                message: None,
                owned_closed: false,
                auto_fault: false,
                service_status: None,
            })),
        )
    }
}

#[tauri::command]
pub fn dpi_control_status(state: State<'_, DiagnosticState>) -> Result<serde_json::Value, String> {
    state
        .1
        .lock()
        .map(|v| v.json())
        .map_err(|_| "Состояние общей остановки недоступно".to_string())
}

#[tauri::command]
pub fn dpi_diagnostic_status(
    state: State<'_, DiagnosticState>,
) -> Result<umbranet_dpi::diagnostics::session::View, String> {
    state.0.view()
}

#[tauri::command]
pub fn dpi_diagnostic_clear_events(state: State<'_, DiagnosticState>) -> Result<(), String> {
    state.0.clear_events()
}

#[tauri::command]
pub async fn dpi_diagnostic_start(
    dpi: State<'_, DpiState>,
    diagnostic: State<'_, DiagnosticState>,
) -> Result<umbranet_dpi::diagnostics::session::View, String> {
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        use umbranet_dpi::diagnostics::windows::WindowsBackend;
        // Start is serialized against the stop reservation.
        let gate = diagnostic
            .1
            .lock()
            .map_err(|_| "Состояние общей остановки недоступно".to_string())?;
        if matches!(gate.phase, "stopping" | "recovering" | "failed") {
            return Err("Общая остановка не подтверждена; диагностика заблокирована".into());
        }
        let (plan, selected) = {
            let locked = dpi
                .0
                .lock()
                .map_err(|_| "Хранилище DPI недоступно".to_string())?;
            match &*locked {
                Ok(store) => store.diagnostic_setup()?,
                Err(error) => return Err(error.clone()),
            }
        };
        let path = AppPaths::new(&app_root()?).driver_dll();
        diagnostic
            .0
            .start(Arc::new(WindowsBackend::new(path)), plan, selected)
    }
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        let _ = (dpi, diagnostic);
        Err("Диагностика доступна только в Windows x64".into())
    }
}

/// Отдельный пассивный NETWORK SNIFF: включает трафик других приложений на
/// web-портах, не применяет стратегии и не доказывает отсутствие LSO.
#[tauri::command]
pub async fn dpi_tcp_diagnostic_start(
    diagnostic: State<'_, DiagnosticState>,
    strategy: State<'_, StrategyState>,
) -> Result<umbranet_dpi::diagnostics::session::View, String> {
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        let gate = diagnostic
            .1
            .lock()
            .map_err(|_| "Состояние общей остановки недоступно".to_string())?;
        if matches!(gate.phase, "stopping" | "recovering" | "failed") {
            return Err("Общая остановка не подтверждена; диагностика заблокирована".into());
        }
        let inner = strategy.try_lock()?;
        if inner.running_id.is_some()
            || inner.channel.is_some()
            || inner.worker.is_some()
            || inner.supervisor.is_some()
            || inner.stop.is_some()
        {
            return Err("Сначала полностью остановите активный DPI".into());
        }
        let path = AppPaths::new(&app_root()?).driver_dll();
        diagnostic.0.start(
            Arc::new(umbranet_dpi::diagnostics::windows::TcpMetadataBackend::new(
                path,
            )),
            umbranet_dpi::capture::CapturePlan::tcp_metadata_diagnostic(),
            std::collections::BTreeSet::new(),
        )
    }
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        let _ = (diagnostic, strategy);
        Err("Диагностика доступна только в Windows x64".into())
    }
}

#[tauri::command]
pub async fn dpi_diagnostic_stop(
    state: State<'_, DiagnosticState>,
) -> Result<umbranet_dpi::diagnostics::session::View, String> {
    state.0.stop()
}

// ---- Пресеты стратегий и управление активным движком ----

use std::sync::atomic::AtomicBool;
use umbranet_dpi::autohostlist::AutoHostList;
use umbranet_dpi::profiles::{Profiles, Summary};

#[cfg(all(windows, target_arch = "x86_64"))]
type SharedChannel = Arc<umbranet_dpi::capture::windivert::DivertChannel>;
#[cfg(not(all(windows, target_arch = "x86_64")))]
type SharedChannel = ();

pub struct StrategyView {
    pub strategies: Vec<Summary>,
    pub selected: Option<String>,
    pub running: bool,
    pub running_id: Option<String>,
    pub last_error: Option<String>,
    pub auto_domains: Vec<String>,
}

impl StrategyView {
    /// Без derive-зависимостей: мост использует только serde_json, который уже есть.
    pub fn to_json(&self) -> String {
        let strategies: Vec<String> = self
            .strategies
            .iter()
            .map(|s| {
                format!(
                    "{{\"id\":{},\"name\":{},\"file\":{}}}",
                    quote(&s.id),
                    quote(&s.name),
                    quote(&s.file)
                )
            })
            .collect();
        let auto: Vec<String> = self.auto_domains.iter().map(|d| quote(d)).collect();
        format!(
            "{{\"strategies\":[{}],\"selected\":{},\"running\":{},\"running_id\":{},\"last_error\":{},\"auto_domains\":[{}]}}",
            strategies.join(","),
            opt(&self.selected),
            self.running,
            opt(&self.running_id),
            opt(&self.last_error),
            auto.join(",")
        )
    }
}

fn quote(value: &str) -> String {
    serde_json::Value::String(value.to_string()).to_string()
}

fn opt(value: &Option<String>) -> String {
    match value {
        Some(text) => quote(text),
        None => "null".to_string(),
    }
}

pub struct StrategyState {
    inner: Arc<Mutex<StrategyInner>>,
}

struct StrategyInner {
    profiles: Result<Profiles, String>,
    stop: Option<Arc<AtomicBool>>,
    channel: Option<SharedChannel>,
    worker: Option<umbranet_dpi::capture::active_stop::Worker>,
    supervisor: Option<Arc<umbranet_dpi::capture::active_supervisor::Supervisor>>,
    events: Option<std::sync::mpsc::Receiver<String>>,
    running_id: Option<String>,
    last_error: Option<String>,
    auto_domains: Vec<String>,
}

impl StrategyState {
    pub fn new() -> Self {
        let profiles = app_root()
            .map(|root| umbranet_dpi::layout::AppPaths::new(&root).strategy_dir())
            .and_then(|dir| Profiles::load(&dir))
            .and_then(|p| {
                p.ensure_selected()?;
                Ok(p)
            });
        Self {
            inner: Arc::new(Mutex::new(StrategyInner {
                profiles,
                stop: None,
                channel: None,
                worker: None,
                supervisor: None,
                events: None,
                running_id: None,
                last_error: None,
                auto_domains: Vec::new(),
            })),
        }
    }

    fn try_lock(&self) -> Result<std::sync::MutexGuard<'_, StrategyInner>, String> {
        self.inner
            .lock()
            .map_err(|_| "Состояние стратегий недоступно".to_string())
    }
}

fn drain_events(inner: &mut StrategyInner) {
    if let Some(rx) = &inner.events {
        while let Ok(text) = rx.try_recv() {
            inner.last_error = Some(text);
        }
    }
    // Не считать worker освобождённым только по событию ошибки.
    // До включения активного Start требуется автоматический безопасный cleanup.
}

fn build_view(inner: &mut StrategyInner) -> StrategyView {
    let (strategies, selected, profiles_error) = match &inner.profiles {
        Ok(profiles) => (profiles.list(), profiles.selected_id(), None),
        Err(error) => (Vec::new(), None, Some(error.clone())),
    };
    StrategyView {
        strategies,
        selected,
        running: inner.running_id.is_some(),
        running_id: inner.running_id.clone(),
        last_error: profiles_error.or_else(|| inner.last_error.clone()),
        auto_domains: inner.auto_domains.clone(),
    }
}

#[tauri::command]
pub fn dpi_strategy_list(state: State<'_, StrategyState>) -> Result<String, String> {
    let mut inner = state.try_lock()?;
    drain_events(&mut inner);
    Ok(build_view(&mut inner).to_json())
}

#[tauri::command]
pub fn dpi_strategy_select(state: State<'_, StrategyState>, id: String) -> Result<String, String> {
    let mut inner = state.try_lock()?;
    if inner.running_id.is_some() || inner.channel.is_some() || inner.worker.is_some() || inner.supervisor.is_some() || inner.stop.is_some() {
        return Err("Сначала полностью остановите DPI, затем меняйте стратегию".into());
    }
    {
        let profiles = match &inner.profiles {
            Ok(profiles) => profiles,
            Err(error) => return Err(error.clone()),
        };
        profiles.select(&id)?;
    }
    inner.last_error = None;
    Ok(build_view(&mut inner).to_json())
}

/// Включает активный движок на выбранной стратегии.
/// Требует прав администратора и наличия WinDivert.dll рядом с драйвером.
#[tauri::command]
pub async fn dpi_engine_start(
    state: State<'_, StrategyState>,
    diagnostic: State<'_, DiagnosticState>,
    dpi: State<'_, DpiState>,
) -> Result<String, String> {
    // Эта блокировка остаётся до безопасного запуска, автоочистки и Windows-проверок.
    umbranet_dpi::safety::active_start_guard().map_err(str::to_string)?;
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        // Сериализуем подготовку, открытие и публикацию с общей остановкой и диагностикой.
        let mut gate = diagnostic
            .1
            .lock()
            .map_err(|_| "Состояние общей остановки недоступно".to_string())?;
        if matches!(gate.phase, "stopping" | "recovering" | "failed") {
            return Err("Предыдущая остановка DPI не подтверждена".into());
        }
        if diagnostic.0.view()?.busy {
            return Err("Сначала остановите пассивную проверку".into());
        }
        // Обе блокировки держатся одновременно, поэтому выбранный профиль и
        // цели фиксируются вместе, до открытия канала и запуска рабочего потока.
        let mut inner = state.try_lock()?;
        let (id, plan, dll) = {
            if inner.running_id.is_some() {
                return Ok(build_view(&mut inner).to_json());
            }
            let profiles = match &inner.profiles {
                Ok(p) => p,
                Err(error) => return Err(error.clone()),
            };
            let store = dpi
                .0
                .lock()
                .map_err(|_| "Хранилище DPI недоступно".to_string())?;
            let store = match &*store {
                Ok(store) => store,
                Err(error) => return Err(error.clone()),
            };
            let plan = store.prepare_selected_session(profiles)?;
            plan.check_known_limits()?;
            let id = plan.strategy().id.clone();
            let dll = AppPaths::new(&app_root()?).driver_dll();
            (id, plan, dll)
        };
        let filter = plan.active_capture_filter()?;
        let auto = AutoHostList::load(&AppPaths::new(&app_root()?).strategy_dir());
        let auto_domains = auto.domains();
        // Отдельный guard не позволяет запустить текущий одно-пакетный pipeline.
        let mut engine = plan.make_guarded_engine(Some(auto))?;

        let channel = match umbranet_dpi::capture::windivert::DivertChannel::open(&dll, filter) {
            Ok(channel) => Arc::new(channel),
            Err(e) => {
                inner.last_error = Some(format!("Не удалось открыть WinDivert: {e}"));
                return Ok(build_view(&mut inner).to_json());
            }
        };

        let stop = Arc::new(AtomicBool::new(false));
        let supervisor = Arc::new(umbranet_dpi::capture::active_supervisor::Supervisor::new());
        let thread_stop = Arc::clone(&stop);
        let thread_channel = Arc::clone(&channel);
        let thread_supervisor = Arc::clone(&supervisor);
        let thread_gate = Arc::clone(&diagnostic.1);
        let thread_strategy = Arc::clone(&state.inner);
        let (events_tx, events_rx) = std::sync::mpsc::channel::<String>();
        let handle = match std::thread::Builder::new().name("umbra-dpi-worker".into()).spawn(move || {
            let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                engine.run_channel(&thread_channel, &thread_stop)
            })) {
                Ok(result) => result.map_err(|error| error.to_string()),
                Err(_) => Err("panic рабочего потока DPI".to_string()),
            };
            if let Some(report) = thread_supervisor.finish_worker(&*thread_channel, &thread_stop, &result, || {
                if let Ok(mut gate) = thread_gate.lock() {
                    if gate.phase == "idle" {
                        gate.phase = "recovering";
                        gate.message = Some("Рабочий поток DPI завершился неожиданно; закрываем собственный канал".into());
                    }
                }
            }) {
                let _ = events_tx.send(report.message.clone());
                // Если пользователь уже запросил Stop, итог установит его поток.
                // Порядок блокировок совпадает с запуском и остановкой: gate → strategy.
                if let Ok(mut gate) = thread_gate.lock() {
                    if gate.phase == "recovering" || gate.phase == "idle" || gate.phase == "failed" || (gate.phase == "stopping" && report.after_failed_user_shutdown) {
                        let stopping = gate.phase == "stopping";
                        let previous = gate.message.take();
                        if !stopping { gate.phase = "failed"; }
                        gate.owned_closed = report.owned_closed;
                        gate.auto_fault = true;
                        gate.message = Some(match previous { Some(text) => format!("{text}; {}", report.message), None => report.message.clone() });
                        if let Ok(mut strategy) = thread_strategy.lock() {
                            strategy.last_error = Some(report.message.clone());
                            strategy.running_id = None;
                        }
                    }
                }
                Err(report.message)
            } else {
                if let Err(error) = &result { let _ = events_tx.send(format!("Движок остановлен: {error}")); }
                result
            }
        }) {
            Ok(handle) => handle,
            Err(error) => {
                // Поток не создан; только этот поток владеет каналом.
                use umbranet_dpi::capture::active_stop::ActiveChannel;
                let shutdown = channel.shutdown_recv();
                let close = channel.close_checked();
                let message = format!("Не удалось создать поток DPI: {error}; shutdown: {}; close: {}", shutdown.err().map_or_else(|| "ok".into(), |e| e.to_string()), close.as_ref().err().map_or_else(|| "ok".into(), |e| e.to_string()));
                gate.phase = "failed";
                gate.owned_closed = close.is_ok();
                gate.message = Some(message.clone());
                inner.last_error = Some(message.clone());
                if close.is_err() { inner.channel = Some(channel); }
                return Err(message);
            }
        };

        inner.stop = Some(stop);
        inner.channel = Some(channel);
        inner.worker = Some(handle);
        inner.supervisor = Some(supervisor);
        inner.events = Some(events_rx);
        inner.auto_domains = auto_domains;
        inner.running_id = Some(id);
        inner.last_error = None;
        *gate = StopView {
            phase: "idle",
            message: None,
            owned_closed: false,
            auto_fault: false,
            service_status: None,
        };
        Ok(build_view(&mut inner).to_json())
    }
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        let _ = (state, diagnostic, dpi);
        Err("Активный движок доступен только в Windows x64".into())
    }
}

// Порядок: собственный shutdown -> join -> проверенное close -> диагностика -> SCM.
// Всё потенциально блокирующее выполняется только в выделенном потоке.
#[cfg(all(windows, target_arch = "x86_64"))]
fn run_common_stop(
    strategy: Arc<Mutex<StrategyInner>>,
    diagnostics: Arc<umbranet_dpi::diagnostics::session::Diagnostics>,
    control: Arc<Mutex<StopView>>,
) -> Result<(Option<String>, &'static str), String> {
    use umbranet_dpi::capture::active_stop::Outcome;
    use umbranet_dpi::capture::active_supervisor::StopClaim;
    let (flag, channel, worker, supervisor, claim) = {
        let mut inner = strategy
            .lock()
            .map_err(|_| "Состояние DPI недоступно".to_string())?;
        let flag = inner.stop.clone().ok_or("Нет флага остановки DPI")?;
        let channel = inner.channel.clone().ok_or("Нет канала DPI")?;
        let supervisor = inner.supervisor.clone().ok_or("Нет координатора остановки DPI")?;
        if inner.worker.is_none() { return Err("Нет потока DPI".into()); }
        // Владельца выбираем только после успешного создания потока Stop.
        let claim = supervisor.reserve_user_stop();
        if claim == StopClaim::AlreadyClaimed { return Err("Владелец остановки DPI уже выбран".into()); }
        let worker = inner.worker.take().ok_or("Нет потока DPI")?;
        (flag, channel, worker, supervisor, claim)
    };
    let worker_error = match supervisor.stop(claim, &*channel, &flag, worker) {
        Outcome::ShutdownFailed { worker, error } => {
            // Сохраняем handle даже при ошибке shutdown. Поток может ещё работать;
            // его результат нельзя объявить успешным или потерять.
            if let Ok(mut inner) = strategy.lock() {
                drain_events(&mut inner);
                let message = match &inner.last_error {
                    Some(previous) => format!("{error}; {previous}"),
                    None => error,
                };
                inner.worker = Some(worker);
                return Err(message);
            }
            return Err(format!("{error}; состояние потока DPI недоступно"));
        }
        Outcome::CloseFailed { error } => return Err(error),
        Outcome::Closed { worker_error } => worker_error,
    };
    {
        let mut inner = strategy
            .lock()
            .map_err(|_| "Состояние DPI недоступно после закрытия".to_string())?;
        inner.channel = None;
        inner.stop = None;
        inner.supervisor = None;
        inner.running_id = None;
        drain_events(&mut inner);
        inner.events = None;
    }
    drop(channel);
    {
        let mut view = control
            .lock()
            .map_err(|_| "Состояние общей остановки недоступно".to_string())?;
        view.owned_closed = true;
        view.message = worker_error.clone();
    }
    // Диагностический handle тоже нужно закрыть до остановки общей службы.
    let mut view = diagnostics.view()?;
    if view.busy {
        view = diagnostics.stop()?;
    }
    let begin = std::time::Instant::now();
    while view.busy && view.phase != umbranet_dpi::diagnostics::session::Phase::StopFailed {
        if begin.elapsed() >= std::time::Duration::from_secs(10) {
            return Err("Пассивная проверка ещё не закрыта; общая служба не остановлена".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        view = diagnostics.view()?;
    }
    if view.busy || view.phase == umbranet_dpi::diagnostics::session::Phase::Error {
        return Err(format!(
            "Не подтверждено закрытие пассивной проверки: {}. Общая служба не остановлена",
            view.message
                .unwrap_or_else(|| "состояние неизвестно".into())
        ));
    }
    let service = umbranet_dpi::capture::driver_service::request_stop_and_confirm(
        std::time::Duration::from_secs(10),
    )
    .map_err(|e| format!("Не подтверждена остановка службы WinDivert: {e}"))?;
    // Это статус SCM, не подтверждение выгрузки всех экземпляров драйвера.
    Ok((worker_error, service.status))
}

#[tauri::command]
pub fn dpi_engine_stop(
    state: State<'_, StrategyState>,
    diagnostic: State<'_, DiagnosticState>,
) -> Result<serde_json::Value, String> {
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        let mut gate = diagnostic
            .1
            .lock()
            .map_err(|_| "Состояние общей остановки недоступно".to_string())?;
        if gate.phase == "stopping" {
            return Ok(gate.json());
        }
        // После подтверждённого автоматического закрытия та же кнопка Stop
        // может явно запросить остановку общей службы. Не повторяем close handle.
        if gate.phase == "failed" && !(gate.auto_fault && gate.owned_closed) {
            return Err(gate
                .message
                .clone()
                .unwrap_or_else(|| "Остановка не подтверждена".into()));
        }
        {
            let inner = state.try_lock()?;
            if inner.running_id.is_none()
                && inner.channel.is_none()
                && inner.worker.is_none()
                && inner.supervisor.is_none()
                && inner.stop.is_none()
            {
                return Err(
                    "Активная сессия DPI не запущена; общая служба не останавливалась".into(),
                );
            }
            if inner.stop.is_none() || inner.channel.is_none() || inner.worker.is_none() || inner.supervisor.is_none() {
                gate.phase = "failed";
                gate.message =
                    Some("Состояние ресурсов DPI неполное; остановка не подтверждена".into());
                return Err(gate.message.clone().unwrap());
            }
        }
        *gate = StopView {
            phase: "stopping",
            message: None,
            owned_closed: false,
            auto_fault: false,
            service_status: None,
        };
        let strategy = state.inner.clone();
        let diagnostics = diagnostic.0.clone();
        let control = diagnostic.1.clone();
        let spawn = std::thread::Builder::new().name("umbra-dpi-stop".into()).spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_common_stop(strategy, diagnostics, control.clone())));
            if let Ok(mut gate) = control.lock() {
                match outcome {
                    Ok(Ok((worker_error, service))) => {
                        gate.service_status = Some(service);
                        if let Some(error) = worker_error { gate.phase = "failed"; gate.message = Some(error); }
                        else { gate.phase = "complete"; }
                    }
                    Ok(Err(error)) => {
                        gate.phase = "failed";
                        gate.message = Some(match gate.message.take() { Some(previous) => format!("{previous}; {error}"), None => error });
                    }
                    Err(_) => {
                        gate.phase = "failed";
                        let error = "Ошибка общей остановки DPI (panic); состояние ресурсов не подтверждено";
                        gate.message = Some(match gate.message.take() { Some(previous) => format!("{previous}; {error}"), None => error.into() });
                    }
                }
            }
        });
        if let Err(error) = spawn {
            gate.phase = "failed";
            gate.message = Some(format!("Не удалось запустить остановку DPI: {error}. Рабочий поток может продолжать работу; общая служба не останавливалась."));
            return Err(gate.message.clone().unwrap());
        }
        Ok(gate.json())
    }
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        let _ = (state, diagnostic);
        Err("Остановка DPI доступна только в Windows x64".into())
    }
}

/// Очищает автоматически собранный список доменов.
#[tauri::command]
pub fn dpi_autohostlist_clear(state: State<'_, StrategyState>) -> Result<String, String> {
    let mut inner = state.try_lock()?;
    let dir = umbranet_dpi::layout::AppPaths::new(&app_root()?).strategy_dir();
    let mut auto = AutoHostList::load(&dir);
    auto.clear()?;
    inner.auto_domains = Vec::new();
    Ok(build_view(&mut inner).to_json())
}
