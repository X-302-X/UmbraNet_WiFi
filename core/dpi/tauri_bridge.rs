use std::path::PathBuf;
use std::sync::Mutex;
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

fn app_root() -> Result<PathBuf, String> {
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

pub struct DiagnosticState(umbranet_dpi::diagnostics::session::Diagnostics);
impl DiagnosticState {
    pub fn new() -> Self {
        Self(umbranet_dpi::diagnostics::session::Diagnostics::new(
            std::time::Duration::from_secs(30),
        ))
    }
}

#[tauri::command]
pub fn dpi_diagnostic_status(
    state: State<'_, DiagnosticState>,
) -> Result<umbranet_dpi::diagnostics::session::View, String> {
    state.0.view()
}

#[tauri::command]
pub async fn dpi_diagnostic_start(
    dpi: State<'_, DpiState>,
    diagnostic: State<'_, DiagnosticState>,
) -> Result<umbranet_dpi::diagnostics::session::View, String> {
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        use std::sync::Arc;
        use umbranet_dpi::diagnostics::windows::WindowsBackend;
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

#[tauri::command]
pub async fn dpi_diagnostic_stop(
    state: State<'_, DiagnosticState>,
) -> Result<umbranet_dpi::diagnostics::session::View, String> {
    state.0.stop()
}

// ---- Пресеты стратегий и управление активным движком ----

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use umbranet_dpi::engine::Engine;
use umbranet_dpi::profiles::{Profiles, Summary};

const ENGINE_FILTER: &str = "!loopback and ((tcp.DstPort == 80 or tcp.DstPort == 443 or tcp.DstPort == 2053 or tcp.DstPort == 2083 or tcp.DstPort == 2087 or tcp.DstPort == 2096 or tcp.DstPort == 8443) or udp.DstPort == 443 or (udp.DstPort >= 19294 and udp.DstPort <= 19344) or (udp.DstPort >= 50000 and udp.DstPort <= 65535))";

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
        format!(
            "{{\"strategies\":[{}],\"selected\":{},\"running\":{},\"running_id\":{},\"last_error\":{}}}",
            strategies.join(","),
            opt(&self.selected),
            self.running,
            opt(&self.running_id),
            opt(&self.last_error)
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
    inner: Mutex<StrategyInner>,
}

struct StrategyInner {
    profiles: Result<Profiles, String>,
    stop: Option<Arc<AtomicBool>>,
    channel: Option<SharedChannel>,
    worker: Option<std::thread::JoinHandle<()>>,
    events: Option<std::sync::mpsc::Receiver<String>>,
    running_id: Option<String>,
    last_error: Option<String>,
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
            inner: Mutex::new(StrategyInner {
                profiles,
                stop: None,
                channel: None,
                worker: None,
                events: None,
                running_id: None,
                last_error: None,
            }),
        }
    }

    fn try_lock(&self) -> Result<std::sync::MutexGuard<'_, StrategyInner>, String> {
        self.inner
            .lock()
            .map_err(|_| "Состояние стратегий недоступно".to_string())
    }
}

fn drain_events(inner: &mut StrategyInner) {
    let failed = if let Some(rx) = &inner.events {
        let mut failed = false;
        while let Ok(text) = rx.try_recv() {
            inner.last_error = Some(text);
            failed = true;
        }
        failed
    } else {
        false
    };
    if failed {
        stop_worker(inner);
    }
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
    }
}

fn stop_worker(inner: &mut StrategyInner) {
    if let Some(flag) = inner.stop.take() {
        flag.store(true, Ordering::Relaxed);
    }
    #[cfg(all(windows, target_arch = "x86_64"))]
    if let Some(channel) = inner.channel.take() {
        // Отменяет заблокированный WinDivertRecv, иначе join повиснет.
        let _ = channel.shutdown();
    }
    if let Some(handle) = inner.worker.take() {
        let _ = handle.join();
    }
    inner.events = None;
    inner.running_id = None;
}

#[tauri::command]
pub fn dpi_strategy_list(state: State<'_, StrategyState>) -> Result<String, String> {
    let mut inner = state.try_lock()?;
    drain_events(&mut inner);
    Ok(build_view(&mut inner).to_json())
}

#[tauri::command]
pub fn dpi_strategy_select(
    state: State<'_, StrategyState>,
    id: String,
) -> Result<String, String> {
    let mut inner = state.try_lock()?;
    if inner.running_id.is_some() {
        return Err("Сначала остановите обход, затем меняйте стратегию".into());
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
pub async fn dpi_engine_start(state: State<'_, StrategyState>) -> Result<String, String> {
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        let (id, strategy, dll) = {
            let mut inner = state.try_lock()?;
            if inner.running_id.is_some() {
                return Ok(build_view(&mut inner).to_json());
            }
            let profiles = match &inner.profiles {
                Ok(p) => p,
                Err(error) => return Err(error.clone()),
            };
            let id = profiles
                .selected_id()
                .ok_or_else(|| "Стратегия не выбрана".to_string())?;
            let strategy = profiles
                .get(&id)
                .cloned()
                .ok_or_else(|| "Выбранная стратегия не найдена".to_string())?;
            let dll = umbranet_dpi::layout::AppPaths::new(&app_root()?).driver_dll();
            (id, strategy, dll)
        };

        let channel = match umbranet_dpi::capture::windivert::DivertChannel::open(&dll, ENGINE_FILTER)
        {
            Ok(channel) => Arc::new(channel),
            Err(e) => {
                let mut inner = state.try_lock()?;
                inner.last_error = Some(format!("Не удалось открыть WinDivert: {e}"));
                return Ok(build_view(&mut inner).to_json());
            }
        };

        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread_channel = Arc::clone(&channel);
        let (events_tx, events_rx) = std::sync::mpsc::channel::<String>();
        let handle = std::thread::spawn(move || {
            let mut engine = Engine::new(
                strategy,
                umbranet_dpi::traffic::filter::HostList::default(),
                umbranet_dpi::traffic::filter::IpSet::default(),
            );
            let _ = engine.run_channel_with_events(&thread_channel, &thread_stop, Some(events_tx));
        });

        let mut inner = state.try_lock()?;
        inner.stop = Some(stop);
        inner.channel = Some(channel);
        inner.worker = Some(handle);
        inner.events = Some(events_rx);
        inner.running_id = Some(id);
        inner.last_error = None;
        Ok(build_view(&mut inner).to_json())
    }
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        let _ = state;
        Err("Активный движок доступен только в Windows x64".into())
    }
}

#[tauri::command]
pub fn dpi_engine_stop(state: State<'_, StrategyState>) -> Result<String, String> {
    let mut inner = state.try_lock()?;
    stop_worker(&mut inner);
    Ok(build_view(&mut inner).to_json())
}
