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
