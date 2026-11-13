use std::path::PathBuf;
use std::sync::Mutex;
use tauri::State;
use umbranet_dpi::store::{Store, View};

pub struct DpiState(Mutex<Result<Store, String>>);

impl DpiState {
    pub fn new() -> Self {
        let store = app_root().and_then(|root| Store::open(&root.join("core").join("dpi")));
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
    let locked = state.0.lock().map_err(|_| "Хранилище DPI недоступно".to_string())?;
    match &*locked {
        Ok(store) => store.view(),
        Err(error) => Err(error.clone()),
    }
}

#[tauri::command]
pub fn dpi_apply(state: State<'_, DpiState>, action: String, value: String, enabled: bool) -> Result<View, String> {
    let mut locked = state.0.lock().map_err(|_| "Хранилище DPI недоступно".to_string())?;
    match &mut *locked {
        Ok(store) => store.apply(&action, &value, enabled),
        Err(error) => Err(error.clone()),
    }
}
