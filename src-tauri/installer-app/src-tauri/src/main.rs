#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#[cfg(windows)]
mod backend;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use tauri::{Manager, State, WindowEvent};

// CI embeds the verified NSIS installer only after its Windows smoke test succeeds.
#[cfg(windows)]
static PAYLOAD: &[u8] = include_bytes!("../resources/backend-setup.exe");

struct InstallState {
    busy: Arc<AtomicBool>,
    installed: Mutex<Option<std::path::PathBuf>>,
}
struct BusyGuard(Arc<AtomicBool>);
impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[tauri::command]
fn setup_suggested_path() -> Result<String, String> {
    #[cfg(windows)]
    {
        backend::suggested_path()
    }
    #[cfg(not(windows))]
    {
        Err("Установщик доступен только в Windows.".into())
    }
}
#[tauri::command]
async fn setup_choose_folder() -> Result<Option<String>, String> {
    #[cfg(windows)]
    {
        tauri::async_runtime::spawn_blocking(|| {
            rfd::FileDialog::new()
                .set_title("Папка установки UmbraNet")
                .pick_folder()
                .map(|p| p.to_string_lossy().into_owned())
        })
        .await
        .map_err(|e| format!("Не удалось открыть выбор папки: {e}"))
    }
    #[cfg(not(windows))]
    {
        Err("Установщик доступен только в Windows.".into())
    }
}
#[tauri::command]
async fn setup_install(
    state: State<'_, InstallState>,
    path: String,
    shortcuts: bool,
) -> Result<String, String> {
    if state
        .busy
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err("Установка уже выполняется.".into());
    }
    let busy = state.busy.clone();
    #[cfg(windows)]
    {
        let result = tauri::async_runtime::spawn_blocking(move || {
            let _guard = BusyGuard(busy);
            backend::install(&path, shortcuts, PAYLOAD)
        })
        .await
        .map_err(|e| format!("Не удалось завершить установку: {e}"))??;
        *state
            .installed
            .lock()
            .map_err(|_| "Состояние установщика недоступно.")? = Some(result.clone());
        Ok(result.to_string_lossy().into_owned())
    }
    #[cfg(not(windows))]
    {
        let _ = (path, shortcuts, state, BusyGuard(busy));
        Err("Установщик доступен только в Windows.".into())
    }
}
#[tauri::command]
fn setup_open(state: State<'_, InstallState>, application: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        let lock = state
            .installed
            .lock()
            .map_err(|_| "Состояние установщика недоступно.")?;
        let dir = lock.as_ref().ok_or("Установка ещё не завершена.")?;
        let path = if application {
            dir.join("umbranet-wifi.exe")
        } else {
            dir.clone()
        };
        backend::open(&path)
    }
    #[cfg(not(windows))]
    {
        let _ = (state, application);
        Err("Установщик доступен только в Windows.".into())
    }
}
#[tauri::command]
fn setup_minimize(window: tauri::WebviewWindow) -> Result<(), String> {
    window.minimize().map_err(|e| e.to_string())
}
#[tauri::command]
fn setup_close(window: tauri::WebviewWindow, state: State<'_, InstallState>) -> Result<(), String> {
    if state.busy.load(Ordering::Acquire) {
        return Err("Дождитесь завершения установки.".into());
    }
    window.close().map_err(|e| e.to_string())
}
#[cfg(windows)]
fn native_error(text: &str) {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};
    let text: Vec<u16> = OsStr::new(text).encode_wide().chain(Some(0)).collect();
    let title: Vec<u16> = OsStr::new("Установка UmbraNet")
        .encode_wide()
        .chain(Some(0))
        .collect();
    unsafe {
        MessageBoxW(
            ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}
#[cfg(windows)]
fn confirm_classic_fallback() -> bool {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, IDYES, MB_ICONQUESTION, MB_YESNO,
    };
    let text: Vec<u16> = OsStr::new("Для современного окна установщика нужен Microsoft Edge WebView2 Runtime. Он не обнаружен. Открыть резервный стандартный установщик? При необходимости резервный установщик автоматически скачает и установит WebView2 с серверов Microsoft, для этого может потребоваться интернет. Без вашего согласия установка не начнётся.").encode_wide().chain(Some(0)).collect();
    let title: Vec<u16> = OsStr::new("Установка UmbraNet")
        .encode_wide()
        .chain(Some(0))
        .collect();
    unsafe {
        MessageBoxW(
            ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            MB_YESNO | MB_ICONQUESTION,
        ) == IDYES
    }
}
fn main() {
    #[cfg(windows)]
    if !backend::webview2_available() {
        if confirm_classic_fallback() {
            if let Err(error) = backend::run_classic_fallback(PAYLOAD) {
                native_error(&error);
            }
        }
        return;
    }
    let result = tauri::Builder::default()
        .manage(InstallState {
            busy: Arc::new(AtomicBool::new(false)),
            installed: Mutex::new(None),
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                if window.state::<InstallState>().busy.load(Ordering::Acquire) {
                    api.prevent_close();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            setup_suggested_path,
            setup_choose_folder,
            setup_install,
            setup_open,
            setup_minimize,
            setup_close
        ])
        .run(tauri::generate_context!());
    if let Err(error) = result {
        #[cfg(windows)]
        native_error(&format!("Не удалось открыть установщик UmbraNet. Проверьте наличие и работоспособность Microsoft Edge WebView2 Runtime.\n\n{error}"));
        #[cfg(not(windows))]
        eprintln!("Не удалось открыть установщик: {error}");
    }
}
