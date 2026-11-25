#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[path = "../../core/dpi/tauri_bridge.rs"]
mod dpi_bridge;

#[path = "bridge/system.rs"]
mod system;

mod appearance;
mod journal;
use std::sync::atomic::Ordering;
use tauri::Manager;

#[tauri::command]
fn admin_status() -> Result<bool, String> {
    system::is_elevated()
}

#[tauri::command]
async fn running_processes() -> Result<Vec<String>, String> {
    system::running_processes()
}

fn main() {
    tauri::Builder::default()
        .manage(dpi_bridge::DpiState::new())
        .manage(dpi_bridge::DiagnosticState::new())
        .manage(dpi_bridge::StrategyState::new())
        .manage(journal::JournalState::new())
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // Дочерний тест не должен оставаться без наблюдения при обычном закрытии.
                if window.label() == "main"
                    && window
                        .state::<dpi_bridge::DiagnosticState>()
                        .probe_running_or_unknown()
                {
                    api.prevent_close();
                    if let Some(webview) = window.app_handle().get_webview_window(window.label()) {
                        let _ = webview.eval(
                            "window.dispatchEvent(new Event('umbra-loopback-close-blocked'))",
                        );
                    }
                    return;
                }
                let state = window.state::<journal::JournalState>();
                if window.label() == "main"
                    && state.ready.load(Ordering::Acquire)
                    && !state.allow_close.load(Ordering::Acquire)
                {
                    // JS дождётся сохранения очереди или спросит перед закрытием без неё.
                    if let Some(webview) = window.app_handle().get_webview_window(window.label()) {
                        if webview
                            .eval("window.dispatchEvent(new Event('umbra-journal-close-request'))")
                            .is_ok()
                        {
                            api.prevent_close();
                        }
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            journal::journal_write,
            journal::journal_cleanup,
            journal::journal_ready,
            journal::journal_finish_close,
            dpi_bridge::dpi_get,
            dpi_bridge::dpi_apply,
            dpi_bridge::dpi_control_status,
            dpi_bridge::dpi_diagnostic_status,
            dpi_bridge::dpi_loopback_status,
            dpi_bridge::dpi_loopback_start,
            dpi_bridge::dpi_diagnostic_clear_events,
            dpi_bridge::dpi_diagnostic_start,
            dpi_bridge::dpi_tcp_diagnostic_start,
            dpi_bridge::dpi_diagnostic_stop,
            dpi_bridge::dpi_strategy_list,
            dpi_bridge::dpi_strategy_select,
            dpi_bridge::dpi_engine_start,
            dpi_bridge::dpi_engine_stop,
            dpi_bridge::dpi_autohostlist_clear,
            admin_status,
            running_processes,
            appearance::appearance_load,
            appearance::appearance_save,
            appearance::appearance_migrate
        ])
        .run(tauri::generate_context!())
        .expect("Не удалось запустить UmbraNet_WiFi");
}
