#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[path = "../../core/dpi/tauri_bridge.rs"]
mod dpi_bridge;

#[path = "bridge/system.rs"]
mod system;

mod appearance;

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
        .invoke_handler(tauri::generate_handler![
            dpi_bridge::dpi_get,
            dpi_bridge::dpi_apply,
            dpi_bridge::dpi_diagnostic_status,
            dpi_bridge::dpi_diagnostic_start,
            dpi_bridge::dpi_diagnostic_stop,
            admin_status,
            running_processes,
            appearance::appearance_load,
            appearance::appearance_save,
            appearance::appearance_migrate
        ])
        .run(tauri::generate_context!())
        .expect("Не удалось запустить UmbraNet_WiFi");
}
