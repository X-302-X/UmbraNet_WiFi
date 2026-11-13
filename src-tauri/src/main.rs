#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[path = "../../core/dpi/tauri_bridge.rs"]
mod dpi_bridge;

#[path = "bridge/system.rs"]
mod system;

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
        .invoke_handler(tauri::generate_handler![
            dpi_bridge::dpi_get,
            dpi_bridge::dpi_apply,
            admin_status,
            running_processes
        ])
        .run(tauri::generate_context!())
        .expect("Не удалось запустить UmbraNet_WiFi");
}
