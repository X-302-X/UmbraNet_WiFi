#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[path = "../../core/dpi/tauri_bridge.rs"]
mod dpi_bridge;

fn main() {
    tauri::Builder::default()
        .manage(dpi_bridge::DpiState::new())
        .invoke_handler(tauri::generate_handler![dpi_bridge::dpi_get, dpi_bridge::dpi_apply])
        .run(tauri::generate_context!())
        .expect("Не удалось запустить UmbraNet_WiFi");
}
