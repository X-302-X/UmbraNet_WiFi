fn main() {
    println!("cargo:rerun-if-changed=icons/setup.ico");
    let windows = tauri_build::WindowsAttributes::new().window_icon_path("icons/setup.ico");
    tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows))
        .expect("Не удалось подготовить ресурсы установщика");
}
