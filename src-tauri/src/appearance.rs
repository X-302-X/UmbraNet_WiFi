//! User appearance settings, kept separately from the executable and WebView cache.
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_BYTES: usize = 64 * 1024;

fn location() -> Result<PathBuf, String> {
    let base =
        std::env::var_os("APPDATA").ok_or("Не удалось определить папку настроек пользователя.")?;
    Ok(PathBuf::from(base)
        .join("UmbraNet_WiFi")
        .join("appearance.json"))
}

fn validate(value: &str) -> Result<(), String> {
    if value.len() > MAX_BYTES {
        return Err("Файл настроек слишком большой.".into());
    }
    let parsed: serde_json::Value = serde_json::from_str(value).map_err(|_| {
        "Файл настроек оформления повреждён. Он сохранён без изменений.".to_string()
    })?;
    if !parsed.is_object() {
        return Err(
            "Файл настроек оформления имеет неверный формат. Он сохранён без изменений.".into(),
        );
    }
    Ok(())
}

fn read(path: &Path) -> Result<Option<String>, String> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "Не удалось прочитать настройки оформления: {error}"
            ))
        }
    };
    if !metadata.is_file() || metadata.len() > MAX_BYTES as u64 {
        return Err(
            "Файл настроек оформления недоступен или слишком большой. Он сохранён без изменений."
                .into(),
        );
    }
    let text = fs::read_to_string(path)
        .map_err(|e| format!("Не удалось прочитать настройки оформления: {e}"))?;
    validate(&text)?;
    Ok(Some(text))
}

fn write(path: &Path, text: &str) -> Result<(), String> {
    validate(text)?;
    // Do not replace a damaged or unreadable file; the user may recover it manually.
    let _ = read(path)?;
    let parent = path
        .parent()
        .ok_or("Не удалось определить папку настроек.")?;
    fs::create_dir_all(parent).map_err(|e| format!("Не удалось создать папку настроек: {e}"))?;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    for _ in 0..20 {
        let temp = parent.join(format!(
            ".appearance-{}-{}.tmp",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&temp) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "Не удалось сохранить настройки оформления: {error}"
                ))
            }
        };
        let result = file
            .write_all(text.as_bytes())
            .and_then(|_| file.sync_all());
        drop(file);
        let result = result.and_then(|_| fs::rename(&temp, path));
        if let Err(error) = result {
            let _ = fs::remove_file(&temp);
            return Err(format!(
                "Не удалось сохранить настройки оформления: {error}"
            ));
        }
        return Ok(());
    }
    Err("Не удалось подготовить временный файл настроек.".into())
}

#[tauri::command]
pub fn appearance_load() -> Result<Option<String>, String> {
    read(&location()?)
}

#[tauri::command]
pub fn appearance_save(value: String) -> Result<(), String> {
    write(&location()?, &value)
}

#[tauri::command]
pub fn appearance_migrate(value: String) -> Result<bool, String> {
    let path = location()?;
    migrate(&path, &value)
}

fn migrate(path: &Path, value: &str) -> Result<bool, String> {
    validate(value)?;
    let parent = path
        .parent()
        .ok_or("Не удалось определить папку настроек.")?;
    fs::create_dir_all(parent).map_err(|e| format!("Не удалось создать папку настроек: {e}"))?;
    let mut file = match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::AlreadyExists => return Ok(false),
        Err(error) => {
            return Err(format!(
                "Не удалось перенести настройки оформления: {error}"
            ))
        }
    };
    let result = file
        .write_all(value.as_bytes())
        .and_then(|_| file.sync_all());
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(path);
        return Err(format!(
            "Не удалось перенести настройки оформления: {error}"
        ));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn settings_save_reload_and_corruption_is_not_overwritten() {
        let root = std::env::temp_dir().join(format!("umbra-appearance-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let path = root.join("appearance.json");
        assert!(read(&path).unwrap().is_none());
        assert!(migrate(&path, r#"{"transparency": 17}"#).unwrap());
        assert!(!migrate(&path, r#"{"transparency": 99}"#).unwrap());
        assert_eq!(read(&path).unwrap().unwrap(), r#"{"transparency": 17}"#);
        write(&path, r#"{"transparency": 72}"#).unwrap();
        assert_eq!(read(&path).unwrap().unwrap(), r#"{"transparency": 72}"#);
        fs::write(&path, "{broken").unwrap();
        assert!(read(&path).is_err());
        assert!(write(&path, r#"{"transparency": 0}"#).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "{broken");
        fs::remove_dir_all(root).unwrap();
    }
}
