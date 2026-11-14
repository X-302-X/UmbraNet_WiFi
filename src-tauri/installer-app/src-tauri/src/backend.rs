//! Windows installer execution, independent from the DPI engine.
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::process::CommandExt;
use std::path::{Component, Path, PathBuf, Prefix};
use std::process::Command;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
    KEY_READ, RRF_RT_REG_SZ,
};
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::Shell::{
    FOLDERID_Desktop, FOLDERID_Documents, FOLDERID_Downloads, FOLDERID_PublicDesktop,
    SHGetKnownFolderPath, ShellExecuteW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_SETFOREGROUND, MB_YESNO, SW_SHOWNORMAL,
};

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}
const UNINSTALL_KEY: &str =
    "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\UmbraNet_WiFi";

fn registry_location(hive: HKEY) -> Result<Option<PathBuf>, String> {
    let key_name = wide(OsStr::new(UNINSTALL_KEY));
    let mut key: HKEY = ptr::null_mut();
    let status = unsafe { RegOpenKeyExW(hive, key_name.as_ptr(), 0, KEY_READ, &mut key) };
    if status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND {
        return Ok(None);
    }
    if status != 0 {
        return Err(format!(
            "Не удалось проверить прежнюю установку (код {status})."
        ));
    }
    let name = wide(OsStr::new("InstallLocation"));
    let mut bytes = 0u32;
    let status = unsafe {
        RegGetValueW(
            key,
            ptr::null(),
            name.as_ptr(),
            RRF_RT_REG_SZ,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut bytes,
        )
    };
    if status != 0 || bytes == 0 || bytes > 65536 || bytes % 2 != 0 {
        unsafe {
            RegCloseKey(key);
        }
        return Err("Обнаружена запись прежней установки, но её расположение недоступно. Установка остановлена, чтобы не затронуть данные.".into());
    }
    let mut buffer = vec![0u16; (bytes as usize / 2) + 1];
    let status = unsafe {
        RegGetValueW(
            key,
            ptr::null(),
            name.as_ptr(),
            RRF_RT_REG_SZ,
            ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    unsafe {
        RegCloseKey(key);
    }
    if status != 0 {
        return Err(format!(
            "Не удалось прочитать путь прежней установки (код {status})."
        ));
    }
    let end = buffer.iter().position(|u| *u == 0).unwrap_or(buffer.len());
    let raw = OsString::from_wide(&buffer[..end]);
    let text = raw.to_string_lossy();
    let path = PathBuf::from(text.trim().trim_matches('"'));
    if path.as_os_str().is_empty() {
        return Err("Путь прежней установки пуст. Установка остановлена.".into());
    }
    Ok(Some(path))
}

fn existing_installation() -> Result<Option<PathBuf>, String> {
    let user = registry_location(HKEY_CURRENT_USER)?;
    let machine = registry_location(HKEY_LOCAL_MACHINE)?;
    if machine.is_some() {
        return Err("Обнаружена общесистемная установка UmbraNet. Этот тестовый установщик не изменяет её автоматически.".into());
    }
    Ok(user)
}

/// The Evergreen WebView2 Runtime is normally registered by Microsoft Edge Update.
pub fn webview2_available() -> bool {
    for (hive, key) in [
        (
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
        ),
        (
            HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
        ),
    ] {
        let key = wide(OsStr::new(key));
        let value = wide(OsStr::new("pv"));
        let mut buffer = [0u16; 128];
        let mut bytes = (buffer.len() * 2) as u32;
        let result = unsafe {
            RegGetValueW(
                hive,
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ,
                ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        if result == 0 {
            let end = buffer.iter().position(|v| *v == 0).unwrap_or(buffer.len());
            let version = String::from_utf16_lossy(&buffer[..end]);
            if !version.is_empty() && version != "0.0.0.0" {
                return true;
            }
        }
    }
    false
}

pub fn suggested_path() -> Result<String, String> {
    if let Some(path) = existing_installation()? {
        match fs::metadata(&path) {
            Ok(meta) if meta.is_dir() => return Ok(path.to_string_lossy().into_owned()),
            Ok(_) => {
                return Err(
                    "Путь прежней установки указывает не на папку. Установка остановлена.".into(),
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("Не удалось проверить прежнюю папку: {error}")),
        }
    }
    Ok(known_folder(&FOLDERID_Desktop)
        .map(|desktop| desktop.join("UmbraNet_WiFi").to_string_lossy().into_owned())
        .unwrap_or_default())
}

fn validate_path(value: &str) -> Result<PathBuf, String> {
    if value.trim() != value
        || value.is_empty()
        || value.chars().any(|c| c == '"' || c.is_control())
    {
        return Err("Укажите корректный абсолютный путь без кавычек и переносов строк.".into());
    }
    // NSIS accepts /D= as a raw command-line remainder. Do not allow switches, quotes, UNC, or relative components.
    let path = PathBuf::from(value);
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_)))
        || !matches!(components.next(), Some(Component::RootDir))
        || components
            .clone()
            .any(|c| !matches!(c, Component::Normal(_)))
        || value.encode_utf16().count() > 200
    {
        return Err(
            "Выберите локальную папку на диске без '..'; путь должен быть короче 201 символа."
                .into(),
        );
    }
    Ok(path)
}

/// Resolve a selected location to a dedicated app directory, retaining old custom install paths.
pub fn resolved_path(value: &str) -> Result<String, String> {
    let previous = existing_installation()?;
    Ok(resolve_path(value, previous.as_deref())?
        .to_string_lossy()
        .into_owned())
}

fn known_folder(id: &windows_sys::core::GUID) -> Option<PathBuf> {
    let mut value = ptr::null_mut();
    let status = unsafe { SHGetKnownFolderPath(id, 0, ptr::null_mut(), &mut value) };
    if status < 0 || value.is_null() {
        return None;
    }
    let mut len = 0;
    unsafe {
        while len < 32768 && *value.add(len) != 0 {
            len += 1;
        }
    }
    let result = if len < 32768 {
        Some(PathBuf::from(OsString::from_wide(unsafe {
            std::slice::from_raw_parts(value, len)
        })))
    } else {
        None
    };
    unsafe {
        CoTaskMemFree(value.cast());
    }
    result
}

fn is_shared_location(path: &Path) -> bool {
    if path.parent().is_none() {
        return true;
    }
    for id in [
        &FOLDERID_Desktop,
        &FOLDERID_PublicDesktop,
        &FOLDERID_Documents,
        &FOLDERID_Downloads,
    ] {
        if let Some(known) = known_folder(id) {
            if path
                .to_string_lossy()
                .eq_ignore_ascii_case(&known.to_string_lossy())
                || (path.is_dir() && known.is_dir() && same_path(path, &known).unwrap_or(false))
            {
                return true;
            }
        }
    }
    false
}

fn resolve_path(value: &str, previous: Option<&Path>) -> Result<PathBuf, String> {
    let path = validate_path(value)?;
    let is_previous = previous.is_some_and(|old| {
        old.to_string_lossy()
            .eq_ignore_ascii_case(&path.to_string_lossy())
            || (path.is_dir() && old.is_dir() && same_path(&path, old).unwrap_or(false))
    });
    let is_app_dir = path
        .file_name()
        .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("UmbraNet_WiFi"));
    let result = if !is_shared_location(&path) && (is_previous || is_app_dir) {
        path
    } else {
        path.join("UmbraNet_WiFi")
    };
    if result.as_os_str().encode_wide().count() > 200 {
        return Err("Итоговый путь к папке UmbraNet_WiFi слишком длинный.".into());
    }
    Ok(result)
}

fn same_path(a: &Path, b: &Path) -> Result<bool, String> {
    let a =
        fs::canonicalize(a).map_err(|e| format!("Не удалось проверить папку установки: {e}"))?;
    let b = fs::canonicalize(b)
        .map_err(|e| format!("Не удалось проверить прежнюю папку установки: {e}"))?;
    Ok(a.to_string_lossy()
        .eq_ignore_ascii_case(&b.to_string_lossy()))
}

struct InstallLock(windows_sys::Win32::Foundation::HANDLE);
impl InstallLock {
    fn acquire() -> Result<Self, String> {
        let name = wide(OsStr::new("Local\\UmbraNetWifiInstallerGuard"));
        let handle = unsafe { CreateMutexW(ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err("Не удалось проверить, не идёт ли другая установка.".into());
        }
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            unsafe {
                CloseHandle(handle);
            }
            return Err("Установка UmbraNet уже выполняется.".into());
        }
        Ok(Self(handle))
    }
}
impl Drop for InstallLock {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

struct TempDir(PathBuf);
impl TempDir {
    fn create() -> Result<Self, String> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir();
        for _ in 0..20 {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let dir = base.join(format!(
                "UmbraNet-setup-{}-{now}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&dir) {
                Ok(()) => return Ok(Self(dir)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("Не удалось подготовить установку: {e}")),
            }
        }
        Err("Не удалось подготовить временную папку установки.".into())
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join("backend-setup.exe"));
        let _ = fs::remove_dir(&self.0);
    }
}

fn stage_payload(payload: &[u8]) -> Result<(TempDir, PathBuf), String> {
    let temp = TempDir::create()?;
    let file = temp.0.join("backend-setup.exe");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&file)
        .map_err(|e| format!("Не удалось подготовить установщик: {e}"))?;
    output
        .write_all(payload)
        .and_then(|_| output.sync_all())
        .map_err(|e| format!("Не удалось подготовить файлы установщика: {e}"))?;
    drop(output);
    Ok((temp, file))
}

/// Interactive NSIS fallback when WebView2 is missing; no silent changes without consent.
pub fn run_classic_fallback(payload: &[u8]) -> Result<(), String> {
    let _lock = InstallLock::acquire()?;
    let (_temp, file) = stage_payload(payload)?;
    let status = Command::new(file)
        .status()
        .map_err(|e| format!("Не удалось открыть резервный установщик: {e}"))?;
    if !status.success() {
        return Err("Резервный установщик был закрыт или завершился с ошибкой.".into());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PreviousState {
    MissingFolder,
    ReinstallHere,
    IncompleteElsewhere,
}

fn confirm_reinstall(old: &Path, state: PreviousState) -> bool {
    let message = match state {
        PreviousState::MissingFolder => format!("Обнаружена прежняя установка, но её папка не найдена:\n{}\n\nУстановить заново в выбранную пустую папку и обновить запись Windows? Старые файлы и стратегии не удаляются.", old.display()),
        PreviousState::ReinstallHere => format!("Обнаружена прежняя установка:\n{}\n\nПереустановить программу в эту папку? Файлы приложения будут заменены. Ваши стратегии, настройки и логи останутся на месте. Перед продолжением закройте UmbraNet.", old.display()),
        PreviousState::IncompleteElsewhere => format!("В прежней папке:\n{}\nпрограмма и файл удаления не найдены.\n\nУстановить в выбранную новую папку? Старые файлы не будут удалены, но стратегии и настройки останутся в прежней папке и автоматически не перенесутся. Запись Windows будет обновлена.", old.display()),
    };
    let text = wide(OsStr::new(&message));
    let title = wide(OsStr::new("UmbraNet: прежняя установка не найдена"));
    unsafe {
        MessageBoxW(
            ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND,
        ) == IDYES
    }
}

pub fn install(path: &str, shortcuts: bool, payload: &[u8]) -> Result<PathBuf, String> {
    install_with_confirmation(path, shortcuts, payload, confirm_reinstall)
}

fn install_with_confirmation(
    path: &str,
    shortcuts: bool,
    payload: &[u8],
    confirm_reinstall: impl Fn(&Path, PreviousState) -> bool,
) -> Result<PathBuf, String> {
    let _lock = InstallLock::acquire()?;
    let registered = existing_installation()?;
    let target = resolve_path(path, registered.as_deref())?;
    let mut previous = match registered {
        Some(old) => match fs::metadata(&old) {
            Ok(meta) if meta.is_dir() => Some(old),
            Ok(_) => {
                return Err(
                    "Путь прежней установки указывает не на папку. Установка остановлена.".into(),
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Missing on a disconnected drive must not be mistaken for a removed installation.
                let mut parts = old.components();
                let drive = match (parts.next(), parts.next()) {
                    (Some(Component::Prefix(prefix)), Some(Component::RootDir))
                        if matches!(prefix.kind(), Prefix::Disk(_)) =>
                    {
                        PathBuf::from(prefix.as_os_str()).join("\\")
                    }
                    _ => {
                        return Err(
                            "Путь прежней установки некорректен. Установка остановлена.".into()
                        )
                    }
                };
                if !drive.is_dir() {
                    return Err(format!("Диск прежней установки недоступен ({}). Подключите его и повторите попытку.", drive.display()));
                }
                if !confirm_reinstall(&old, PreviousState::MissingFolder) {
                    return Err(
                        "Установка отменена: прежняя папка не найдена. Данные не изменены.".into(),
                    );
                }
                None
            }
            Err(error) => {
                return Err(format!(
                    "Не удалось проверить прежнюю папку установки: {error}. Данные не изменены."
                ))
            }
        },
        None => None,
    };
    if let Some(old) = previous.as_ref() {
        let same = target.is_dir() && same_path(&target, old)?;
        if !same {
            // A different destination is permitted only when neither app executable remains.
            // Do not delete or silently transfer any data from the previous directory.
            let exists = |name: &str| {
                old.join(name)
                    .try_exists()
                    .map_err(|e| format!("Не удалось проверить прежнюю установку: {e}"))
            };
            if exists("umbranet-wifi.exe")? || exists("uninstall.exe")? {
                return Err("UmbraNet уже установлен в другой папке. Для сохранения данных выберите прежнюю папку: автоматический перенос установленной программы пока не поддерживается.".into());
            }
            if !confirm_reinstall(old, PreviousState::IncompleteElsewhere) {
                return Err("Установка отменена. Прежние файлы не изменены.".into());
            }
            previous = None;
        }
    }
    fs::create_dir_all(&target).map_err(|e| {
        format!("Не удалось создать папку установки: {e}. Выберите доступную для записи папку.")
    })?;
    if let Some(old) = previous {
        if !same_path(&target, &old)? {
            return Err("UmbraNet уже установлен в другой папке. Для сохранения стратегий и настроек выберите прежнюю папку: автоматический перенос пока не поддерживается.".into());
        }
        if !confirm_reinstall(&old, PreviousState::ReinstallHere) {
            return Err("Переустановка отменена. Файлы не изменены.".into());
        }
    } else if fs::read_dir(&target)
        .map_err(|e| format!("Не удалось проверить папку: {e}"))?
        .next()
        .is_some()
    {
        return Err(
            "Выберите пустую папку: установщик не перезаписывает неизвестные файлы.".into(),
        );
    }
    let (_temp, file) = stage_payload(payload)?;
    let mut process = Command::new(&file);
    process.arg("/S");
    if !shortcuts {
        process.arg("/NS");
    }
    // NSIS requires /D= to be the final raw, unquoted remainder, including spaces.
    process.raw_arg(format!("/D={}", target.display()));
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    process.creation_flags(CREATE_NO_WINDOW);
    let status = process
        .status()
        .map_err(|e| format!("Не удалось запустить установку: {e}"))?;
    if !status.success() {
        return Err(format!("Установка завершилась с ошибкой (код {}). Проверьте доступ к папке и закройте UmbraNet перед повтором.", status.code().map(|x| x.to_string()).unwrap_or_else(|| "неизвестен".into())));
    }
    for file in [
        "umbranet-wifi.exe",
        "uninstall.exe",
        "core/dpi/driver/WinDivert.dll",
        "core/dpi/driver/WinDivert64.sys",
        "strtegs_Uz/pass-through.json",
    ] {
        if !target.join(file).is_file() {
            return Err(format!(
                "Установщик завершился, но необходимый файл отсутствует: {file}."
            ));
        }
    }
    Ok(target)
}

pub fn open(path: &Path) -> Result<(), String> {
    let path = wide(path.as_os_str());
    let operation = wide(OsStr::new("open"));
    let result = unsafe {
        ShellExecuteW(
            ptr::null_mut(),
            operation.as_ptr(),
            path.as_ptr(),
            ptr::null(),
            ptr::null(),
            SW_SHOWNORMAL,
        )
    } as isize;
    if result <= 32 {
        return Err(format!("Не удалось открыть объект (код {result})."));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paths_must_be_local_and_resolve_to_a_dedicated_directory() {
        assert!(validate_path(r"C:\UmbraNet").is_ok());
        assert!(validate_path(r"D:\Program Files\UmbraNet").is_ok());
        assert_eq!(
            resolve_path(r"C:\", None).unwrap(),
            PathBuf::from(r"C:\UmbraNet_WiFi")
        );
        assert_eq!(
            resolve_path(r"C:\Users\test\Desktop", None).unwrap(),
            PathBuf::from(r"C:\Users\test\Desktop\UmbraNet_WiFi")
        );
        assert_eq!(
            resolve_path(r"C:\Users\test\Desktop\UmbraNet_WiFi", None).unwrap(),
            PathBuf::from(r"C:\Users\test\Desktop\UmbraNet_WiFi")
        );
        assert_eq!(
            resolve_path(r"C:\OldApp", Some(Path::new(r"C:\OldApp"))).unwrap(),
            PathBuf::from(r"C:\OldApp")
        );
        for invalid in [
            r"C:relative",
            r"\\server\share\app",
            r"C:\a\..\b",
            "C:\\a\" /S",
            "",
        ] {
            assert!(validate_path(invalid).is_err(), "{invalid}");
        }
    }

    // Explicitly enabled only on an isolated GitHub Windows runner, never on an end user's machine.
    #[test]
    fn ci_real_backend_install_reinstall_and_uninstall() {
        if std::env::var_os("UMBRA_INSTALLER_SMOKE").as_deref() != Some(OsStr::new("1")) {
            return;
        }
        assert!(
            existing_installation().unwrap().is_none(),
            "runner must have no prior UmbraNet installation"
        );
        let target = std::env::temp_dir()
            .join(format!("Umbra Test {} с пробелом", std::process::id()))
            .join("UmbraNet_WiFi");
        assert!(!target.exists());
        fs::create_dir_all(&target).unwrap();
        let sentinel = target.join("existing-user-file.txt");
        fs::write(&sentinel, b"do not overwrite").unwrap();
        static PAYLOAD: &[u8] = include_bytes!("../resources/backend-setup.exe");
        assert!(
            install_with_confirmation(&target.to_string_lossy(), false, PAYLOAD, |_, _| true)
                .is_err()
        );
        assert_eq!(fs::read(&sentinel).unwrap(), b"do not overwrite");
        fs::remove_file(sentinel).unwrap();
        install_with_confirmation(&target.to_string_lossy(), false, PAYLOAD, |_, _| true).unwrap();
        let strategy = target.join("strtegs_Uz/pass-through.json");
        let custom = target.join("strtegs_Uz/custom.json");
        let selection = target.join("core/dpi/selection.json");
        fs::write(&strategy, b"user strategy").unwrap();
        fs::write(&custom, b"user custom").unwrap();
        fs::write(&selection, b"user selection").unwrap();
        install_with_confirmation(&target.to_string_lossy(), false, PAYLOAD, |_, _| true).unwrap();
        assert_eq!(fs::read(&strategy).unwrap(), b"user strategy");
        assert_eq!(fs::read(&custom).unwrap(), b"user custom");
        assert_eq!(fs::read(&selection).unwrap(), b"user selection");
        fs::remove_file(target.join("umbranet-wifi.exe")).unwrap();
        fs::remove_file(target.join("uninstall.exe")).unwrap();
        assert!(install_with_confirmation(
            &target.to_string_lossy(),
            false,
            PAYLOAD,
            |_, state| {
                assert_eq!(state, PreviousState::ReinstallHere);
                false
            }
        )
        .is_err());
        assert!(!target.join("umbranet-wifi.exe").exists());
        assert_eq!(fs::read(&custom).unwrap(), b"user custom");
        install_with_confirmation(&target.to_string_lossy(), false, PAYLOAD, |_, state| {
            assert_eq!(state, PreviousState::ReinstallHere);
            true
        })
        .unwrap();
        assert_eq!(fs::read(&strategy).unwrap(), b"user strategy");
        assert_eq!(fs::read(&custom).unwrap(), b"user custom");
        assert_eq!(fs::read(&selection).unwrap(), b"user selection");
        let mut uninstall = Command::new(target.join("uninstall.exe"));
        uninstall
            .arg("/S")
            .raw_arg(format!("_?={}", target.display()))
            .creation_flags(0x08000000);
        assert!(uninstall.status().unwrap().success());
        assert_eq!(fs::read(&strategy).unwrap(), b"user strategy");
        assert_eq!(fs::read(&custom).unwrap(), b"user custom");
        assert_eq!(fs::read(&selection).unwrap(), b"user selection");
        assert!(!target.join("umbranet-wifi.exe").exists());
        fs::remove_dir_all(&target).unwrap();

        // An incomplete old folder with user data may be kept while installing to a new location.
        assert!(existing_installation().unwrap().is_none());
        let original = std::env::temp_dir()
            .join(format!("Umbra-old-{}", std::process::id()))
            .join("UmbraNet_WiFi");
        fs::create_dir_all(original.join("strtegs_Uz")).unwrap();
        let keep = original.join("strtegs_Uz/custom.json");
        fs::write(&keep, b"keep original").unwrap();
        let key = format!(r"HKCU\{}", UNINSTALL_KEY);
        assert!(Command::new("reg.exe")
            .args(["add", &key, "/v", "InstallLocation", "/t", "REG_SZ", "/d"])
            .arg(&original)
            .arg("/f")
            .status()
            .unwrap()
            .success());
        let new = std::env::temp_dir()
            .join(format!("Umbra-new-{}", std::process::id()))
            .join("UmbraNet_WiFi");
        assert!(!new.exists());
        assert!(
            install_with_confirmation(&new.to_string_lossy(), false, PAYLOAD, |_, state| {
                assert_eq!(state, PreviousState::IncompleteElsewhere);
                false
            })
            .is_err()
        );
        assert!(!new.exists());
        assert_eq!(fs::read(&keep).unwrap(), b"keep original");
        install_with_confirmation(&new.to_string_lossy(), false, PAYLOAD, |_, state| {
            assert_eq!(state, PreviousState::IncompleteElsewhere);
            true
        })
        .unwrap();
        assert_eq!(fs::read(&keep).unwrap(), b"keep original");
        let mut uninstall = Command::new(new.join("uninstall.exe"));
        uninstall
            .arg("/S")
            .raw_arg(format!("_?={}", new.display()))
            .creation_flags(0x08000000);
        assert!(uninstall.status().unwrap().success());
        fs::remove_dir_all(&new).unwrap();
        fs::remove_dir_all(&original).unwrap();

        // Simulate a stale registration on the isolated runner. The prior folder does not exist.
        assert!(existing_installation().unwrap().is_none());
        let missing = std::env::temp_dir().join(format!("Umbra-missing-{}", std::process::id()));
        assert!(!missing.exists());
        let key = format!(r"HKCU\{}", UNINSTALL_KEY);
        let status = Command::new("reg.exe")
            .args(["add", &key, "/v", "InstallLocation", "/t", "REG_SZ", "/d"])
            .arg(&missing)
            .args(["/f"])
            .status()
            .unwrap();
        assert!(status.success());
        let target = std::env::temp_dir()
            .join(format!("Umbra-stale-test-{}", std::process::id()))
            .join("UmbraNet_WiFi");
        assert!(!target.exists());
        assert!(install_with_confirmation(
            &target.to_string_lossy(),
            false,
            PAYLOAD,
            |old, state| {
                assert_eq!(state, PreviousState::MissingFolder);
                assert_eq!(old, missing);
                false
            }
        )
        .is_err());
        assert!(!target.exists(), "cancel must not create the destination");
        assert_eq!(
            existing_installation().unwrap().as_deref(),
            Some(missing.as_path())
        );
        fs::create_dir_all(&target).unwrap();
        let sentinel = target.join("do-not-overwrite.txt");
        fs::write(&sentinel, b"keep").unwrap();
        assert!(
            install_with_confirmation(&target.to_string_lossy(), false, PAYLOAD, |_, _| true)
                .is_err()
        );
        assert_eq!(fs::read(&sentinel).unwrap(), b"keep");
        assert_eq!(
            existing_installation().unwrap().as_deref(),
            Some(missing.as_path())
        );
        fs::remove_file(sentinel).unwrap();
        install_with_confirmation(&target.to_string_lossy(), false, PAYLOAD, |_, _| true).unwrap();
        assert_eq!(
            existing_installation().unwrap().as_deref(),
            Some(target.as_path())
        );
        assert!(!missing.exists());
        let mut uninstall = Command::new(target.join("uninstall.exe"));
        uninstall
            .arg("/S")
            .raw_arg(format!("_?={}", target.display()))
            .creation_flags(0x08000000);
        assert!(uninstall.status().unwrap().success());
        fs::remove_dir_all(&target).unwrap();
    }
}
