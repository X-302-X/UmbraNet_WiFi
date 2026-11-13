use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use umbranet_dpi::store::Store;

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "umbra-dpi-store-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn selection_persists_and_active_file_is_rebuilt() {
    let dir = Temp::new();
    let mut store = Store::open(&dir.0).unwrap();
    store.apply("service", "discord", true).unwrap();
    store.apply("add_domain", "Example.org", true).unwrap();
    store.apply("add_process", "Discord.exe", true).unwrap();
    fs::write(dir.0.join("active-domains.txt"), "stale.invalid\n").unwrap();
    drop(store);
    let store = Store::open(&dir.0).unwrap();
    let view = store.view().unwrap();
    assert!(view.services.contains("discord"));
    assert!(view.domains.contains("example.org"));
    assert!(view.processes.contains("discord.exe"));
    assert_eq!(view.protected_processes.len(), 3);
    let active = fs::read_to_string(dir.0.join("active-domains.txt")).unwrap();
    assert!(active.lines().any(|d| d == "discord.com"));
    assert!(active.lines().any(|d| d == "example.org"));
    assert!(!active.contains("stale.invalid"));
}

#[test]
fn invalid_action_does_not_change_saved_selection() {
    let dir = Temp::new();
    let mut store = Store::open(&dir.0).unwrap();
    store.apply("add_domain", "ok.example", true).unwrap();
    let saved = fs::read(dir.0.join("selection.json")).unwrap();
    assert!(store
        .apply("add_domain", "https://bad.example", true)
        .is_err());
    assert!(store.apply("remove_process", "CHROME.EXE", false).is_err());
    assert!(store.apply("service", "unknown", true).is_err());
    assert_eq!(fs::read(dir.0.join("selection.json")).unwrap(), saved);
}

#[test]
fn corrupt_selection_is_not_silently_overwritten() {
    let dir = Temp::new();
    fs::write(dir.0.join("selection.json"), "invalid json").unwrap();
    assert!(Store::open(&dir.0).is_err());
    assert_eq!(
        fs::read_to_string(dir.0.join("selection.json")).unwrap(),
        "invalid json"
    );
}

#[test]
fn active_file_failure_reports_warning_but_preserves_committed_selection() {
    let dir = Temp::new();
    let mut store = Store::open(&dir.0).unwrap();
    fs::remove_file(dir.0.join("active-domains.txt")).unwrap();
    fs::create_dir(dir.0.join("active-domains.txt")).unwrap();
    let view = store.apply("add_domain", "ok.example", true).unwrap();
    assert!(view.warning.is_some());
    assert!(view.domains.contains("ok.example"));
    fs::remove_dir(dir.0.join("active-domains.txt")).unwrap();
    drop(store);
    let restored = Store::open(&dir.0).unwrap().view().unwrap();
    assert!(restored.warning.is_none());
    assert!(restored.domains.contains("ok.example"));
}
