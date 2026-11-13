use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use umbranet_dpi::{layout::AppPaths, store::Store};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "umbra-layout-{}-{}",
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
fn release_layout_is_inside_data_and_separate_from_source_tree() {
    let temp = Temp::new();
    let paths = AppPaths::new(&temp.0);
    assert_eq!(paths.dpi_dir(), temp.0.join("data/core/dpi"));
    assert_eq!(paths.legacy_dpi_dir(), temp.0.join("core/dpi"));
    assert_eq!(
        paths.driver_dll(),
        temp.0.join("data/core/dpi/driver/WinDivert.dll")
    );
    let view = Store::open_portable(&temp.0).unwrap().view().unwrap();
    assert!(view.services.is_empty());
    assert!(paths.dpi_dir().join("services.json").exists());
    assert!(!paths.legacy_dpi_dir().exists());
}

#[test]
fn migrates_selection_and_custom_catalog_without_touching_old_or_driver() {
    let temp = Temp::new();
    let paths = AppPaths::new(&temp.0);
    let legacy = paths.legacy_dpi_dir();
    let mut old = Store::open(&legacy).unwrap();
    old.apply("service", "discord", true).unwrap();
    old.apply("add_domain", "manual.example", true).unwrap();
    old.apply("add_process", "myapp.exe", true).unwrap();
    drop(old);
    let saved = fs::read(legacy.join("selection.json")).unwrap();
    let catalog_text = fs::read_to_string(legacy.join("services.json"))
        .unwrap()
        .replace("discord.com", "customdiscord.example");
    fs::write(legacy.join("services.json"), &catalog_text).unwrap();
    let catalog = fs::read(legacy.join("services.json")).unwrap();
    fs::create_dir_all(legacy.join("driver")).unwrap();
    fs::write(legacy.join("driver/WinDivert.dll"), b"not copied").unwrap();
    let view = Store::open_portable(&temp.0).unwrap().view().unwrap();
    assert!(view.services.contains("discord"));
    assert!(view.active_domains.contains("customdiscord.example"));
    assert!(view.domains.contains("manual.example"));
    assert!(view.processes.contains("myapp.exe"));
    assert_eq!(fs::read(legacy.join("selection.json")).unwrap(), saved);
    assert_eq!(
        fs::read(paths.dpi_dir().join("selection.json")).unwrap(),
        saved
    );
    assert_eq!(
        fs::read(paths.dpi_dir().join("services.json")).unwrap(),
        catalog
    );
    assert!(legacy.join("driver/WinDivert.dll").exists());
    assert!(!paths.driver_dll().exists());
    assert!(
        fs::read_to_string(paths.dpi_dir().join("active-domains.txt"))
            .unwrap()
            .contains("manual.example")
    );
}

#[test]
fn existing_new_files_are_never_overwritten_or_reimported() {
    let temp = Temp::new();
    let paths = AppPaths::new(&temp.0);
    let mut old = Store::open(&paths.legacy_dpi_dir()).unwrap();
    old.apply("service", "discord", true).unwrap();
    let mut current = Store::open_portable(&temp.0).unwrap();
    current.apply("service", "discord", false).unwrap();
    current.apply("add_domain", "new.example", true).unwrap();
    drop(current);
    let view = Store::open_portable(&temp.0).unwrap().view().unwrap();
    assert!(!view.services.contains("discord"));
    assert!(view.domains.contains("new.example"));
    assert!(old.view().unwrap().services.contains("discord"));
}

#[test]
fn damaged_legacy_selection_is_not_erased_or_replaced_with_empty() {
    let temp = Temp::new();
    let paths = AppPaths::new(&temp.0);
    fs::create_dir_all(paths.legacy_dpi_dir()).unwrap();
    fs::write(paths.legacy_dpi_dir().join("selection.json"), b"invalid").unwrap();
    assert!(Store::open_portable(&temp.0).is_err());
    assert_eq!(
        fs::read(paths.legacy_dpi_dir().join("selection.json")).unwrap(),
        b"invalid"
    );
    assert_eq!(
        fs::read(paths.dpi_dir().join("selection.json")).unwrap(),
        b"invalid"
    );
}

#[test]
fn existing_destination_remains_preferred_even_if_legacy_is_unreadable() {
    let temp = Temp::new();
    let paths = AppPaths::new(&temp.0);
    let mut store = Store::open_portable(&temp.0).unwrap();
    store.apply("add_domain", "new.example", true).unwrap();
    drop(store);
    fs::create_dir_all(paths.legacy_dpi_dir().join("selection.json")).unwrap();
    assert!(Store::open_portable(&temp.0)
        .unwrap()
        .view()
        .unwrap()
        .domains
        .contains("new.example"));
}

#[test]
fn legacy_read_failure_does_not_silently_create_empty_selection() {
    let temp = Temp::new();
    let paths = AppPaths::new(&temp.0);
    fs::create_dir_all(paths.legacy_dpi_dir().join("selection.json")).unwrap();
    assert!(Store::open_portable(&temp.0).is_err());
    assert!(!paths.dpi_dir().join("selection.json").exists());
}
