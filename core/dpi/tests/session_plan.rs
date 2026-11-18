use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use umbranet_dpi::{
    autohostlist::AutoHostList,
    store::Store,
    strategy::{Action, Strategy},
};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "umbra-plan-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn strategy() -> Strategy {
    Strategy::from_json(r#"{"version":1,"id":"split","name":"Split","actions":[{"disorder":{"positions":["sld"]}}]}"#).unwrap()
}
fn packet(host: &str) -> Vec<u8> {
    let payload = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
    let mut p = vec![0; 40 + payload.len()];
    let len = p.len() as u16;
    p[0] = 0x45;
    p[2..4].copy_from_slice(&len.to_be_bytes());
    p[8] = 64;
    p[9] = 6;
    p[12..16].copy_from_slice(&[192, 0, 2, 1]);
    p[16..20].copy_from_slice(&[203, 0, 113, 1]);
    p[20..22].copy_from_slice(&50000u16.to_be_bytes());
    p[22..24].copy_from_slice(&443u16.to_be_bytes());
    p[32] = 0x50;
    p[33] = 0x18;
    p[40..].copy_from_slice(payload.as_bytes());
    p
}

#[test]
fn empty_and_invalid_strategy_fail_closed() {
    let dir = Temp::new();
    let mut store = Store::open(&dir.0).unwrap();
    assert!(store.prepare_session(&strategy()).is_err());
    store.apply("add_domain", "example.com", true).unwrap();
    let mut invalid = strategy();
    invalid.version = 2;
    assert!(store.prepare_session(&invalid).is_err());
}

#[test]
fn snapshot_is_independent_of_selection_and_strategy_changes() {
    let dir = Temp::new();
    let mut store = Store::open(&dir.0).unwrap();
    store.apply("add_domain", "Example.COM.", true).unwrap();
    let mut selected = strategy();
    let plan = store.prepare_session(&selected).unwrap();
    selected.id = "other".into();
    selected.actions = vec![Action::PassThrough];
    store.apply("remove_domain", "example.com", false).unwrap();
    store.apply("add_domain", "other.example", true).unwrap();
    let next = store.prepare_session(&selected).unwrap();
    assert_eq!(plan.strategy().id, "split");
    assert_eq!(next.strategy().id, "other");
    assert!(plan.matches_domain("sub.example.com"));
    assert!(!plan.matches_domain("notexample.com"));
    assert!(!plan.matches_domain("other.example"));
    assert!(next.matches_domain("other.example"));
    assert!(!next.matches_domain("example.com"));
}

#[test]
fn service_and_process_choices_are_preserved_and_known_limits_fail_closed() {
    let dir = Temp::new();
    let mut store = Store::open(&dir.0).unwrap();
    store.apply("service", "discord", true).unwrap();
    store.apply("add_process", "Custom.EXE", true).unwrap();
    let plan = store.prepare_session(&strategy()).unwrap();
    assert!(plan.services().contains("discord"));
    assert!(plan.matches_domain("discord.com"));
    assert!(plan.manual_processes().contains("custom.exe"));
    assert!(plan.service_processes()["discord"].contains("discord.exe"));
    assert!(plan.check_known_limits().is_err());
    assert!(plan.make_offline_engine(None).is_err());
    store.apply("service", "discord", false).unwrap();
    store.apply("remove_process", "custom.exe", false).unwrap();
    assert!(plan.services().contains("discord"));
    assert!(store.prepare_session(&strategy()).is_err());
}

#[test]
fn process_only_and_udp_strategy_are_explicitly_unsupported() {
    let dir = Temp::new();
    let mut store = Store::open(&dir.0).unwrap();
    store.apply("add_process", "client.exe", true).unwrap();
    assert!(store
        .prepare_session(&strategy())
        .unwrap()
        .check_known_limits()
        .is_err());
    store.apply("remove_process", "client.exe", false).unwrap();
    store.apply("add_domain", "example.com", true).unwrap();
    let udp = Strategy::from_json(include_str!("../../../strtegs_Uz/quic-bypass.json")).unwrap();
    assert!(store
        .prepare_session(&udp)
        .unwrap()
        .check_known_limits()
        .is_err());
    assert!(store
        .prepare_session(&strategy())
        .unwrap()
        .check_known_limits()
        .is_ok());
}

#[test]
fn offline_engine_uses_frozen_hostlist_and_not_automatic_list() {
    let dir = Temp::new();
    let mut store = Store::open(&dir.0).unwrap();
    store.apply("add_domain", "selected.example", true).unwrap();
    let plan = store.prepare_session(&strategy()).unwrap();
    store
        .apply("remove_domain", "selected.example", false)
        .unwrap();
    store.apply("add_domain", "new.example", true).unwrap();
    let mut auto = AutoHostList::load(&dir.0);
    auto.record("unselected.example");
    let mut engine = plan.make_offline_engine(Some(auto)).unwrap();
    for host in ["unselected.example", "new.example", "notselected.example"] {
        let raw = packet(host);
        assert_eq!(engine.process_packet(&raw, true), vec![raw]);
    }
    assert!(
        engine
            .process_packet(&packet("selected.example"), true)
            .len()
            > 1
    );
}

#[test]
fn active_file_write_failure_blocks_preparation() {
    let dir = Temp::new();
    let mut store = Store::open(&dir.0).unwrap();
    fs::remove_file(dir.0.join("active-domains.txt")).unwrap();
    fs::create_dir(dir.0.join("active-domains.txt")).unwrap();
    assert!(store
        .apply("add_domain", "example.com", true)
        .unwrap()
        .warning
        .is_some());
    assert!(store.prepare_session(&strategy()).is_err());
}

#[test]
fn youtube_service_snapshot_contains_only_selected_service_and_manual_domains() {
    let dir = Temp::new();
    let mut store = Store::open(&dir.0).unwrap();
    store.apply("service", "youtube", true).unwrap();
    store.apply("add_domain", "custom.example", true).unwrap();
    let plan = store.prepare_session(&strategy()).unwrap();
    assert!(plan.services().contains("youtube"));
    assert!(plan.matches_domain("youtube.com"));
    assert!(plan.matches_domain("custom.example"));
    assert!(!plan.matches_domain("discord.com"));
    store.apply("service", "youtube", false).unwrap();
    assert!(plan.matches_domain("youtube.com"));
    assert!(!store
        .prepare_session(&strategy())
        .unwrap()
        .matches_domain("youtube.com"));
}
