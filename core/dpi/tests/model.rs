use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use umbranet_dpi::{
    catalog::Catalog,
    domain::{domain_matches, normalize_domain},
    selection::Selection,
    strategy::Strategy,
};

fn catalog() -> Catalog {
    Catalog::from_json(include_str!("../services.json")).unwrap()
}
fn strategy() -> Strategy {
    Strategy::from_json(include_str!("../../../strtegs_Uz/pass-through.json")).unwrap()
}

#[test]
fn catalog_covers_all_25_ui_services() {
    let catalog = catalog();
    assert_eq!(catalog.services.len(), 25);
    assert!(catalog.services["discord"]
        .domains
        .contains(&"discord.com".to_string()));
    assert!(catalog.services["youtube"]
        .domains
        .contains(&"googlevideo.com".to_string()));
}

#[test]
fn manual_domain_in_active_list_and_snapshot() {
    let mut s = Selection::default();
    s.add_domain(" EXAMPLE.com. ").unwrap();
    assert!(s
        .active_domains(&catalog())
        .unwrap()
        .contains("example.com"));
    assert!(s
        .snapshot(&catalog(), &strategy())
        .unwrap()
        .domains
        .contains("example.com"));
}

#[test]
fn shared_domains_survive_unselecting_service() {
    let c = Catalog::from_json(r#"{"version":1,"services":{"a":{"name":"A","domains":["shared.example","a.example"]},"b":{"name":"B","domains":["shared.example"]}}}"#).unwrap();
    let mut s = Selection::default();
    s.set_service(&c, "a", true).unwrap();
    s.set_service(&c, "b", true).unwrap();
    s.set_service(&c, "a", false).unwrap();
    let domains = s.active_domains(&c).unwrap();
    assert!(domains.contains("shared.example"));
    assert!(!domains.contains("a.example"));
}

#[test]
fn manual_domain_survives_unselecting_service() {
    let c = catalog();
    let mut s = Selection::default();
    s.add_domain("discord.com").unwrap();
    s.set_service(&c, "discord", true).unwrap();
    s.set_service(&c, "discord", false).unwrap();
    assert_eq!(
        s.active_domains(&c)
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>(),
        ["discord.com"]
    );
}

#[test]
fn snapshot_is_independent_of_later_edits_and_strategy() {
    let c = catalog();
    let mut s = Selection::default();
    s.set_service(&c, "discord", true).unwrap();
    let mut st = strategy();
    let running = s.snapshot(&c, &st).unwrap();
    s.set_service(&c, "discord", false).unwrap();
    s.add_domain("example.org").unwrap();
    s.add_process("Discord.exe").unwrap();
    st.name = "Changed".into();
    assert!(running.domains.contains("discord.com"));
    assert!(!running.domains.contains("example.org"));
    assert!(running.services.contains("discord"));
    assert!(running.manual_processes.is_empty());
    assert_ne!(running.strategy.name, st.name);
    let restarted = s.snapshot(&c, &st).unwrap();
    assert!(!restarted.domains.contains("discord.com"));
    assert!(restarted.domains.contains("example.org"));
    assert!(restarted.manual_processes.contains("discord.exe"));
}

#[test]
fn browsers_are_protected_but_not_universal_process_targets() {
    let mut s = Selection::default();
    for name in ["chrome.exe", "msedge.exe", "firefox.exe"] {
        assert!(s.visible_processes().contains(name));
        assert!(s.remove_process(name).is_err());
        s.add_process(name).unwrap();
    }
    assert!(s
        .snapshot(&catalog(), &strategy())
        .unwrap()
        .manual_processes
        .is_empty());
    s.add_process("Discord.exe").unwrap();
    assert!(s
        .snapshot(&catalog(), &strategy())
        .unwrap()
        .manual_processes
        .contains("discord.exe"));
    assert!(s.remove_process("DISCORD.EXE").unwrap());
}

#[test]
fn invalid_domains_rejected() {
    for d in [
        "",
        "example",
        "*.example.com",
        "https://example.com/",
        "example.com:443",
        "127.0.0.1",
        "::1",
        "a..com",
        "example.com..",
        "-a.com",
        "тест.рф",
    ] {
        assert!(normalize_domain(d).is_err(), "{d}");
    }
    assert_eq!(
        normalize_domain("WWW.Example.COM.").unwrap(),
        "www.example.com"
    );
    assert!(normalize_domain("xn--e1afmkfd.xn--p1ai").is_ok());
}

#[test]
fn matching_only_at_label_boundaries() {
    assert!(domain_matches("example.com", "sub.example.com"));
    assert!(domain_matches("example.com", "EXAMPLE.COM."));
    assert!(!domain_matches("example.com", "notexample.com"));
    assert!(!domain_matches("example.com", "example.com.evil.org"));
}

#[test]
fn invalid_process_names_rejected() {
    let mut s = Selection::default();
    for name in [
        "",
        ".exe",
        "foo",
        "C:\\foo.exe",
        "foo/bar.exe",
        "*.exe",
        "bad?.exe",
    ] {
        assert!(s.add_process(name).is_err(), "{name}");
    }
}

#[test]
fn unknown_services_and_strategy_actions_fail_closed() {
    let mut s = Selection::default();
    assert!(s.set_service(&catalog(), "missing", true).is_err());
    assert!(
        Strategy::from_json(r#"{"version":1,"id":"x","name":"x","actions":["fake"]}"#).is_err()
    );
    assert!(Strategy::from_json(r#"{"version":1,"id":"x","name":"x","actions":["pass_through"],"args":["--dpi-desync=fake"]}"#).is_err());
    assert!(
        Strategy::from_json(r#"{"version":2,"id":"x","name":"x","actions":["pass_through"]}"#)
            .is_err()
    );
}

#[test]
fn writes_current_active_file_without_changing_snapshot() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "umbra-dpi-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&dir).unwrap();
    let path = dir.join("active-domains.txt");
    let c = catalog();
    let mut s = Selection::default();
    s.add_domain("old.example").unwrap();
    s.write_active_domains(&c, &path).unwrap();
    let snapshot = s.snapshot(&c, &strategy()).unwrap();
    s.remove_domain("old.example").unwrap();
    s.add_domain("new.example").unwrap();
    s.write_active_domains(&c, &path).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), "new.example\n");
    assert!(snapshot.domains.contains("old.example"));
    assert!(!snapshot.domains.contains("new.example"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn invalid_catalog_is_rejected() {
    assert!(Catalog::from_json(r#"{"version":2,"services":{}}"#).is_err());
    assert!(Catalog::from_json(
        r#"{"version":1,"services":{"x":{"name":"X","domains":["*.example.com"]}}}"#
    )
    .is_err());
}

#[test]
fn every_catalog_id_matches_a_ui_service() {
    let html = include_str!("../../../ui/index.html");
    for id in catalog().services.keys() {
        assert!(
            html.contains(&format!("data-service=\"{id}\"")),
            "Missing UI service: {id}"
        );
    }
}

#[test]
fn failed_publication_to_missing_directory_leaves_existing_file_alone() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "umbra-dpi-fail-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&dir).unwrap();
    let path = dir.join("active-domains.txt");
    fs::write(&path, "previous.example\n").unwrap();
    let mut s = Selection::default();
    s.add_domain("new.example").unwrap();
    assert!(s
        .write_active_domains(&catalog(), &dir.join("missing").join("active.txt"))
        .is_err());
    assert_eq!(fs::read_to_string(path).unwrap(), "previous.example\n");
    fs::remove_dir_all(dir).unwrap();
}
