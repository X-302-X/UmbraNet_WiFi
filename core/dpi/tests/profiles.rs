use umbranet_dpi::engine::Engine;
use umbranet_dpi::profiles::Profiles;
use umbranet_dpi::strategy::{Action, Strategy};
use umbranet_dpi::traffic::filter::{HostList, IpSet};

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("umbranet-profiles-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(dir: &std::path::Path, file: &str, body: &str) {
    std::fs::write(dir.join(file), body).unwrap();
}

#[test]
fn loads_sorts_and_selects_profiles() {
    let dir = temp_dir("load");
    write(
        &dir,
        "b.json",
        r#"{"version":1,"id":"b-profile","name":"B","actions":["pass_through"]}"#,
    );
    write(
        &dir,
        "a.json",
        r#"{"version":1,"id":"a-profile","name":"A","actions":[{"disorder":{"positions":["sld"]}}]}"#,
    );
    // Не JSON и не стратегия — игнорируются / вызывают ошибку только при разборе .json
    write(&dir, "notes.txt", "ignore me");

    let profiles = Profiles::load(&dir).unwrap();
    let list = profiles.list();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].id, "a-profile");

    assert_eq!(profiles.selected_id(), None);
    let selected = profiles.ensure_selected().unwrap();
    assert_eq!(
        selected, None,
        "без pass-through активный профиль не выбирается автоматически"
    );
    assert_eq!(profiles.selected_id(), None);

    profiles.select("b-profile").unwrap();
    assert_eq!(profiles.selected_id().as_deref(), Some("b-profile"));
    assert!(profiles.select("missing").is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rejects_duplicate_ids_and_broken_json() {
    let dir = temp_dir("dup");
    let body = r#"{"version":1,"id":"same","name":"S","actions":["pass_through"]}"#;
    write(&dir, "1.json", body);
    write(&dir, "2.json", body);
    assert!(Profiles::load(&dir).is_err());
    let _ = std::fs::remove_dir_all(&dir);

    let dir = temp_dir("broken");
    write(&dir, "bad.json", "{ not json");
    assert!(Profiles::load(&dir).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn udp_fake_action_is_parsed() {
    let json = r#"{
        "version": 1,
        "id": "voice",
        "name": "Voice",
        "actions": [
            { "udp_fake": { "repeats": 7, "fooling": [{ "ttl": 2 }, "bad_sum", { "bad_seq": -1000 }] } }
        ]
    }"#;
    let strategy = Strategy::from_json(json).unwrap();
    let (repeats, fooling) = strategy.udp_fake().expect("udp_fake must be present");
    assert_eq!(repeats, 7);
    // bad_seq для UDP отбрасывается
    assert_eq!(fooling.len(), 2);
    assert!(matches!(strategy.actions[0], Action::UdpFake { .. }));
    // TCP-план при этом пустой, но не паникует
    let plan = strategy.to_desync_plan(None);
    assert!(plan.splits.is_empty());
    assert!(!plan.fake);
}

#[test]
fn engine_passes_through_foreign_traffic() {
    let strategy =
        Strategy::from_json(r#"{"version":1,"id":"p","name":"P","actions":["pass_through"]}"#)
            .unwrap();
    let mut engine = Engine::new(strategy, HostList::default(), IpSet::default());

    // IPv4 TCP 443 с payload
    let mut raw = vec![0u8; 20 + 20 + 5];
    raw[0] = 0x45;
    let total = raw.len() as u16;
    raw[2..4].copy_from_slice(&total.to_be_bytes());
    raw[8] = 64;
    raw[9] = 6;
    raw[12..16].copy_from_slice(&[192, 168, 1, 10]);
    raw[16..20].copy_from_slice(&[1, 1, 1, 1]);
    raw[20..22].copy_from_slice(&50000u16.to_be_bytes());
    raw[22..24].copy_from_slice(&443u16.to_be_bytes());
    raw[32] = 0x50;
    raw[33] = 0x18;

    let out = engine.process_packet(&raw, true);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0], raw);
}

#[test]
fn hostlist_and_ipset_filtering() {
    let list = HostList::from_lines(["youtube.com", ".discord.com", "# comment", ""]);
    assert!(list.matches("youtube.com"));
    assert!(list.matches("www.youtube.com"));
    assert!(list.matches("gateway.discord.com"));
    assert!(!list.matches("notyoutube.com"));
    assert!(!list.matches("discord.com.evil.net"));

    let set = IpSet::from_lines(["142.250.0.0/16", "2a00:1450::/32", "8.8.8.8", "bad"]);
    assert!(set.contains("142.250.74.14".parse().unwrap()));
    assert!(!set.contains("142.251.74.14".parse().unwrap()));
    assert!(set.contains("8.8.8.8".parse().unwrap()));
    assert!(set.contains("2a00:1450::1".parse().unwrap()));
    assert!(!set.contains("2a00:1451::1".parse().unwrap()));
}

#[test]
fn safe_default_is_pass_through_and_existing_selection_is_preserved() {
    let dir = temp_dir("safe-default");
    write(
        &dir,
        "a.json",
        r#"{"version":1,"id":"aaa-active","name":"Active","actions":[{"disorder":{"positions":["sld"]}}]}"#,
    );
    write(
        &dir,
        "pass-through.json",
        r#"{"version":1,"id":"pass-through","name":"Safe","actions":["pass_through"]}"#,
    );
    let p = Profiles::load(&dir).unwrap();
    assert_eq!(
        p.ensure_selected().unwrap().as_deref(),
        Some("pass-through")
    );
    p.select("aaa-active").unwrap();
    assert_eq!(p.ensure_selected().unwrap().as_deref(), Some("aaa-active"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pass_through_name_does_not_make_active_strategy_safe() {
    let dir = temp_dir("fake-safe");
    write(
        &dir,
        "evil.json",
        r#"{"version":1,"id":"pass-through","name":"Not safe","actions":[{"disorder":{"positions":["sld"]}}]}"#,
    );
    let p = Profiles::load(&dir).unwrap();
    assert_eq!(p.ensure_selected().unwrap(), None);
    let _ = std::fs::remove_dir_all(&dir);
}
