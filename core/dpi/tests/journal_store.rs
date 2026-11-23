use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use umbranet_dpi::journal_store::JournalStore;

fn temp() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "umbra-journal-test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&dir).unwrap();
    dir
}
#[test]
fn batches_are_ordered_idempotent_and_saved_inside_logs() {
    let dir = temp();
    let mut j = JournalStore::new(&dir, false);
    let first = vec![
        r#"{"тип":"system","событие":"Запуск"}"#.to_string(),
        r#"{"тип":"error","событие":"ошибка 192.0.2.1"}"#.to_string(),
    ];
    assert!(j.append(2, first.clone()).is_err());
    j.append(1, first.clone()).unwrap();
    j.append(1, first.clone()).unwrap();
    assert!(j.append(1, vec!["{}".into()]).is_err());
    j.append(2, vec![r#"{"тип":"flow","событие":"процесс.exe"}"#.into()])
        .unwrap();
    let path = j.path().unwrap().to_owned();
    assert_eq!(path.parent().unwrap(), dir.join("logs"));
    let lines: Vec<_> = fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(String::from)
        .collect();
    assert_eq!(lines.len(), 3);
    assert!(lines[1].contains("192.0.2.1"));
    assert!(lines[2].contains("процесс.exe"));
    assert!(lines
        .iter()
        .all(|s| serde_json::from_str::<serde_json::Value>(s).is_ok()));
    drop(j);
    fs::remove_dir_all(dir).unwrap();
}
#[test]
fn invalid_records_and_inaccessible_folder_are_reported_without_acknowledging() {
    let dir = temp();
    let mut j = JournalStore::new(&dir, false);
    assert!(j.append(1, vec!["bad".into()]).is_err());
    assert!(j.path().is_none());
    fs::write(dir.join("logs"), "not a directory").unwrap();
    assert!(j.append(1, vec!["{}".into()]).is_err());
    fs::remove_file(dir.join("logs")).unwrap();
    j.append(1, vec!["{}".into()]).unwrap();
    drop(j);
    fs::remove_dir_all(dir).unwrap();
}
#[test]
fn separate_sessions_do_not_overwrite_each_other() {
    let dir = temp();
    let mut a = JournalStore::new(&dir, false);
    let mut b = JournalStore::new(&dir, false);
    a.append(1, vec![r#"{"value":1}"#.into()]).unwrap();
    b.append(1, vec![r#"{"value":2}"#.into()]).unwrap();
    assert_ne!(a.path(), b.path());
    assert!(fs::read_to_string(a.path().unwrap()).unwrap().contains('1'));
    assert!(fs::read_to_string(b.path().unwrap()).unwrap().contains('2'));
    drop((a, b));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn prior_session_is_removed_only_after_new_log_is_safely_written() {
    let dir = temp();
    let mut old = JournalStore::new(&dir, false);
    old.append(1, vec![r#"{"value":"old"}"#.into()]).unwrap();
    let old_path = old.path().unwrap().to_owned();
    drop(old);
    let folder = dir.join("logs");
    fs::write(folder.join("1.txt"), "keep").unwrap();
    fs::write(folder.join("my-notes.txt"), "keep").unwrap();
    fs::write(folder.join("umbranet-session-not-numeric.jsonl"), "keep").unwrap();
    let mut next = JournalStore::new(&dir, true);
    assert!(next.cleanup_previous().is_err());
    assert!(old_path.exists());
    next.append(1, vec![r#"{"value":"new"}"#.into()]).unwrap();
    let new_path = next.path().unwrap().to_owned();
    next.cleanup_previous().unwrap();
    assert!(!old_path.exists());
    assert!(new_path.exists());
    for name in [
        "1.txt",
        "my-notes.txt",
        "umbranet-session-not-numeric.jsonl",
    ] {
        assert!(folder.join(name).exists());
    }
    drop(next);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn active_session_is_not_deleted_and_cleanup_can_retry() {
    let dir = temp();
    let mut old = JournalStore::new(&dir, false);
    old.append(1, vec!["{}".into()]).unwrap();
    let old_path = old.path().unwrap().to_owned();
    let mut next = JournalStore::new(&dir, true);
    next.append(1, vec!["{}".into()]).unwrap();
    assert!(next.cleanup_previous().is_err());
    assert!(old_path.exists());
    next.append(2, vec![r#"{"still":"recording"}"#.into()])
        .unwrap();
    drop(old);
    next.cleanup_previous().unwrap();
    assert!(!old_path.exists());
    assert!(fs::read_to_string(next.path().unwrap())
        .unwrap()
        .contains("recording"));
    drop(next);
    fs::remove_dir_all(dir).unwrap();
}
