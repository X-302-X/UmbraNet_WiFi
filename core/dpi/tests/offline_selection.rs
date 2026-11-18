use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use umbranet_dpi::{
    flow::tracker::{FlowKey, Transport},
    store::Store,
    strategy::Strategy,
    traffic::{
        classifier::Match,
        connections::{Config, Connections, Error},
    },
};
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "umbra-flow-plan-{}-{}",
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
fn key(port: u16) -> FlowKey {
    FlowKey::new(
        format!("192.0.2.1:{port}").parse().unwrap(),
        "198.51.100.1:443".parse().unwrap(),
        Transport::Tcp,
    )
    .unwrap()
}
fn strategy() -> Strategy {
    Strategy::from_json(r#"{"version":1,"id":"pass","name":"Pass","actions":["pass_through"]}"#)
        .unwrap()
}
fn table() -> Connections {
    Connections::new(Config::new(4, 1024, 10, 30, 5).unwrap())
}

#[test]
fn snapshot_matches_only_contiguous_prefix_after_handshake() {
    let dir = Temp::new();
    let mut store = Store::open(&dir.0).unwrap();
    store.apply("add_domain", "selected.example", true).unwrap();
    store.apply("add_process", "client.exe", true).unwrap();
    let plan = store.prepare_session(&strategy()).unwrap();
    store
        .apply("remove_domain", "selected.example", false)
        .unwrap();
    store.apply("add_domain", "new.example", true).unwrap();
    let mut c = table();
    let k = key(50000);
    let t = c.open(k.clone(), 100, 1).unwrap();
    assert_eq!(
        plan.offline_tcp_candidate(&mut c, &k, t, 1),
        Err(Error::WrongState)
    );
    c.syn_ack(&k, t, 500, 101, 2).unwrap();
    c.client_ack(&k, t, 101, 501, 3).unwrap();
    let data = b"GET / HTTP/1.1\r\nHost: sub.selected.example\r\n\r\n";
    c.payload(&k, t, 111, &data[10..], 4).unwrap();
    assert_eq!(
        plan.offline_tcp_candidate(&mut c, &k, t, 4),
        Ok(Match::Unknown)
    );
    c.payload(&k, t, 101, &data[..10], 5).unwrap();
    assert_eq!(
        plan.offline_tcp_candidate(&mut c, &k, t, 5),
        Ok(Match::Domain("selected.example".into()))
    );
    assert_eq!(
        store
            .prepare_session(&strategy())
            .unwrap()
            .offline_tcp_candidate(&mut c, &k, t, 5),
        Ok(Match::Unknown)
    );
}

#[test]
fn evidence_is_revoked_on_conflict_close_timeout_and_stale_token() {
    let dir = Temp::new();
    let mut store = Store::open(&dir.0).unwrap();
    store.apply("add_domain", "selected.example", true).unwrap();
    let plan = store.prepare_session(&strategy()).unwrap();
    let mut c = table();
    let k = key(50000);
    let old = c.open(k.clone(), 100, 1).unwrap();
    c.syn_ack(&k, old, 500, 101, 1).unwrap();
    c.client_ack(&k, old, 101, 501, 1).unwrap();
    c.payload(
        &k,
        old,
        101,
        b"GET / HTTP/1.1\r\nHost: selected.example\r\n\r\n",
        2,
    )
    .unwrap();
    assert!(matches!(
        plan.offline_tcp_candidate(&mut c, &k, old, 2),
        Ok(Match::Domain(_))
    ));
    assert!(c.payload(&k, old, 101, b"X", 3).is_err());
    assert_eq!(
        plan.offline_tcp_candidate(&mut c, &k, old, 3),
        Err(Error::NotFound)
    );
    let new = c.open(k.clone(), 200, 8).unwrap();
    assert_eq!(
        plan.offline_tcp_candidate(&mut c, &k, old, 8),
        Err(Error::StaleToken)
    );
    c.syn_ack(&k, new, 600, 201, 8).unwrap();
    c.client_ack(&k, new, 201, 601, 8).unwrap();
    assert_eq!(
        plan.offline_tcp_candidate(&mut c, &k, new, 8),
        Ok(Match::Unknown)
    );
    assert_eq!(
        plan.offline_tcp_candidate(&mut c, &k, new, 18),
        Err(Error::NotFound)
    );
}

#[test]
fn unknown_unselected_and_ambiguous_http_never_become_process_matches() {
    let dir = Temp::new();
    let mut store = Store::open(&dir.0).unwrap();
    store.apply("add_domain", "selected.example", true).unwrap();
    store.apply("add_process", "client.exe", true).unwrap();
    let plan = store.prepare_session(&strategy()).unwrap();
    for (n, data) in [
        b"GET / HTTP/1.1\r\nHost: unselected.example\r\n\r\n".as_slice(),
        b"GET / HTTP/1.1\r\nHost: selected.example\r\nHost: other.example\r\n\r\n",
        b"not a request",
    ]
    .iter()
    .enumerate()
    {
        let mut c = table();
        let k = key(50000 + n as u16);
        let t = c.open(k.clone(), 100, 1).unwrap();
        c.syn_ack(&k, t, 500, 101, 1).unwrap();
        c.client_ack(&k, t, 101, 501, 1).unwrap();
        c.payload(&k, t, 101, data, 2).unwrap();
        assert_eq!(
            plan.offline_tcp_candidate(&mut c, &k, t, 2),
            Ok(Match::Unknown)
        );
    }
}

#[test]
fn ech_outer_name_remains_unknown_after_handshake_and_buffering() {
    let dir = Temp::new();
    let mut store = Store::open(&dir.0).unwrap();
    store.apply("add_domain", "selected.example", true).unwrap();
    let plan = store.prepare_session(&strategy()).unwrap();
    let host = b"selected.example";
    let mut names = vec![0, 0, host.len() as u8];
    names.extend_from_slice(host);
    let mut sni = (names.len() as u16).to_be_bytes().to_vec();
    sni.extend_from_slice(&names);
    let mut ext = vec![0, 0];
    ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sni);
    ext.extend_from_slice(&[0xfe, 0x0d, 0, 1, 0]);
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0; 32]);
    body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    let mut hello = vec![1, 0, 0, body.len() as u8];
    hello.extend_from_slice(&body);
    let mut record = vec![22, 3, 1];
    record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    record.extend_from_slice(&hello);
    let mut c = table();
    let k = key(50000);
    let t = c.open(k.clone(), 100, 1).unwrap();
    c.syn_ack(&k, t, 500, 101, 1).unwrap();
    c.client_ack(&k, t, 101, 501, 1).unwrap();
    c.payload(&k, t, 101, &record, 2).unwrap();
    assert_eq!(
        plan.offline_tcp_candidate(&mut c, &k, t, 2),
        Ok(Match::Unknown)
    );
    c.invalidate();
    assert_eq!(
        plan.offline_tcp_candidate(&mut c, &k, t, 3),
        Err(Error::Unavailable)
    );
}
