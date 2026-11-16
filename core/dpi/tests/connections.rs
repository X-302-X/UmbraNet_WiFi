use umbranet_dpi::{
    flow::tracker::{FlowKey, Transport},
    traffic::{
        application::Evidence,
        connections::{Config, Connections, Error, Token},
        stream::StreamError,
    },
};

fn key(port: u16, protocol: Transport) -> FlowKey {
    FlowKey::new(
        format!("192.0.2.1:{port}").parse().unwrap(),
        "198.51.100.2:443".parse().unwrap(),
        protocol,
    )
    .unwrap()
}
fn config(slots: usize) -> Config {
    Config::new(slots, 128, 10, 30, 5).unwrap()
}
fn ready(table: &mut Connections, key: &FlowKey, now: u64) -> Token {
    let t = table.open(key.clone(), 100, now).unwrap();
    table.syn_ack(key, t, 500, 101, now).unwrap();
    table.client_ack(key, t, 101, 501, now).unwrap();
    t
}

#[test]
fn handshake_and_segmented_http_in_two_independent_flows() {
    let mut c = Connections::new(config(2));
    let a = key(30001, Transport::Tcp);
    let b = key(30002, Transport::Tcp);
    let first = c.open(a.clone(), 100, 1).unwrap();
    assert_eq!(c.payload(&a, first, 101, b"", 1), Err(Error::WrongState));
    assert_eq!(c.evidence(&a, first, 1), Err(Error::WrongState));
    c.syn_ack(&a, first, 500, 101, 2).unwrap();
    c.syn_ack(&a, first, 500, 101, 2).unwrap(); // identical retransmission
    c.client_ack(&a, first, 101, 501, 3).unwrap();
    let second = ready(&mut c, &b, 3);
    let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    c.payload(&a, first, 111, &data[10..], 4).unwrap();
    assert_eq!(c.evidence(&a, first, 4), Ok(Evidence::Unknown));
    c.payload(&a, first, 101, &data[..10], 5).unwrap();
    assert_eq!(
        c.evidence(&a, first, 5),
        Ok(Evidence::HttpHost("example.com".into()))
    );
    assert_eq!(c.evidence(&b, second, 5), Ok(Evidence::Unknown));
}

#[test]
fn invalid_ack_quarantines_and_no_new_data_can_enter() {
    let mut c = Connections::new(config(1));
    let k = key(30001, Transport::Tcp);
    let t = c.open(k.clone(), 100, 1).unwrap();
    assert_eq!(c.syn_ack(&k, t, 500, 999, 2), Err(Error::InvalidHandshake));
    assert_eq!(c.open(k.clone(), 200, 2), Err(Error::KeyBusy));
    assert_eq!(c.evidence(&k, t, 2), Err(Error::NotFound));
    c.sweep(7).unwrap();
    let next = c.open(k.clone(), 200, 7).unwrap();
    c.syn_ack(&k, next, 600, 201, 7).unwrap();
    assert_eq!(
        c.client_ack(&k, next, 201, 999, 7),
        Err(Error::InvalidHandshake)
    );
    assert_eq!(c.payload(&k, next, 201, b"x", 7), Err(Error::NotFound));
}

#[test]
fn conflicting_syn_ack_and_prefix_fail_closed() {
    let mut c = Connections::new(config(2));
    let a = key(30001, Transport::Tcp);
    let b = key(30002, Transport::Tcp);
    let t = c.open(a.clone(), 100, 1).unwrap();
    c.syn_ack(&a, t, 500, 101, 1).unwrap();
    assert_eq!(c.syn_ack(&a, t, 501, 101, 1), Err(Error::InvalidHandshake));
    let u = ready(&mut c, &b, 1);
    c.payload(&b, u, 101, b"abc", 2).unwrap();
    assert_eq!(
        c.payload(&b, u, 102, b"X", 2),
        Err(Error::Prefix(StreamError::ConflictingOverlap))
    );
    assert_eq!(c.evidence(&b, u, 2), Err(Error::NotFound));
    assert_eq!(c.open(b, 100, 2), Err(Error::KeyBusy));
}

#[test]
fn closing_and_quarantine_reject_stale_token_after_reuse() {
    let mut c = Connections::new(config(1));
    let k = key(30001, Transport::Tcp);
    let old = ready(&mut c, &k, 1);
    c.close(&k, old, 2).unwrap();
    assert_eq!(c.open(k.clone(), 200, 6), Err(Error::KeyBusy));
    let new = c.open(k.clone(), 200, 7).unwrap();
    assert_ne!(old, new);
    assert_eq!(c.close(&k, old, 7), Err(Error::StaleToken));
    assert_eq!(c.payload(&k, old, 101, b"old", 7), Err(Error::StaleToken));
    c.syn_ack(&k, new, 600, 201, 7).unwrap();
    c.client_ack(&k, new, 201, 601, 7).unwrap();
    assert_eq!(c.evidence(&k, new, 7), Ok(Evidence::Unknown));
}

#[test]
fn idle_and_absolute_lifetime_are_bounded_and_need_sweep() {
    let mut c = Connections::new(config(2));
    let a = key(30001, Transport::Tcp);
    let b = key(30002, Transport::Tcp);
    let t = ready(&mut c, &a, 0);
    c.payload(&a, t, 101, b"x", 9).unwrap();
    c.payload(&a, t, 102, b"y", 18).unwrap();
    c.payload(&a, t, 103, b"z", 27).unwrap();
    assert_eq!(c.evidence(&a, t, 30), Err(Error::NotFound)); // absolute lifetime
    let u = ready(&mut c, &b, 30);
    c.payload(&b, u, 101, b"", 39).unwrap(); // empty payload doesn't extend idle
    assert_eq!(c.evidence(&b, u, 40), Err(Error::NotFound));
    assert_eq!(c.slots_used(), 1); // first quarantine expired, second now held
    c.sweep(45).unwrap();
    assert_eq!(c.slots_used(), 0);
}

#[test]
fn capacity_never_evicts_live_or_quarantined_entries() {
    let mut c = Connections::new(config(1));
    let a = key(30001, Transport::Tcp);
    let b = key(30002, Transport::Tcp);
    let t = ready(&mut c, &a, 1);
    assert_eq!(c.open(b.clone(), 9, 2), Err(Error::Capacity));
    assert_eq!(c.evidence(&a, t, 2), Ok(Evidence::Unknown));
    c.close(&a, t, 3).unwrap();
    assert_eq!(c.open(b.clone(), 9, 7), Err(Error::Capacity));
    assert!(c.open(b, 9, 8).is_ok());
}

#[test]
fn bad_time_and_loss_disable_until_new_session_without_token_reuse() {
    let mut c = Connections::new(config(1));
    let k = key(30001, Transport::Tcp);
    let old = ready(&mut c, &k, 20);
    assert_eq!(c.sweep(19), Err(Error::ClockWentBackwards));
    assert_eq!(c.slots_used(), 0);
    assert_eq!(c.open(k.clone(), 1, 21), Err(Error::Unavailable));
    c.reset();
    let new = ready(&mut c, &k, 0);
    assert_ne!(old, new);
    assert_eq!(c.close(&k, old, 0), Err(Error::StaleToken));
    c.invalidate();
    assert!(!c.is_available());
    assert_eq!(c.evidence(&k, new, 0), Err(Error::Unavailable));
}

#[test]
fn validates_configuration_protocol_and_wrapped_handshake() {
    assert!(matches!(
        Config::new(0, 1, 1, 1, 1),
        Err(Error::InvalidConfig)
    ));
    assert!(matches!(
        Config::new(4097, 1, 1, 1, 1),
        Err(Error::InvalidConfig)
    ));
    assert!(matches!(
        Config::new(4096, 65536, 1, 1, 1),
        Err(Error::InvalidConfig)
    ));
    assert!(matches!(
        Config::new(1, 1, 0, 1, 1),
        Err(Error::InvalidConfig)
    ));
    let mut c = Connections::new(config(1));
    assert_eq!(
        c.open(key(30001, Transport::Udp), 1, 0),
        Err(Error::InvalidProtocol)
    );
    let k = key(30001, Transport::Tcp);
    let t = c.open(k.clone(), u32::MAX, 0).unwrap();
    c.syn_ack(&k, t, u32::MAX, 0, 0).unwrap();
    c.client_ack(&k, t, 0, 0, 0).unwrap();
    c.payload(&k, t, 0, b"x", 0).unwrap();
    assert_eq!(c.evidence(&k, t, 0), Ok(Evidence::Unknown));
}

#[test]
fn unexpected_early_data_and_duplicate_open_close_active_flow() {
    let mut c = Connections::new(config(2));
    let a = key(30001, Transport::Tcp);
    let b = key(30002, Transport::Tcp);
    let t = c.open(a.clone(), 10, 0).unwrap();
    assert_eq!(c.payload(&a, t, 11, b"x", 0), Err(Error::WrongState));
    assert_eq!(c.syn_ack(&a, t, 50, 11, 0), Err(Error::NotFound));
    let u = ready(&mut c, &b, 0);
    assert_eq!(c.open(b.clone(), 100, 1), Err(Error::KeyBusy));
    assert_eq!(c.evidence(&b, u, 1), Err(Error::NotFound));
}
