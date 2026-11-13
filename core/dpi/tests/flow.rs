use std::net::SocketAddr;
use umbranet_dpi::flow::tracker::{
    same_process, Candidate, FlowKey, FlowTracker, ProcessIdentity, TrackerError, Transport,
};

fn key() -> FlowKey {
    FlowKey::new(
        "192.0.2.2:50001".parse().unwrap(),
        "198.51.100.4:443".parse().unwrap(),
        Transport::Tcp,
    )
    .unwrap()
}
fn pid(pid: u32, start: u64, name: &str) -> ProcessIdentity {
    ProcessIdentity::new(pid, start, name).unwrap()
}

#[test]
fn only_a_tentative_candidate_is_returned() {
    let mut tracker = FlowTracker::new(16, 100);
    let flow = key();
    let discord = pid(123, 50, "Discord.exe");
    assert_eq!(tracker.candidate(&flow, 10), Candidate::Unknown);
    tracker
        .established(flow.clone(), 99, discord.clone(), 10)
        .unwrap();
    assert_eq!(tracker.candidate(&flow, 11), Candidate::Tentative(discord));
    tracker.closed(&flow, 99, 12).unwrap();
    assert_eq!(tracker.candidate(&flow, 13), Candidate::Unknown);
}
#[test]
fn duplicate_tuple_is_ambiguous_even_for_the_same_process() {
    let mut t = FlowTracker::new(16, 100);
    let k = key();
    let p = pid(123, 50, "Discord.exe");
    t.established(k.clone(), 1, p.clone(), 10).unwrap();
    t.established(k.clone(), 2, p.clone(), 11).unwrap();
    assert_eq!(t.candidate(&k, 12), Candidate::Ambiguous);
    t.closed(&k, 2, 13).unwrap();
    assert_eq!(t.candidate(&k, 14), Candidate::Tentative(p));
}
#[test]
fn stale_colliding_flow_never_becomes_a_new_owner_by_expiry() {
    let mut t = FlowTracker::new(16, 10);
    let k = key();
    t.established(k.clone(), 1, pid(123, 50, "discord.exe"), 10)
        .unwrap();
    t.established(k.clone(), 2, pid(321, 51, "other.exe"), 18)
        .unwrap();
    assert_eq!(t.candidate(&k, 22), Candidate::Stale);
    assert_eq!(t.len(), 2);
}
#[test]
fn pid_reuse_and_different_image_do_not_match() {
    let old = pid(123, 50, "Discord.exe");
    assert!(same_process(&old, &pid(123, 50, "discord.exe")));
    assert!(!same_process(&old, &pid(123, 51, "discord.exe")));
    assert!(!same_process(&old, &pid(124, 50, "discord.exe")));
    assert!(!same_process(&old, &pid(123, 50, "other.exe")));
}
#[test]
fn out_of_order_or_unknown_close_disables_candidates() {
    let mut t = FlowTracker::new(16, 100);
    let k = key();
    t.established(k.clone(), 1, pid(123, 50, "discord.exe"), 10)
        .unwrap();
    assert_eq!(t.closed(&k, 1, 9), Err(TrackerError::OutOfOrder));
    assert_eq!(t.candidate(&k, 11), Candidate::Unavailable);
    t.reset();
    assert!(t.is_empty());
    assert!(t.is_available());
    assert_eq!(t.closed(&k, 1, 20), Err(TrackerError::UnknownClose));
    assert_eq!(t.candidate(&k, 21), Candidate::Unavailable);
}
#[test]
fn reaching_capacity_fails_closed_without_evicting_existing_flow() {
    let mut t = FlowTracker::new(1, 100);
    let k = key();
    t.established(k.clone(), 1, pid(123, 50, "discord.exe"), 10)
        .unwrap();
    assert_eq!(
        t.established(k.clone(), 2, pid(321, 51, "other.exe"), 11),
        Err(TrackerError::Capacity)
    );
    assert_eq!(t.len(), 1);
    assert_eq!(t.candidate(&k, 12), Candidate::Unavailable);
}
#[test]
fn conflicting_endpoint_is_not_silently_replaced() {
    let mut t = FlowTracker::new(3, 100);
    let k = key();
    t.established(k.clone(), 1, pid(123, 50, "discord.exe"), 10)
        .unwrap();
    t.established(k.clone(), 1, pid(123, 50, "discord.exe"), 11)
        .unwrap();
    assert_eq!(
        t.established(k.clone(), 1, pid(123, 99, "discord.exe"), 12),
        Err(TrackerError::EndpointConflict)
    );
    assert_eq!(t.candidate(&k, 13), Candidate::Unavailable);
}
#[test]
fn backwards_queries_and_old_flows_are_stale() {
    let mut t = FlowTracker::new(3, 10);
    let k = key();
    t.established(k.clone(), 1, pid(123, 50, "discord.exe"), 10)
        .unwrap();
    assert_eq!(t.candidate(&k, 9), Candidate::Stale);
    assert_eq!(t.candidate(&k, 21), Candidate::Stale);
}
#[test]
fn ipv4_mapped_ipv6_is_normalized_but_link_local_is_rejected() {
    let a = FlowKey::new(
        "[::ffff:192.0.2.2]:50001".parse().unwrap(),
        "[::ffff:198.51.100.4]:443".parse().unwrap(),
        Transport::Tcp,
    )
    .unwrap();
    assert_eq!(a, key());
    let link: SocketAddr = "[fe80::1]:5000".parse().unwrap();
    assert!(FlowKey::new(link, "[2001:db8::1]:443".parse().unwrap(), Transport::Tcp).is_none());
    assert!(FlowKey::new(
        "0.0.0.0:5000".parse().unwrap(),
        "192.0.2.1:443".parse().unwrap(),
        Transport::Udp
    )
    .is_none());
    assert!(FlowKey::new(
        "192.0.2.2:5000".parse().unwrap(),
        "198.51.100.4:0".parse().unwrap(),
        Transport::Udp
    )
    .is_none());
}
#[test]
fn invalid_process_identity_is_rejected() {
    for (p, start, name) in [
        (0, 1, "a.exe"),
        (1, 0, "a.exe"),
        (1, 1, "a"),
        (1, 1, "*.exe"),
        (1, 1, "C:\\a.exe"),
    ] {
        assert!(ProcessIdentity::new(p, start, name).is_none());
    }
}

#[test]
fn explicit_event_loss_invalidates_candidates_until_new_session() {
    let mut t = FlowTracker::new(3, 100);
    let k = key();
    t.established(k.clone(), 1, pid(123, 50, "discord.exe"), 10)
        .unwrap();
    t.invalidate();
    assert_eq!(t.candidate(&k, 11), Candidate::Unavailable);
    t.reset();
    assert_eq!(t.candidate(&k, 12), Candidate::Unknown);
}
