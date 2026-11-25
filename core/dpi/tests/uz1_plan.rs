use umbranet_dpi::{
    strategy::{Action, LegacyUz1, Strategy},
    uz1_plan::{Asset, Protocol, Uz1Plan},
};

fn original() -> LegacyUz1 {
    let profile =
        Strategy::from_profile_json(include_str!("../../../strtegs_Uz/uz1.json")).unwrap();
    let [Action::LegacyUz1 { profile }] = profile.actions.as_slice() else {
        panic!("expected Uz1")
    };
    profile.clone()
}

#[test]
fn parses_original_sections_without_losing_order_or_duplicate_fake_tls() {
    let plan = Uz1Plan::parse(&original()).unwrap();
    assert_eq!(
        plan.capture_tcp_ports,
        [80, 443, 2053, 2083, 2087, 2096, 8443]
    );
    assert_eq!(plan.capture_udp_ports, [443]);
    assert_eq!(plan.sections.len(), 3);
    let a = &plan.sections[0];
    assert_eq!(a.protocol, Protocol::Udp);
    assert_eq!(a.ports, [443]);
    assert!(a.selected_hostlist && a.fake && !a.multisplit);
    assert_eq!(a.repeats, 11);
    assert_eq!(a.fake_quic, [Asset::GoogleQuic]);
    let b = &plan.sections[1];
    assert_eq!(b.protocol, Protocol::Tcp);
    assert_eq!(b.ports, [443]);
    assert!(b.selected_hostlist && b.ip_id_zero && b.fake && b.multisplit && b.fooling_ts);
    assert_eq!(
        (b.seq_overlap, b.split_pos, b.repeats),
        (Some(681), Some(1), 8)
    );
    assert_eq!(b.overlap_pattern, Some(Asset::GoogleTls));
    assert_eq!(b.fake_tls, [Asset::GoogleTls]);
    let c = &plan.sections[2];
    assert_eq!(c.protocol, Protocol::Tcp);
    assert_eq!(c.ports, [80, 443, 8443, 2053, 2083, 2087, 2096]);
    assert!(c.selected_hostlist && !c.ip_id_zero && c.fake && c.multisplit && c.fooling_ts);
    assert_eq!(
        (c.seq_overlap, c.split_pos, c.repeats),
        (Some(664), Some(1), 8)
    );
    assert_eq!(c.overlap_pattern, Some(Asset::MaxTls));
    assert_eq!(c.fake_tls, [Asset::Stun, Asset::MaxTls]);
    assert_eq!(c.fake_http, [Asset::MaxTls]);
    // We deliberately return both. Precedence and fake-tls duplicate behaviour
    // must not be guessed from similarly named Zapret flags.
    assert_eq!(plan.matching_sections(Protocol::Tcp, 443), [1, 2]);
    assert_eq!(plan.matching_sections(Protocol::Tcp, 80), [2]);
    assert_eq!(plan.matching_sections(Protocol::Udp, 443), [0]);
    assert!(plan.matching_sections(Protocol::Tcp, 22).is_empty());
}

#[test]
fn rejects_unknown_or_ambiguous_arguments_without_running_anything() {
    let source = original();
    for (find, replacement) in [
        ("--dpi-desync-fooling=ts", "--dpi-desync-fooling=unknown"),
        ("--dpi-desync-split-pos=1", "--dpi-desync-split-pos=0"),
        ("--dpi-desync-repeats=8", "--dpi-desync-repeats=255"),
        ("{hostlist}", "--hostlist=everything.txt"),
        ("--filter-tcp=443", "--filter-tcp=9999"),
        (
            "--dpi-desync-fake-tls={bin}\\tls_clienthello_www_google_com.bin",
            "--dpi-desync-fake-tls={bin}\\..\\arbitrary.bin",
        ),
        ("--new", "--new-other"),
    ] {
        let mut changed = source.clone();
        let arg = changed
            .args
            .iter_mut()
            .find(|arg| arg.as_str() == find)
            .unwrap();
        *arg = replacement.into();
        assert!(Uz1Plan::parse(&changed).is_err(), "accepted {replacement}");
    }
    let mut changed = source.clone();
    changed.args.push("--new".into());
    assert!(Uz1Plan::parse(&changed).is_err());
    let mut changed = source.clone();
    changed.args.insert(4, "--dpi-desync-repeats=8".into());
    assert!(Uz1Plan::parse(&changed).is_err());
    let mut changed = source.clone();
    changed.hostlist.push("unselected.example".into());
    assert!(Uz1Plan::parse(&changed).is_err());
}

#[test]
fn copied_fixture_payloads_have_expected_lengths_and_shapes() {
    let google = include_bytes!("fixtures/uz1/tls_clienthello_www_google_com.bin");
    let max = include_bytes!("fixtures/uz1/tls_clienthello_max_ru.bin");
    let stun = include_bytes!("fixtures/uz1/stun.bin");
    let quic = include_bytes!("fixtures/uz1/quic_initial_www_google_com.bin");
    assert_eq!(
        (google.len(), max.len(), stun.len(), quic.len()),
        (681, 664, 100, 1200)
    );
    assert_eq!(google[0], 0x16);
    assert_eq!(max[0], 0x16);
    // Payload files are fixtures only: no proof of network compatibility or source-engine semantics.
}
