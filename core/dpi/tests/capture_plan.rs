use umbranet_dpi::{
    capture::CapturePlan, catalog::Catalog, selection::Selection, strategy::Strategy,
};
fn inputs() -> (Catalog, Strategy) {
    (
        Catalog::from_json(include_str!("../services.json")).unwrap(),
        Strategy::from_json(include_str!("../../../strtegs_Uz/pass-through.json")).unwrap(),
    )
}
#[test]
fn empty_selection_does_not_produce_capture_plan() {
    let (catalog, strategy) = inputs();
    let s = Selection::default();
    assert!(CapturePlan::from_snapshot(&s.snapshot(&catalog, &strategy).unwrap()).is_none());
}
#[test]
fn discord_card_enables_voice_diagnostics_in_snapshot_only() {
    let (catalog, strategy) = inputs();
    let mut s = Selection::default();
    s.set_service(&catalog, "youtube", true).unwrap();
    let old = CapturePlan::from_snapshot(&s.snapshot(&catalog, &strategy).unwrap()).unwrap();
    assert!(!old.includes_discord_voice());
    assert!(!old.filter().contains("19294"));
    for p in ["80", "443", "2053", "2083", "2087", "2096", "8443"] {
        assert!(old.filter().contains(&format!("tcp.DstPort == {p}")));
    }
    s.set_service(&catalog, "discord", true).unwrap();
    let new = CapturePlan::from_snapshot(&s.snapshot(&catalog, &strategy).unwrap()).unwrap();
    assert!(new.includes_discord_voice());
    assert!(!old.includes_discord_voice());
    for p in ["19294", "19344", "50000", "65535"] {
        assert!(new.filter().contains(p));
    }
    s.set_service(&catalog, "discord", false).unwrap();
    assert!(
        !CapturePlan::from_snapshot(&s.snapshot(&catalog, &strategy).unwrap())
            .unwrap()
            .includes_discord_voice()
    );
}
#[test]
fn discord_process_enables_voice_diagnostics_but_other_process_does_not() {
    let (catalog, strategy) = inputs();
    let mut s = Selection::default();
    s.add_process("other.exe").unwrap();
    assert!(
        !CapturePlan::from_snapshot(&s.snapshot(&catalog, &strategy).unwrap())
            .unwrap()
            .includes_discord_voice()
    );
    s.add_process("Discord.exe").unwrap();
    assert!(
        CapturePlan::from_snapshot(&s.snapshot(&catalog, &strategy).unwrap())
            .unwrap()
            .includes_discord_voice()
    );
}
#[test]
fn manually_entered_discord_domain_does_not_guess_the_voice_service() {
    let (catalog, strategy) = inputs();
    let mut s = Selection::default();
    s.add_domain("discord.com").unwrap();
    assert!(
        !CapturePlan::from_snapshot(&s.snapshot(&catalog, &strategy).unwrap())
            .unwrap()
            .includes_discord_voice()
    );
}
