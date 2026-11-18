#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn active_open_is_blocked_before_filter_or_library_access() {
    use std::{io::ErrorKind, path::Path};
    use umbranet_dpi::capture::windivert::DivertChannel;

    // Обе ошибки сработали бы позже guard: NUL в фильтре и отсутствующая DLL.
    let error = match DivertChannel::open(Path::new("missing/WinDivert.dll"), "bad\0filter") {
        Ok(_) => panic!("активное открытие должно быть заблокировано"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("временно отключён"));
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn missing_library_fails_without_opening_driver() {
    use umbranet_dpi::{
        capture::{windivert::Sniffer, CapturePlan},
        catalog::Catalog,
        selection::Selection,
        strategy::Strategy,
    };
    let catalog = Catalog::from_json(include_str!("../services.json")).unwrap();
    let strategy =
        Strategy::from_json(include_str!("../../../strtegs_Uz/pass-through.json")).unwrap();
    let mut selection = Selection::default();
    selection.add_domain("example.com").unwrap();
    let plan =
        CapturePlan::from_snapshot(&selection.snapshot(&catalog, &strategy).unwrap()).unwrap();
    let path = std::env::temp_dir()
        .join(format!("missing-windivert-{}", std::process::id()))
        .join("WinDivert.dll");
    assert!(Sniffer::open(&path, &plan).is_err());
}
