#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn current_process_identity_is_read_without_opening_a_driver() {
    use umbranet_dpi::flow::windows_process::current_process_info;
    let result = current_process_info(std::process::id()).unwrap();
    assert_eq!(result.pid(), std::process::id());
    assert_ne!(result.creation_id(), 0);
    assert!(result.image_name().ends_with(".exe"));
}
