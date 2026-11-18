use std::sync::{Arc, Barrier};
use umbranet_dpi::lifecycle::{Error, Lifecycle, Phase, StartOutcome, StopOutcome};

#[test]
fn start_stop_requires_cleanup_before_next_start() {
    let c = Lifecycle::new();
    let t = c.begin_start().unwrap();
    assert_eq!(c.phase(), Ok(Phase::Starting));
    assert_eq!(c.begin_start(), Err(Error::Busy));
    assert_eq!(c.complete_start(t), Ok(StartOutcome::RunningInModel));
    assert_eq!(c.request_stop(), Ok(StopOutcome::CleanupRequired(t)));
    assert_eq!(c.request_stop(), Ok(StopOutcome::WaitingForCleanup));
    assert_eq!(c.begin_start(), Err(Error::Busy));
    assert_eq!(c.worker_exited(t), Ok(StopOutcome::WaitingForCleanup));
    c.cleanup_complete(t, true).unwrap();
    assert_eq!(c.phase(), Ok(Phase::Idle));
    assert!(c.begin_start().is_ok());
}

#[test]
fn stop_during_start_cannot_publish_and_must_cleanup() {
    let c = Lifecycle::new();
    let t = c.begin_start().unwrap();
    assert_eq!(c.request_stop(), Ok(StopOutcome::WaitingForStart));
    assert_eq!(c.phase(), Ok(Phase::Cancelling));
    assert_eq!(c.complete_start(t), Ok(StartOutcome::CleanupRequired));
    assert_eq!(c.phase(), Ok(Phase::Stopping));
    assert_eq!(c.begin_start(), Err(Error::Busy));
    c.cleanup_complete(t, true).unwrap();
    assert_eq!(c.request_stop(), Ok(StopOutcome::AlreadyIdle));
}

#[test]
fn uncertain_cleanup_fail_closes_for_both_paths() {
    let c = Lifecycle::new();
    let t = c.begin_start().unwrap();
    c.start_failed(t, false).unwrap();
    assert_eq!(c.phase(), Ok(Phase::Faulted));
    assert_eq!(c.begin_start(), Err(Error::Faulted));
    assert_eq!(c.request_stop(), Ok(StopOutcome::Faulted));
    let c = Lifecycle::new();
    let t = c.begin_start().unwrap();
    c.complete_start(t).unwrap();
    c.request_stop().unwrap();
    c.cleanup_complete(t, false).unwrap();
    assert_eq!(c.begin_start(), Err(Error::Faulted));
}

#[test]
fn stale_callbacks_cannot_change_a_new_attempt() {
    let c = Lifecycle::new();
    let old = c.begin_start().unwrap();
    c.start_failed(old, true).unwrap();
    let new = c.begin_start().unwrap();
    assert_ne!(old, new);
    assert_eq!(c.complete_start(old), Err(Error::Stale));
    assert_eq!(c.start_failed(old, true), Err(Error::Stale));
    assert_eq!(c.phase(), Ok(Phase::Starting));
    c.complete_start(new).unwrap();
    assert_eq!(c.worker_exited(old), Err(Error::Stale));
    assert_eq!(c.request_stop(), Ok(StopOutcome::CleanupRequired(new)));
    assert_eq!(c.cleanup_complete(old, true), Err(Error::Stale));
    assert_eq!(c.phase(), Ok(Phase::Stopping));
    c.cleanup_complete(new, true).unwrap();
}

#[test]
fn failure_while_cancelling_and_worker_exit_are_accounted_for() {
    let c = Lifecycle::new();
    let t = c.begin_start().unwrap();
    c.request_stop().unwrap();
    c.start_failed(t, true).unwrap();
    let t = c.begin_start().unwrap();
    c.complete_start(t).unwrap();
    assert_eq!(c.worker_exited(t), Ok(StopOutcome::CleanupRequired(t)));
    assert_eq!(c.request_stop(), Ok(StopOutcome::WaitingForCleanup));
    c.cleanup_complete(t, true).unwrap();
}

#[test]
fn concurrent_start_has_exactly_one_winner() {
    let c = Arc::new(Lifecycle::new());
    let barrier = Arc::new(Barrier::new(17));
    let handles: Vec<_> = (0..16)
        .map(|_| {
            let c = c.clone();
            let b = barrier.clone();
            std::thread::spawn(move || {
                b.wait();
                c.begin_start()
            })
        })
        .collect();
    barrier.wait();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results.iter().filter(|r| **r == Err(Error::Busy)).count(),
        15
    );
    let t = results.into_iter().find_map(Result::ok).unwrap();
    c.start_failed(t, true).unwrap();
}

#[test]
fn concurrent_stop_and_finish_start_have_only_safe_model_transitions() {
    for _ in 0..100 {
        let c = Arc::new(Lifecycle::new());
        let t = c.begin_start().unwrap();
        let b = Arc::new(Barrier::new(3));
        let a = {
            let c = c.clone();
            let b = b.clone();
            std::thread::spawn(move || {
                b.wait();
                c.complete_start(t).unwrap()
            })
        };
        let s = {
            let c = c.clone();
            let b = b.clone();
            std::thread::spawn(move || {
                b.wait();
                c.request_stop().unwrap()
            })
        };
        b.wait();
        let a = a.join().unwrap();
        let s = s.join().unwrap();
        assert!(matches!(
            (a, s),
            (
                StartOutcome::RunningInModel,
                StopOutcome::CleanupRequired(_)
            ) | (StartOutcome::CleanupRequired, StopOutcome::WaitingForStart)
        ));
        assert_eq!(c.phase(), Ok(Phase::Stopping));
        assert_eq!(c.begin_start(), Err(Error::Busy));
        c.cleanup_complete(t, true).unwrap();
    }
}

#[test]
fn duplicate_events_in_the_wrong_phase_are_rejected() {
    let c = Lifecycle::new();
    let t = c.begin_start().unwrap();
    assert_eq!(c.cleanup_complete(t, true), Err(Error::WrongPhase));
    c.complete_start(t).unwrap();
    assert_eq!(c.complete_start(t), Err(Error::WrongPhase));
    assert_eq!(c.start_failed(t, true), Err(Error::WrongPhase));
    assert_eq!(c.phase(), Ok(Phase::Running));
}
