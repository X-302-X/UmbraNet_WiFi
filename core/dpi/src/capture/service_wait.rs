//! Ожидание результата SCM, не доказательство выгрузки драйвера из памяти.
use serde::Serialize;
use std::{
    io,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Serialize)]
pub struct View {
    pub status: &'static str,
    pub code: Option<u32>,
    pub wait_hint_ms: Option<u32>,
}
impl View {
    /// Только SCM: отсутствие записи не доказывает выгрузку драйвера или закрытие чужих handle.
    pub fn scm_stopped_or_absent(&self) -> bool {
        matches!(self.status, "stopped" | "absent")
    }
}

/// Вызывается в фоновом потоке: само обращение к Windows не ограничено таймером.
pub(super) fn wait_for_scm(
    mut view: View,
    timeout: Duration,
    mut query: impl FnMut() -> io::Result<View>,
) -> io::Result<View> {
    let start = Instant::now();
    loop {
        if view.scm_stopped_or_absent() {
            return Ok(view);
        }
        let remaining = timeout.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "Остановка службы WinDivert не подтверждена; последнее состояние SCM: {}",
                    view.status
                ),
            ));
        }
        std::thread::sleep(remaining.min(Duration::from_millis(100)));
        view = query().map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("Не удалось проверить остановку службы WinDivert: {e}"),
            )
        })?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn v(status: &'static str) -> View {
        View {
            status,
            code: None,
            wait_hint_ms: None,
        }
    }
    #[test]
    fn pending_then_stopped_and_absent_are_scm_only() {
        let mut count = 0;
        let result = wait_for_scm(v("stop_pending"), Duration::from_millis(250), || {
            count += 1;
            Ok(v("stopped"))
        })
        .unwrap();
        assert_eq!(result.status, "stopped");
        assert_eq!(count, 1);
        assert!(v("absent").scm_stopped_or_absent());
        assert!(!v("marked_for_delete").scm_stopped_or_absent());
    }
    #[test]
    fn pending_unknown_and_marked_are_not_success() {
        for status in ["stop_pending", "marked_for_delete", "unknown", "running"] {
            let err =
                wait_for_scm(v(status), Duration::ZERO, || panic!("not queried")).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::TimedOut);
            assert!(err.to_string().contains(status));
        }
    }
    #[test]
    fn query_failure_is_visible_not_treated_as_absent() {
        let error = wait_for_scm(v("stop_pending"), Duration::from_millis(150), || {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "test"))
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("test"));
    }
}
