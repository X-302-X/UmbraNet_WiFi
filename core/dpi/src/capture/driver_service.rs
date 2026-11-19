//! Read-only status and an explicit stop request for the shared WinDivert service.
//! This does not install the driver, terminate processes or modify the service configuration.
use super::service_wait::wait_for_scm;
pub use super::service_wait::View;
use std::ffi::c_void;
use std::io;
use std::ptr;
use std::time::Duration;

type ScHandle = *mut c_void;
const SC_MANAGER_CONNECT: u32 = 0x0001;
const SERVICE_QUERY_STATUS: u32 = 0x0004;
const SERVICE_STOP: u32 = 0x0020;
const SERVICE_CONTROL_STOP: u32 = 1;
const SERVICE_STOPPED: u32 = 1;
const SERVICE_STOP_PENDING: u32 = 3;
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
const ERROR_SERVICE_MARKED_FOR_DELETE: i32 = 1072;
const ERROR_SERVICE_NOT_ACTIVE: i32 = 1062;

#[repr(C)]
#[derive(Default)]
struct ServiceStatus {
    service_type: u32,
    current_state: u32,
    controls_accepted: u32,
    win32_exit_code: u32,
    service_exit_code: u32,
    checkpoint: u32,
    wait_hint: u32,
}
#[link(name = "advapi32")]
extern "system" {
    fn OpenSCManagerW(machine: *const u16, database: *const u16, access: u32) -> ScHandle;
    fn OpenServiceW(manager: ScHandle, name: *const u16, access: u32) -> ScHandle;
    fn QueryServiceStatus(service: ScHandle, status: *mut ServiceStatus) -> i32;
    fn ControlService(service: ScHandle, control: u32, status: *mut ServiceStatus) -> i32;
    fn CloseServiceHandle(handle: ScHandle) -> i32;
}
struct Handle(ScHandle);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}

fn view(status: &ServiceStatus) -> View {
    let name = match status.current_state {
        1 => "stopped",
        2 => "start_pending",
        3 => "stop_pending",
        4 => "running",
        5 => "continue_pending",
        6 => "pause_pending",
        7 => "paused",
        _ => "unknown",
    };
    View {
        status: name,
        code: Some(status.current_state),
        wait_hint_ms: Some(status.wait_hint),
    }
}
fn manager() -> io::Result<Handle> {
    let handle = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(Handle(handle))
}
fn open_service(manager: &Handle, access: u32) -> io::Result<Option<Handle>> {
    let name: Vec<u16> = "WinDivert".encode_utf16().chain(Some(0)).collect();
    let raw = unsafe { OpenServiceW(manager.0, name.as_ptr(), access) };
    if raw.is_null() {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST) {
            return Ok(None);
        }
        return Err(error);
    }
    Ok(Some(Handle(raw)))
}
fn absent() -> View {
    View {
        status: "absent",
        code: None,
        wait_hint_ms: None,
    }
}
fn marked() -> View {
    View {
        status: "marked_for_delete",
        code: None,
        wait_hint_ms: None,
    }
}
fn query(service: &Handle) -> io::Result<View> {
    let mut status = ServiceStatus::default();
    if unsafe { QueryServiceStatus(service.0, &mut status) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(view(&status))
}
/// Queries SCM only. It never opens WinDivert or loads the driver.
pub fn status() -> io::Result<View> {
    let manager = manager()?;
    match open_service(&manager, SERVICE_QUERY_STATUS) {
        Ok(Some(service)) => query(&service),
        Ok(None) => Ok(absent()),
        Err(error) if error.raw_os_error() == Some(ERROR_SERVICE_MARKED_FOR_DELETE) => Ok(marked()),
        Err(error) => Err(error),
    }
}
/// Requests a stop of the shared service WinDivert. It can affect other applications.
/// A stop-pending response is not a confirmation that the driver has stopped.
pub fn request_stop() -> io::Result<View> {
    let manager = manager()?;
    let service = match open_service(&manager, SERVICE_QUERY_STATUS | SERVICE_STOP) {
        Ok(Some(service)) => service,
        Ok(None) => return Ok(absent()),
        Err(error) if error.raw_os_error() == Some(ERROR_SERVICE_MARKED_FOR_DELETE) => {
            return Ok(marked())
        }
        Err(error) => return Err(error),
    };
    let current = query(&service)?;
    if matches!(current.code, Some(SERVICE_STOPPED | SERVICE_STOP_PENDING)) {
        return Ok(current);
    }
    let mut response = ServiceStatus::default();
    if unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut response) } == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_SERVICE_NOT_ACTIVE) {
            return query(&service);
        }
        return Err(error);
    }
    Ok(view(&response))
}

/// Запрос остановки и ожидание результата SCM, только в фоновом потоке.
/// При timeout состояние неизвестно; наличие отсутствующей/остановленной
/// службы не доказывает выгрузку драйвера или закрытие сторонних handle.
/// Системный вызов SCM сам по себе может зависнуть дольше `timeout`.
pub fn request_stop_and_confirm(timeout: Duration) -> io::Result<View> {
    let initial = request_stop()?;
    if initial.status == "marked_for_delete" {
        return Err(io::Error::other(
            "Служба WinDivert помечена для удаления; запросить её остановку не удалось",
        ));
    }
    wait_for_scm(initial, timeout, status)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn status_layout_and_mapping_are_conservative() {
        assert_eq!(std::mem::size_of::<ServiceStatus>(), 28);
        assert!(absent().scm_stopped_or_absent());
        assert!(!marked().scm_stopped_or_absent());
        assert!(view(&ServiceStatus {
            current_state: SERVICE_STOPPED,
            ..Default::default()
        })
        .scm_stopped_or_absent());
        assert!(!view(&ServiceStatus {
            current_state: SERVICE_STOP_PENDING,
            ..Default::default()
        })
        .scm_stopped_or_absent());
        assert_eq!(
            view(&ServiceStatus {
                current_state: 4,
                ..Default::default()
            })
            .status,
            "running"
        );
        assert_eq!(
            view(&ServiceStatus {
                current_state: 42,
                ..Default::default()
            })
            .status,
            "unknown"
        );
    }
}
