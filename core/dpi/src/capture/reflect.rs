//! Однократный обзор открытых WinDivert handles. Он не устанавливает драйвер,
//! не читает трафик и не завершает процессы. Снимок не является полным или
//! устойчивым доказательством: события могут потеряться, PID переиспользуется.
use super::reflect_wire::{decode, ReflectAddress};
use super::windivert::{CloseFn, Handle, Library, OpenFn, RecvFn, ShutdownFn};
use crate::flow::windows_process::current_process_info;
use serde::Serialize;
use std::{ffi::c_void, io, path::Path};

const REFLECT_LAYER: i32 = 4;
const FLAGS: u64 = 0x0001 | 0x0004 | 0x0010; // SNIFF | RECV_ONLY | NO_INSTALL
const SHUTDOWN_BOTH: i32 = 3;
const ERROR_NO_DATA: i32 = 232;
const LIMIT: usize = 1024;

#[derive(Debug, Serialize)]
pub struct ObservedHandle {
    pub pid: u32,
    pub process_name: Option<String>,
    pub layer: u32,
    pub is_own_process: bool,
}
#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub truncated: bool,
    pub rejected: usize,
    pub handles: Vec<ObservedHandle>,
}
#[derive(Debug)]
pub struct ScanError {
    pub message: String,
    pub close_unconfirmed: bool,
}
fn failure(message: impl Into<String>, close_unconfirmed: bool) -> ScanError {
    ScanError {
        message: message.into(),
        close_unconfirmed,
    }
}
struct ReflectHandle {
    handle: Handle,
    close: CloseFn,
    attempted: bool,
    _library: Library,
}
impl ReflectHandle {
    fn close_checked(&mut self) -> io::Result<()> {
        self.attempted = true;
        if unsafe { (self.close)(self.handle) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
impl Drop for ReflectHandle {
    fn drop(&mut self) {
        if !self.attempted {
            self.attempted = true;
            unsafe {
                (self.close)(self.handle);
            }
        }
    }
}

/// Only called after explicit user action. Even a completed snapshot may miss
/// concurrent opens/closes or queue drops; it must never authorize termination.
pub fn scan(dll_path: &Path) -> Result<ScanResult, ScanError> {
    // Do not open when SCM does not currently report RUNNING. This is only a
    // best-effort guard: a separate process can stop the service after the check,
    // and NO_INSTALL does not promise that an installed driver cannot start.
    let status = super::driver_service::status().map_err(|e| {
        failure(
            format!("Не удалось проверить состояние WinDivert: {e}"),
            false,
        )
    })?;
    if status.status != "running" {
        return Err(failure(format!("Обзор не выполнен: служба WinDivert не подтверждена как работающая ({}). Это не доказывает отсутствие конфликтов.", status.status), false));
    }
    let lib = Library::load(dll_path)
        .map_err(|e| failure(format!("Не удалось загрузить WinDivert: {e}"), false))?;
    let open: OpenFn = unsafe {
        std::mem::transmute(
            lib.symbol(b"WinDivertOpen\0")
                .map_err(|e| failure(e.to_string(), false))?,
        )
    };
    let receive: RecvFn = unsafe {
        std::mem::transmute(
            lib.symbol(b"WinDivertRecv\0")
                .map_err(|e| failure(e.to_string(), false))?,
        )
    };
    let shutdown: ShutdownFn = unsafe {
        std::mem::transmute(
            lib.symbol(b"WinDivertShutdown\0")
                .map_err(|e| failure(e.to_string(), false))?,
        )
    };
    let close: CloseFn = unsafe {
        std::mem::transmute(
            lib.symbol(b"WinDivertClose\0")
                .map_err(|e| failure(e.to_string(), false))?,
        )
    };
    let raw = unsafe { open(c"true".as_ptr(), REFLECT_LAYER, -333, FLAGS) };
    if raw as isize == -1 {
        let e = io::Error::last_os_error();
        return Err(failure(format!("Не удалось открыть REFLECT: {e}"), false));
    }
    if raw.is_null() {
        return Err(failure("WinDivert вернул пустой handle", false));
    }
    let mut handle = ReflectHandle {
        handle: raw,
        close,
        attempted: false,
        _library: lib,
    };
    let mut observations = Vec::new();
    let mut rejected = 0usize;
    let mut truncated = false;
    let mut issue = None;
    if unsafe { shutdown(raw, SHUTDOWN_BOTH) } == 0 {
        issue = Some(format!(
            "Не удалось завершить приём REFLECT: {}",
            io::Error::last_os_error()
        ));
    } else {
        let mut buffer = vec![0u8; 65535];
        loop {
            if observations.len() + rejected >= LIMIT {
                truncated = true;
                break;
            }
            let mut address = ReflectAddress::default();
            let mut length = 0u32;
            let ok = unsafe {
                receive(
                    raw,
                    buffer.as_mut_ptr().cast::<c_void>(),
                    buffer.len() as u32,
                    &mut length,
                    (&mut address as *mut ReflectAddress).cast(),
                )
            };
            if ok == 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() != Some(ERROR_NO_DATA) {
                    issue = Some(format!("Ошибка чтения REFLECT: {e}"));
                }
                break;
            }
            if let Some((pid, layer)) = decode(&address) {
                observations.push((pid, layer));
            } else {
                rejected += 1;
            }
        }
    }
    if let Err(error) = handle.close_checked() {
        let extra = issue.map(|s| format!("; {s}")).unwrap_or_default();
        return Err(failure(
            format!("Не удалось закрыть обзор WinDivert: {error}{extra}"),
            true,
        ));
    }
    drop(handle);
    if let Some(error) = issue {
        return Err(failure(error, false));
    }
    let own = std::process::id();
    let handles = observations
        .into_iter()
        .map(|(pid, layer)| ObservedHandle {
            pid,
            process_name: current_process_info(pid)
                .ok()
                .map(|p| p.image_name().to_string()),
            layer,
            is_own_process: pid == own,
        })
        .collect();
    Ok(ScanResult {
        truncated,
        rejected,
        handles,
    })
}
