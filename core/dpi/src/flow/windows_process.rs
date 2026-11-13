//! Текущий снимок процесса Windows. Он не доказывает, что PID в старом событии тот же процесс.
use crate::flow::tracker::ProcessIdentity;
use std::ffi::c_void;
use std::io;
use std::path::Path;

type Handle = *mut c_void;
const QUERY_LIMITED: u32 = 0x1000;
const STILL_ACTIVE: u32 = 259;
#[repr(C)]
#[derive(Default)]
struct FileTime {
    low: u32,
    high: u32,
}
#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetProcessTimes(
        handle: Handle,
        created: *mut FileTime,
        exited: *mut FileTime,
        kernel: *mut FileTime,
        user: *mut FileTime,
    ) -> i32;
    fn GetExitCodeProcess(handle: Handle, exit_code: *mut u32) -> i32;
    fn QueryFullProcessImageNameW(
        handle: Handle,
        flags: u32,
        path: *mut u16,
        size: *mut u32,
    ) -> i32;
}
struct ProcessHandle(Handle);
impl Drop for ProcessHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// Открывает PID только для чтения. PID мог быть переиспользован до этого вызова.
pub fn current_process_info(pid: u32) -> io::Result<ProcessIdentity> {
    if pid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Некорректный PID",
        ));
    }
    let raw = unsafe { OpenProcess(QUERY_LIMITED, 0, pid) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    let handle = ProcessHandle(raw);
    let (mut created, mut exited, mut kernel, mut user) = (
        FileTime::default(),
        FileTime::default(),
        FileTime::default(),
        FileTime::default(),
    );
    if unsafe { GetProcessTimes(handle.0, &mut created, &mut exited, &mut kernel, &mut user) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut path = vec![0u16; 32768];
    let mut len = path.len() as u32;
    if unsafe { QueryFullProcessImageNameW(handle.0, 0, path.as_mut_ptr(), &mut len) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let path = String::from_utf16(&path[..len as usize])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Некорректное имя процесса"))?;
    let name = Path::new(&path)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Некорректное имя процесса"))?;
    let mut exit_code = 0;
    if unsafe { GetExitCodeProcess(handle.0, &mut exit_code) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if exit_code != STILL_ACTIVE {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Процесс уже завершён",
        ));
    }
    let creation_id = ((created.high as u64) << 32) | created.low as u64;
    ProcessIdentity::new(pid, creation_id, name)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Некорректные данные процесса"))
}
