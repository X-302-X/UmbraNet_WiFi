//! Проверки Windows без изменения прав и сетевых настроек.

#[cfg(windows)]
mod windows {
    use std::collections::BTreeSet;
    use std::ffi::c_void;
    use std::io;
    use std::mem::{size_of, zeroed};
    use std::ptr;

    type Handle = *mut c_void;
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_ELEVATION_CLASS: u32 = 20;
    const TH32CS_SNAPPROCESS: u32 = 2;
    const ERROR_NO_MORE_FILES: i32 = 18;

    #[repr(C)]
    struct ProcessEntry {
        size: u32,
        usage: u32,
        pid: u32,
        default_heap_id: usize,
        module_id: u32,
        threads: u32,
        parent_pid: u32,
        priority: i32,
        flags: u32,
        exe: [u16; 260],
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> Handle;
        fn CloseHandle(handle: Handle) -> i32;
        fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> Handle;
        fn Process32FirstW(snapshot: Handle, entry: *mut ProcessEntry) -> i32;
        fn Process32NextW(snapshot: Handle, entry: *mut ProcessEntry) -> i32;
    }
    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
        fn GetTokenInformation(
            token: Handle,
            class: u32,
            buffer: *mut c_void,
            length: u32,
            result_length: *mut u32,
        ) -> i32;
    }

    struct OwnedHandle(Handle);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    pub fn is_elevated() -> Result<bool, String> {
        let mut raw = ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
            return Err(format!(
                "Не удалось проверить права: {}",
                io::Error::last_os_error()
            ));
        }
        let token = OwnedHandle(raw);
        let mut elevated = 0u32;
        let mut length = 0u32;
        let ok = unsafe {
            GetTokenInformation(
                token.0,
                TOKEN_ELEVATION_CLASS,
                (&mut elevated as *mut u32).cast(),
                size_of::<u32>() as u32,
                &mut length,
            )
        };
        if ok == 0 {
            return Err(format!(
                "Не удалось проверить права: {}",
                io::Error::last_os_error()
            ));
        }
        if length < size_of::<u32>() as u32 {
            return Err("Некорректный ответ Windows о правах".into());
        }
        Ok(elevated != 0)
    }

    pub fn running_processes() -> Result<Vec<String>, String> {
        let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if raw as isize == -1 {
            return Err(format!(
                "Не удалось получить процессы: {}",
                io::Error::last_os_error()
            ));
        }
        let snapshot = OwnedHandle(raw);
        let mut entry: ProcessEntry = unsafe { zeroed() };
        entry.size = size_of::<ProcessEntry>() as u32;
        let mut names = BTreeSet::new();
        let mut ok = unsafe { Process32FirstW(snapshot.0, &mut entry) };
        while ok != 0 {
            let end = entry
                .exe
                .iter()
                .position(|v| *v == 0)
                .unwrap_or(entry.exe.len());
            let name = String::from_utf16_lossy(&entry.exe[..end]);
            if name.to_ascii_lowercase().ends_with(".exe") {
                names.insert(name.to_ascii_lowercase());
            }
            ok = unsafe { Process32NextW(snapshot.0, &mut entry) };
        }
        let last = io::Error::last_os_error();
        if last.raw_os_error() != Some(ERROR_NO_MORE_FILES) {
            return Err(format!("Не удалось прочитать процессы: {last}"));
        }
        Ok(names.into_iter().collect())
    }
}

#[cfg(windows)]
pub use windows::{is_elevated, running_processes};

#[cfg(not(windows))]
pub fn is_elevated() -> Result<bool, String> {
    Err("Проверка доступна в Windows".into())
}
#[cfg(not(windows))]
pub fn running_processes() -> Result<Vec<String>, String> {
    Err("Список процессов доступен в Windows".into())
}
