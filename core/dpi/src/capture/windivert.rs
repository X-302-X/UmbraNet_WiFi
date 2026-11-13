//! Только копии исходящих пакетов на ограниченных портах. Здесь нет WinDivertSend.
//! Запуск возможен лишь явным вызовом open, требует админправа и может установить драйвер.
use super::CapturePlan;
use std::ffi::{c_char, c_void, CString, OsStr};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

const SNIFF_RECV_ONLY: u64 = 0x0001 | 0x0004;
const NETWORK_LAYER: i32 = 0;
const SHUTDOWN_RECV: i32 = 1;
const MAX_PACKET: usize = 40 + 65_535;
const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0000_0100;
const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;

type Handle = *mut c_void;
type OpenFn = unsafe extern "C" fn(*const c_char, i32, i16, u64) -> Handle;
type RecvFn = unsafe extern "C" fn(Handle, *mut c_void, u32, *mut u32, *mut c_void) -> i32;
type ShutdownFn = unsafe extern "C" fn(Handle, i32) -> i32;
type CloseFn = unsafe extern "C" fn(Handle) -> i32;

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryExW(path: *const u16, file: Handle, flags: u32) -> Handle;
    fn GetProcAddress(module: Handle, name: *const c_char) -> *mut c_void;
    fn FreeLibrary(module: Handle) -> i32;
}

struct Library(Handle);
impl Library {
    fn load(path: &Path) -> io::Result<Self> {
        let absolute = path.canonicalize()?;
        if absolute.file_name() != Some(OsStr::new("WinDivert.dll")) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Ожидается WinDivert.dll",
            ));
        }
        if !absolute.with_file_name("WinDivert64.sys").is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Рядом с DLL отсутствует WinDivert64.sys",
            ));
        }
        let wide: Vec<u16> = absolute.as_os_str().encode_wide().chain(Some(0)).collect();
        // Загружаем только из указанной директории и системных папок, а не из PATH.
        let module = unsafe {
            LoadLibraryExW(
                wide.as_ptr(),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(module))
    }
    fn symbol(&self, name: &'static [u8]) -> io::Result<*mut c_void> {
        let address = unsafe { GetProcAddress(self.0, name.as_ptr().cast()) };
        if address.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(address)
        }
    }
}
impl Drop for Library {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.0);
        }
    }
}

/// Низкоуровневый пассивный канал. Сам по себе не запускает поток и не пишет логи.
/// Содержимое полученных копий не должно сохраняться в логи.
pub struct Sniffer {
    handle: Handle,
    recv: RecvFn,
    shutdown_fn: ShutdownFn,
    close: CloseFn,
    _library: Library,
}

// WinDivertShutdown поддерживает отмену заблокированного WinDivertRecv из другого потока.
// Деструктор вызывается только когда у владельца больше не осталось ссылок на Sniffer.
unsafe impl Send for Sniffer {}
unsafe impl Sync for Sniffer {}

impl Sniffer {
    pub fn open(dll_path: &Path, plan: &CapturePlan) -> io::Result<Self> {
        let filter = CString::new(plan.filter())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Некорректный фильтр"))?;
        let library = Library::load(dll_path)?;
        // Адреса экспортов WinDivert приводятся к сигнатурам из официального windivert.h.
        let open: OpenFn = unsafe { std::mem::transmute(library.symbol(b"WinDivertOpen\0")?) };
        let recv: RecvFn = unsafe { std::mem::transmute(library.symbol(b"WinDivertRecv\0")?) };
        let shutdown_fn: ShutdownFn =
            unsafe { std::mem::transmute(library.symbol(b"WinDivertShutdown\0")?) };
        let close: CloseFn = unsafe { std::mem::transmute(library.symbol(b"WinDivertClose\0")?) };
        let handle = unsafe { open(filter.as_ptr(), NETWORK_LAYER, 0, SNIFF_RECV_ONLY) };
        if handle as isize == -1 {
            return Err(io::Error::last_os_error());
        }
        if handle.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Не удалось открыть WinDivert",
            ));
        }
        Ok(Self {
            handle,
            recv,
            shutdown_fn,
            close,
            _library: library,
        })
    }

    /// Блокируется до получения копии пакета или shutdown. Буфер не записывается на диск.
    pub fn receive(&self) -> io::Result<Vec<u8>> {
        let mut packet = vec![0u8; MAX_PACKET];
        let mut length = 0u32;
        let result = unsafe {
            (self.recv)(
                self.handle,
                packet.as_mut_ptr().cast(),
                MAX_PACKET as u32,
                &mut length,
                ptr::null_mut(),
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        if length as usize > packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Некорректная длина пакета",
            ));
        }
        packet.truncate(length as usize);
        Ok(packet)
    }

    /// Можно вызвать из другого потока для завершения ожидающего receive.
    pub fn shutdown(&self) -> io::Result<()> {
        if unsafe { (self.shutdown_fn)(self.handle, SHUTDOWN_RECV) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
impl Drop for Sniffer {
    fn drop(&mut self) {
        unsafe {
            (self.close)(self.handle);
        }
    }
}
