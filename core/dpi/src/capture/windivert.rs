//! Пассивный Sniffer и отдельный активный DivertChannel (требует WinDivertSend).
//! Запуск возможен лишь явным вызовом open, требует админправа и может установить драйвер.
use super::io_guard::{HandleIo, Operation};
use super::CapturePlan;
use crate::flow::wire::{self, FlowEvent, RawAddress};
use std::ffi::{c_char, c_void, CString, OsStr};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

const SNIFF_RECV_ONLY: u64 = 0x0001 | 0x0004;
const NETWORK_LAYER: i32 = 0;
const FLOW_LAYER: i32 = 2;
const SHUTDOWN_RECV: i32 = 1;
const MAX_PACKET: usize = 40 + 65_535;
const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0000_0100;
const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;

pub use super::address::WinDivertAddress;

pub(super) type Handle = *mut c_void;
pub(super) type OpenFn = unsafe extern "C" fn(*const c_char, i32, i16, u64) -> Handle;
pub(super) type RecvFn =
    unsafe extern "C" fn(Handle, *mut c_void, u32, *mut u32, *mut c_void) -> i32;
type SendFn = unsafe extern "C" fn(Handle, *const c_void, u32, *mut u32, *const c_void) -> i32;
pub(super) type ShutdownFn = unsafe extern "C" fn(Handle, i32) -> i32;
pub(super) type CloseFn = unsafe extern "C" fn(Handle) -> i32;

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryExW(path: *const u16, file: Handle, flags: u32) -> Handle;
    fn GetProcAddress(module: Handle, name: *const c_char) -> *mut c_void;
    fn FreeLibrary(module: Handle) -> i32;
}

pub(super) struct Library(Handle);
impl Library {
    pub(super) fn load(path: &Path) -> io::Result<Self> {
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
    pub(super) fn symbol(&self, name: &'static [u8]) -> io::Result<*mut c_void> {
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
    io_state: HandleIo,
    _library: Library,
}

// Shutdown(RECV) запрещает новую очередь, но уже поставленные события ещё
// могут возвращаться из Recv до ERROR_NO_DATA. Деструктор вызывается только
// когда у владельца больше не осталось ссылок на Sniffer.
unsafe impl Send for Sniffer {}
unsafe impl Sync for Sniffer {}

impl Sniffer {
    pub fn open(dll_path: &Path, plan: &CapturePlan) -> io::Result<Self> {
        Self::open_inner(dll_path, plan.filter(), NETWORK_LAYER)
    }

    /// SNIFF + RECV_ONLY: получаем копии TCP на web-портах обоих направлений,
    /// в том числе от невыбранных приложений. Не меняет и не отправляет пакеты.
    pub fn open_tcp_metadata(dll_path: &Path) -> io::Result<Self> {
        Self::open_inner(dll_path, super::ACTIVE_TCP_WEB, NETWORK_LAYER)
    }

    fn open_inner(dll_path: &Path, filter_text: &str, layer: i32) -> io::Result<Self> {
        let filter = CString::new(filter_text)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Некорректный фильтр"))?;
        let library = Library::load(dll_path)?;
        // Адреса экспортов WinDivert приводятся к сигнатурам из официального windivert.h.
        let open: OpenFn = unsafe { std::mem::transmute(library.symbol(b"WinDivertOpen\0")?) };
        let recv: RecvFn = unsafe { std::mem::transmute(library.symbol(b"WinDivertRecv\0")?) };
        let shutdown_fn: ShutdownFn =
            unsafe { std::mem::transmute(library.symbol(b"WinDivertShutdown\0")?) };
        let close: CloseFn = unsafe { std::mem::transmute(library.symbol(b"WinDivertClose\0")?) };
        let handle = unsafe { open(filter.as_ptr(), layer, 0, SNIFF_RECV_ONLY) };
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
            io_state: HandleIo::default(),
            _library: library,
        })
    }

    fn begin_io(&self) -> io::Result<Operation<'_>> {
        self.io_state.begin()
    }

    /// Однократная попытка закрытия, только после завершения I/O.
    pub fn close_checked(&self) -> io::Result<()> {
        self.io_state.close_checked(|| {
            if unsafe { (self.close)(self.handle) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })
    }

    /// Блокируется до получения копии пакета или shutdown. Буфер не записывается на диск.
    pub fn receive(&self) -> io::Result<Vec<u8>> {
        let _operation = self.begin_io()?;
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

    /// Получает копию и WINDIVERT_ADDRESS. Вызывающий обязан отбросить байты
    /// после агрегирования; отсутствие событий не доказывает отсутствие потерь.
    pub fn receive_with_address(&self) -> io::Result<(Vec<u8>, WinDivertAddress)> {
        let _operation = self.begin_io()?;
        let mut packet = vec![0u8; MAX_PACKET];
        let mut length = 0u32;
        let mut address = WinDivertAddress::default();
        let result = unsafe {
            (self.recv)(
                self.handle,
                packet.as_mut_ptr().cast(),
                MAX_PACKET as u32,
                &mut length,
                (&mut address as *mut WinDivertAddress).cast(),
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
        Ok((packet, address))
    }

    /// Можно вызвать из другого потока для завершения ожидающего receive.
    pub fn shutdown(&self) -> io::Result<()> {
        let _operation = self.begin_io()?;
        if unsafe { (self.shutdown_fn)(self.handle, SHUTDOWN_RECV) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
impl Drop for Sniffer {
    fn drop(&mut self) {
        self.io_state.close_on_drop(|| unsafe {
            (self.close)(self.handle);
        });
    }
}

/// FLOW-слой наблюдает события соединений и не получает содержимое пакетов.
/// Не запускается без явного вызова. Прежние соединения не видны этому handle.
pub struct FlowListener {
    inner: Sniffer,
}

impl FlowListener {
    pub fn open(dll_path: &Path, plan: &CapturePlan) -> io::Result<Self> {
        Ok(Self {
            inner: Sniffer::open_inner(dll_path, plan.flow_filter(), FLOW_LAYER)?,
        })
    }
    /// Неизвестные либо неподдерживаемые события возвращаются как None.
    pub fn receive(&self) -> io::Result<Option<FlowEvent>> {
        let _operation = self.inner.begin_io()?;
        let mut raw = RawAddress::default();
        let ok = unsafe {
            (self.inner.recv)(
                self.inner.handle,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                (&mut raw as *mut RawAddress).cast(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(wire::decode(raw))
    }
    pub fn shutdown(&self) -> io::Result<()> {
        self.inner.shutdown()
    }
    pub fn close_checked(&self) -> io::Result<()> {
        self.inner.close_checked()
    }
}

/// Активный канал WinDivert (без SNIFF_RECV_ONLY): перехватывает пакеты,
/// позволяя модифицировать их и отправлять через `WinDivertSend`.
pub struct DivertChannel {
    handle: Handle,
    recv: RecvFn,
    send: SendFn,
    shutdown_fn: ShutdownFn,
    close: CloseFn,
    io_state: HandleIo,
    _library: Library,
}

unsafe impl Send for DivertChannel {}
unsafe impl Sync for DivertChannel {}

impl DivertChannel {
    pub fn open(dll_path: &Path, filter_text: &str) -> io::Result<Self> {
        // Даже низкоуровневый активный канал не открываем до отдельного ревью.
        crate::safety::active_start_guard()
            .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
        Self::open_inner(dll_path, filter_text)
    }

    /// Узкий тестовый канал: только исходящий localhost TCP к заранее занятому
    /// портом этой проверки listener. НЕ разрешает активный DPI-движок.
    #[cfg(feature = "loopback-probe")]
    pub(super) fn open_loopback_probe(dll_path: &Path, port: u16) -> io::Result<Self> {
        Self::open_inner(dll_path, &super::loopback_exchange::filter(port)?)
    }

    fn open_inner(dll_path: &Path, filter_text: &str) -> io::Result<Self> {
        let filter = CString::new(filter_text)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Некорректный фильтр"))?;
        let library = Library::load(dll_path)?;
        let open: OpenFn = unsafe { std::mem::transmute(library.symbol(b"WinDivertOpen\0")?) };
        let recv: RecvFn = unsafe { std::mem::transmute(library.symbol(b"WinDivertRecv\0")?) };
        let send: SendFn = unsafe { std::mem::transmute(library.symbol(b"WinDivertSend\0")?) };
        let shutdown_fn: ShutdownFn =
            unsafe { std::mem::transmute(library.symbol(b"WinDivertShutdown\0")?) };
        let close: CloseFn = unsafe { std::mem::transmute(library.symbol(b"WinDivertClose\0")?) };

        // flags = 0 -> активный перехват (пакеты изымаются из стека до WinDivertSend)
        let handle = unsafe { open(filter.as_ptr(), NETWORK_LAYER, 0, 0) };
        if handle as isize == -1 {
            return Err(io::Error::last_os_error());
        }
        if handle.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Не удалось открыть активный WinDivert",
            ));
        }
        Ok(Self {
            handle,
            recv,
            send,
            shutdown_fn,
            close,
            io_state: HandleIo::default(),
            _library: library,
        })
    }

    pub fn receive(&self) -> io::Result<(Vec<u8>, WinDivertAddress)> {
        let _operation = self.io_state.begin()?;
        let mut packet = vec![0u8; MAX_PACKET];
        let mut length = 0u32;
        let mut addr = WinDivertAddress::default();
        let ok = unsafe {
            (self.recv)(
                self.handle,
                packet.as_mut_ptr().cast(),
                MAX_PACKET as u32,
                &mut length,
                (&mut addr as *mut WinDivertAddress).cast(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if length as usize > packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Некорректная длина пакета",
            ));
        }
        packet.truncate(length as usize);
        Ok((packet, addr))
    }

    pub fn send(&self, packet: &[u8], addr: &WinDivertAddress) -> io::Result<u32> {
        let _operation = self.io_state.begin()?;
        let mut sent = 0u32;
        let ok = unsafe {
            (self.send)(
                self.handle,
                packet.as_ptr().cast(),
                packet.len() as u32,
                &mut sent,
                (addr as *const WinDivertAddress).cast(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(sent)
    }

    pub fn shutdown(&self) -> io::Result<()> {
        let _operation = self.io_state.begin()?;
        if unsafe { (self.shutdown_fn)(self.handle, SHUTDOWN_RECV) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    /// Закрытие разрешено только после завершения receive, send и shutdown.
    pub fn close_checked(&self) -> io::Result<()> {
        self.io_state.close_checked(|| {
            if unsafe { (self.close)(self.handle) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })
    }
}

impl Drop for DivertChannel {
    fn drop(&mut self) {
        self.io_state.close_on_drop(|| unsafe {
            (self.close)(self.handle);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    // Проверяет только синтаксис фильтров через DLL: WinDivertOpen не вызывается.
    #[test]
    fn official_library_compiles_filters_without_opening_driver() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("driver")
            .join("WinDivert.dll");
        let library = Library::load(&path).expect("Не удалось загрузить библиотеку WinDivert");
        type CompileFn = unsafe extern "C" fn(
            *const c_char,
            i32,
            *mut c_char,
            u32,
            *mut *const c_char,
            *mut u32,
        ) -> i32;
        let compile: CompileFn = unsafe {
            std::mem::transmute(library.symbol(b"WinDivertHelperCompileFilter\0").unwrap())
        };
        for (filter, layer) in [
            (super::super::FLOW_WEB, FLOW_LAYER),
            (super::super::FLOW_WEB_AND_DISCORD_VOICE, FLOW_LAYER),
            (super::super::WEB, NETWORK_LAYER),
            (super::super::WEB_AND_DISCORD_VOICE, NETWORK_LAYER),
            (super::super::ACTIVE_TCP_WEB, NETWORK_LAYER),
        ] {
            let input = CString::new(filter).unwrap();
            let mut error = ptr::null();
            let mut position = 0u32;
            let ok = unsafe {
                compile(
                    input.as_ptr(),
                    layer,
                    ptr::null_mut(),
                    0,
                    &mut error,
                    &mut position,
                )
            };
            let text = if error.is_null() {
                "нет описания".into()
            } else {
                unsafe { CStr::from_ptr(error) }
                    .to_string_lossy()
                    .into_owned()
            };
            assert_ne!(ok, 0, "Ошибка фильтра на позиции {position}: {text}");
        }
    }

    // Проверка на официальном интерпретаторе DLL без WinDivertOpen и без драйвера.
    #[test]
    fn official_filter_evaluator_checks_both_tcp_directions() {
        #[link(name = "kernel32")]
        extern "system" {
            fn SetLastError(code: u32);
            fn GetLastError() -> u32;
        }
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("driver")
            .join("WinDivert.dll");
        let library = Library::load(&path).unwrap();
        type EvalFn =
            unsafe extern "C" fn(*const c_char, *const c_void, u32, *const WinDivertAddress) -> i32;
        let eval: EvalFn =
            unsafe { std::mem::transmute(library.symbol(b"WinDivertHelperEvalFilter\0").unwrap()) };
        let filter = CString::new(super::super::ACTIVE_TCP_WEB).unwrap();
        fn packet(ipv6: bool, protocol: u8, src: u16, dst: u16) -> Vec<u8> {
            let len = if ipv6 { 60 } else { 40 };
            let mut p = vec![0u8; len];
            let tcp = if ipv6 {
                p[0] = 0x60;
                p[4..6].copy_from_slice(&20u16.to_be_bytes());
                p[6] = protocol;
                p[8] = 0x20;
                p[23] = 1;
                p[24] = 0x20;
                p[39] = 2;
                40
            } else {
                p[0] = 0x45;
                p[2..4].copy_from_slice(&40u16.to_be_bytes());
                p[8] = 64;
                p[9] = protocol;
                p[12..16].copy_from_slice(&[192, 0, 2, 1]);
                p[16..20].copy_from_slice(&[198, 51, 100, 1]);
                20
            };
            p[tcp..tcp + 2].copy_from_slice(&src.to_be_bytes());
            p[tcp + 2..tcp + 4].copy_from_slice(&dst.to_be_bytes());
            if protocol == 6 {
                p[tcp + 12] = 0x50;
                p[tcp + 13] = 2;
            }
            if protocol == 17 {
                p[tcp + 4..tcp + 6].copy_from_slice(&20u16.to_be_bytes());
            }
            p
        }
        let matches = |p: &[u8], outbound: bool, loopback: bool, impostor: bool, ipv6: bool| {
            let addr = WinDivertAddress::for_filter_test(outbound, loopback, impostor, ipv6);
            unsafe {
                SetLastError(0);
                let result = eval(filter.as_ptr(), p.as_ptr().cast(), p.len() as u32, &addr);
                let error = GetLastError();
                if result == 0 {
                    assert_eq!(error, 0, "WinDivertHelperEvalFilter ошибка: {error}");
                }
                result != 0
            }
        };
        for ipv6 in [false, true] {
            for port in [80, 443, 2053, 2083, 2087, 2096, 8443] {
                let outbound = packet(ipv6, 6, 55000, port);
                let inbound = packet(ipv6, 6, port, 55000);
                assert!(matches(&outbound, true, false, false, ipv6));
                assert!(matches(&inbound, false, false, false, ipv6));
                assert!(!matches(&outbound, false, false, false, ipv6));
                assert!(!matches(&inbound, true, false, false, ipv6));
                assert!(!matches(&outbound, true, true, false, ipv6));
                assert!(!matches(&outbound, true, false, true, ipv6));
                assert!(!matches(
                    &packet(ipv6, 17, 55000, port),
                    true,
                    false,
                    false,
                    ipv6
                ));
            }
            assert!(!matches(
                &packet(ipv6, 6, 55000, 8080),
                true,
                false,
                false,
                ipv6
            ));
        }
    }

    #[test]
    fn official_evaluator_limits_loopback_probe_to_its_address_and_port() {
        #[link(name = "kernel32")]
        extern "system" {
            fn SetLastError(code: u32);
            fn GetLastError() -> u32;
        }
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("driver")
            .join("WinDivert.dll");
        let library = Library::load(&path).unwrap();
        type EvalFn =
            unsafe extern "C" fn(*const c_char, *const c_void, u32, *const WinDivertAddress) -> i32;
        let eval: EvalFn =
            unsafe { std::mem::transmute(library.symbol(b"WinDivertHelperEvalFilter\0").unwrap()) };
        let filter = CString::new(super::super::loopback_exchange::filter(54321).unwrap()).unwrap();
        let mut packet = vec![0; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[127, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[127, 0, 0, 1]);
        packet[20..22].copy_from_slice(&55000u16.to_be_bytes());
        packet[22..24].copy_from_slice(&54321u16.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = 2;
        let matches = |p: &[u8], outbound: bool, loopback: bool, impostor: bool| {
            let addr = WinDivertAddress::for_filter_test(outbound, loopback, impostor, false);
            unsafe {
                SetLastError(0);
                let result = eval(filter.as_ptr(), p.as_ptr().cast(), p.len() as u32, &addr);
                if result == 0 {
                    assert_eq!(GetLastError(), 0, "Ошибка WinDivertHelperEvalFilter");
                }
                result != 0
            }
        };
        assert!(matches(&packet, true, true, false));
        assert!(!matches(&packet, false, true, false));
        assert!(!matches(&packet, true, false, false));
        assert!(!matches(&packet, true, true, true));
        let mut p = packet.clone();
        p[22..24].copy_from_slice(&54322u16.to_be_bytes());
        assert!(!matches(&p, true, true, false));
        let mut p = packet.clone();
        p[12..16].copy_from_slice(&[192, 0, 2, 1]);
        assert!(!matches(&p, true, true, false));
        let mut p = packet.clone();
        p[16..20].copy_from_slice(&[192, 0, 2, 1]);
        assert!(!matches(&p, true, true, false));
        let mut p = packet.clone();
        p[9] = 17;
        p[24..26].copy_from_slice(&20u16.to_be_bytes());
        assert!(!matches(&p, true, true, false));
    }
}
