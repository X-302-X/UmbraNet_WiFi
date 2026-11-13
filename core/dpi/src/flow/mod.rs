//! Модель и подготовка пассивного получения событий соединений.
pub mod tracker;
#[cfg(all(windows, target_arch = "x86_64"))]
pub mod windows_process;
#[cfg(any(test, all(windows, target_arch = "x86_64")))]
pub mod wire;
