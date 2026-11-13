//! Временная пассивная диагностика: только агрегированные счётчики в памяти.
pub mod session;
#[cfg(all(windows, target_arch = "x86_64"))]
pub mod windows;
