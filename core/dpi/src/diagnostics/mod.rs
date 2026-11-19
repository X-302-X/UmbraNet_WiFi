//! Временная пассивная диагностика: только агрегированные счётчики в памяти.
pub mod session;
pub mod tcp_stats;
#[cfg(all(windows, target_arch = "x86_64"))]
pub mod windows;
