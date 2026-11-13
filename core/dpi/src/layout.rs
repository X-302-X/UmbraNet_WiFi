//! Пути приложения в выбранной папке установки.
use std::path::{Path, PathBuf};

pub struct AppPaths {
    root: PathBuf,
}
impl AppPaths {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }
    pub fn dpi_dir(&self) -> PathBuf {
        self.root.join("core").join("dpi")
    }
    pub fn legacy_dpi_dir(&self) -> PathBuf {
        self.root.join("data").join("core").join("dpi")
    }
    pub fn driver_dll(&self) -> PathBuf {
        self.dpi_dir().join("driver").join("WinDivert.dll")
    }
}
