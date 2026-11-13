use crate::catalog::Catalog;
use crate::domain::normalize_domain;
use crate::strategy::Strategy;
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

pub const PROTECTED_BROWSERS: [&str; 3] = ["chrome.exe", "msedge.exe", "firefox.exe"];

#[derive(Debug, Clone, Default)]
pub struct Selection {
    services: BTreeSet<String>,
    manual_domains: BTreeSet<String>,
    manual_processes: BTreeSet<String>,
}

/// Независимая копия целей и стратегии; последующие изменения Selection на неё не влияют.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub services: BTreeSet<String>,
    pub domains: BTreeSet<String>,
    pub manual_processes: BTreeSet<String>,
    pub strategy: Strategy,
}

impl Selection {
    pub fn set_service(
        &mut self,
        catalog: &Catalog,
        id: &str,
        enabled: bool,
    ) -> Result<(), String> {
        if !catalog.services.contains_key(id) {
            return Err(format!("Неизвестный сервис: {id}"));
        }
        if enabled {
            self.services.insert(id.into());
        } else {
            self.services.remove(id);
        }
        Ok(())
    }
    pub fn add_domain(&mut self, input: &str) -> Result<(), String> {
        self.manual_domains.insert(normalize_domain(input)?);
        Ok(())
    }
    pub fn remove_domain(&mut self, input: &str) -> Result<bool, String> {
        Ok(self.manual_domains.remove(&normalize_domain(input)?))
    }
    pub fn add_process(&mut self, input: &str) -> Result<(), String> {
        let name = normalize_process(input)?;
        // Браузеры всегда видны отдельно; повторное добавление не делает весь их трафик целью.
        if !PROTECTED_BROWSERS.contains(&name.as_str()) {
            self.manual_processes.insert(name);
        }
        Ok(())
    }
    pub fn remove_process(&mut self, input: &str) -> Result<bool, String> {
        let name = normalize_process(input)?;
        if PROTECTED_BROWSERS.contains(&name.as_str()) {
            return Err("Защищённый браузер нельзя удалить".into());
        }
        Ok(self.manual_processes.remove(&name))
    }
    pub fn selected_services(&self) -> &BTreeSet<String> {
        &self.services
    }
    pub fn manual_domains(&self) -> &BTreeSet<String> {
        &self.manual_domains
    }
    pub fn manual_processes(&self) -> &BTreeSet<String> {
        &self.manual_processes
    }
    pub fn visible_processes(&self) -> BTreeSet<String> {
        self.manual_processes
            .iter()
            .cloned()
            .chain(PROTECTED_BROWSERS.iter().map(|s| s.to_string()))
            .collect()
    }
    pub fn active_domains(&self, catalog: &Catalog) -> Result<BTreeSet<String>, String> {
        let mut result = self.manual_domains.clone();
        for id in &self.services {
            let service = catalog
                .services
                .get(id)
                .ok_or_else(|| format!("Сервис отсутствует в каталоге: {id}"))?;
            result.extend(service.domains.iter().cloned());
        }
        Ok(result)
    }
    pub fn snapshot(&self, catalog: &Catalog, strategy: &Strategy) -> Result<Snapshot, String> {
        Ok(Snapshot {
            services: self.services.clone(),
            domains: self.active_domains(catalog)?,
            manual_processes: self.manual_processes.clone(),
            strategy: strategy.clone(),
        })
    }
    /// Публикует текущий список, не меняя уже созданные снимки.
    pub fn write_active_domains(&self, catalog: &Catalog, path: &Path) -> Result<(), String> {
        let contents = self
            .active_domains(catalog)?
            .into_iter()
            .map(|d| format!("{d}\n"))
            .collect::<String>();
        atomic_write(path, contents.as_bytes()).map_err(|e| e.to_string())
    }
}

fn normalize_process(input: &str) -> Result<String, String> {
    let name = input.trim().to_ascii_lowercase();
    if name.len() > 255
        || name.len() <= 4
        || !name.ends_with(".exe")
        || name.starts_with('.')
        || name
            .bytes()
            .any(|b| b < 32 || b == 127 || b"\\/:*?\"<>|".contains(&b))
    {
        return Err(format!("Некорректное имя процесса: {input}"));
    }
    Ok(name)
}

pub(crate) fn atomic_write(path: &Path, contents: &[u8]) -> io::Result<()> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temp = parent.join(format!(
        ".umbranet-active-{}-{}.tmp",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}
