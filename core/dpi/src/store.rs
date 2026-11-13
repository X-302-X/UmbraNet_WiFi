use crate::catalog::Catalog;
use crate::selection::{atomic_write, Selection, PROTECTED_BROWSERS};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

const DEFAULT_CATALOG: &str = include_str!("../services.json");

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSelection {
    version: u32,
    services: BTreeSet<String>,
    domains: BTreeSet<String>,
    processes: BTreeSet<String>,
}

#[derive(Debug, Serialize)]
pub struct View {
    pub services: BTreeSet<String>,
    pub domains: BTreeSet<String>,
    pub processes: BTreeSet<String>,
    pub protected_processes: BTreeSet<String>,
    pub active_domains: BTreeSet<String>,
    pub service_domains: BTreeMap<String, Vec<String>>,
    pub warning: Option<String>,
}

pub struct Store {
    dir: PathBuf,
    catalog: Catalog,
    selection: Selection,
    warning: Option<String>,
}

impl Store {
    pub fn open(dir: &Path) -> Result<Self, String> {
        fs::create_dir_all(dir)
            .map_err(|e| format!("Не удалось создать {}: {e}", dir.display()))?;
        let catalog_path = dir.join("services.json");
        if !catalog_path.exists() {
            atomic_write(&catalog_path, DEFAULT_CATALOG.as_bytes())
                .map_err(|e| format!("Не удалось сохранить каталог: {e}"))?;
        }
        let catalog_text = fs::read_to_string(&catalog_path)
            .map_err(|e| format!("Не удалось прочитать каталог: {e}"))?;
        let catalog =
            Catalog::from_json(&catalog_text).map_err(|e| format!("Ошибка каталога: {e}"))?;
        let selection = match fs::read_to_string(dir.join("selection.json")) {
            Ok(text) => Self::decode_selection(&catalog, &text)?,
            Err(e) if e.kind() == ErrorKind::NotFound => Selection::default(),
            Err(e) => return Err(format!("Не удалось прочитать выбор: {e}")),
        };
        let mut store = Self {
            dir: dir.to_path_buf(),
            catalog,
            selection,
            warning: None,
        };
        store.refresh_active();
        Ok(store)
    }

    fn decode_selection(catalog: &Catalog, text: &str) -> Result<Selection, String> {
        let stored: StoredSelection =
            serde_json::from_str(text).map_err(|e| format!("Ошибка файла выбора: {e}"))?;
        if stored.version != 1 {
            return Err("Неизвестная версия файла выбора".into());
        }
        let mut selection = Selection::default();
        for id in stored.services {
            selection.set_service(catalog, &id, true)?;
        }
        for domain in stored.domains {
            selection.add_domain(&domain)?;
        }
        for process in stored.processes {
            selection.add_process(&process)?;
        }
        Ok(selection)
    }

    fn refresh_active(&mut self) {
        self.warning = self
            .selection
            .write_active_domains(&self.catalog, &self.dir.join("active-domains.txt"))
            .err()
            .map(|e| format!("Выбор сохранён, но список активных доменов не обновлён: {e}"));
    }

    pub fn view(&self) -> Result<View, String> {
        Ok(View {
            services: self.selection.selected_services().clone(),
            domains: self.selection.manual_domains().clone(),
            processes: self.selection.manual_processes().clone(),
            protected_processes: PROTECTED_BROWSERS.iter().map(|p| p.to_string()).collect(),
            active_domains: self.selection.active_domains(&self.catalog)?,
            service_domains: self
                .selection
                .selected_services()
                .iter()
                .filter_map(|id| {
                    self.catalog
                        .services
                        .get(id)
                        .map(|service| (id.clone(), service.domains.clone()))
                })
                .collect(),
            warning: self.warning.clone(),
        })
    }

    /// Файл выбора — источник истины. Производный список восстанавливается при открытии.
    pub fn apply(&mut self, action: &str, value: &str, enabled: bool) -> Result<View, String> {
        let mut next = self.selection.clone();
        match action {
            "service" => next.set_service(&self.catalog, value, enabled)?,
            "add_domain" => next.add_domain(value)?,
            "remove_domain" => {
                next.remove_domain(value)?;
            }
            "add_process" => next.add_process(value)?,
            "remove_process" => {
                next.remove_process(value)?;
            }
            _ => return Err("Неизвестное действие".into()),
        }
        let data = StoredSelection {
            version: 1,
            services: next.selected_services().clone(),
            domains: next.manual_domains().clone(),
            processes: next.manual_processes().clone(),
        };
        let json = serde_json::to_vec_pretty(&data).map_err(|e| e.to_string())?;
        atomic_write(&self.dir.join("selection.json"), &json)
            .map_err(|e| format!("Не удалось сохранить выбор: {e}"))?;
        self.selection = next;
        self.refresh_active();
        self.view()
    }
}
