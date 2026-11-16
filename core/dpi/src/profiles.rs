//! Загрузка и выбор пресетов стратегий из папки `strtegs_Uz`.

use crate::selection::atomic_write;
use crate::strategy::Strategy;
use serde::Serialize;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

const SELECTED_FILE: &str = "selected-strategy.txt";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub id: String,
    pub name: String,
    pub file: String,
}

struct LoadedProfile {
    strategy: Strategy,
    file: String,
}

/// Набор пресетов, загруженных из папки.
pub struct Profiles {
    dir: PathBuf,
    items: Vec<LoadedProfile>,
}

impl Profiles {
    pub fn load(dir: &Path) -> Result<Self, String> {
        if !dir.exists() {
            return Ok(Self {
                dir: dir.to_path_buf(),
                items: Vec::new(),
            });
        }
        let entries = fs::read_dir(dir).map_err(|e| format!("Не удалось прочитать {}: {e}", dir.display()))?;
        let mut items = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| format!("Ошибка чтения папки стратегий: {e}"))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let text = fs::read_to_string(&path)
                .map_err(|e| format!("Не удалось прочитать {}: {e}", path.display()))?;
            let strategy = Strategy::from_json(&text)
                .map_err(|e| format!("Некорректная стратегия {}: {e}", path.display()))?;
            let file = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            items.push(LoadedProfile { strategy, file });
        }
        items.sort_by(|a, b| a.strategy.id.cmp(&b.strategy.id));
        // Дубли id делают выбор неоднозначным — отказываемся загружать такие наборы.
        for pair in items.windows(2) {
            if pair[0].strategy.id == pair[1].strategy.id {
                return Err(format!("Дублирующийся идентификатор стратегии: {}", pair[0].strategy.id));
            }
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            items,
        })
    }

    pub fn list(&self) -> Vec<Summary> {
        self.items
            .iter()
            .map(|p| Summary {
                id: p.strategy.id.clone(),
                name: p.strategy.name.clone(),
                file: p.file.clone(),
            })
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn get(&self, id: &str) -> Option<&Strategy> {
        self.items
            .iter()
            .find(|p| p.strategy.id == id)
            .map(|p| &p.strategy)
    }

    /// Идентификатор ранее выбранной стратегии, если он всё ещё существует.
    pub fn selected_id(&self) -> Option<String> {
        let text = fs::read_to_string(self.dir.join(SELECTED_FILE)).ok()?;
        let id = text.trim();
        if id.is_empty() || self.get(id).is_none() {
            return None;
        }
        Some(id.to_string())
    }

    pub fn selected(&self) -> Option<&Strategy> {
        self.selected_id().and_then(|id| self.get(&id))
    }

    pub fn select(&self, id: &str) -> Result<(), String> {
        if self.get(id).is_none() {
            return Err(format!("Неизвестная стратегия: {id}"));
        }
        fs::create_dir_all(&self.dir)
            .map_err(|e| format!("Не удалось создать {}: {e}", self.dir.display()))?;
        atomic_write(&self.dir.join(SELECTED_FILE), format!("{id}\n").as_bytes())
            .map_err(|e| format!("Не удалось сохранить выбор стратегии: {e}"))
    }

    /// При первом запуске выбирает первую доступную стратегию.
    pub fn ensure_selected(&self) -> Result<Option<String>, String> {
        if let Some(id) = self.selected_id() {
            return Ok(Some(id));
        }
        let Some(first) = self.items.first() else {
            return Ok(None);
        };
        let id = first.strategy.id.clone();
        self.select(&id)?;
        Ok(Some(id))
    }
}

/// Если файл выбора повреждён, возвращает None вместо ошибки чтения.
pub fn read_selected_lenient(dir: &Path) -> Option<String> {
    match fs::read_to_string(dir.join(SELECTED_FILE)) {
        Ok(text) => Some(text.trim().to_string()),
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(_) => None,
    }
}
