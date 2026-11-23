//! Файловый журнал интерфейса: отдельный JSONL-файл на запуск.
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_BATCH: usize = 128;
const MAX_BYTES: usize = 2 * 1024 * 1024;

pub struct JournalStore {
    directory: PathBuf,
    file: Option<File>,
    path: Option<PathBuf>,
    acknowledged: u64,
    last_batch: Vec<String>,
    damaged: bool,
    cleanup_pending: bool,
}

impl JournalStore {
    pub fn new(root: &Path, cleanup_previous: bool) -> Self {
        Self {
            directory: root.join("logs"),
            file: None,
            path: None,
            acknowledged: 0,
            last_batch: Vec::new(),
            damaged: false,
            cleanup_pending: cleanup_previous,
        }
    }

    fn create_file(&mut self) -> Result<(), String> {
        fs::create_dir_all(&self.directory)
            .map_err(|e| format!("Не удалось создать папку logs: {e}"))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("Ошибка системного времени: {e}"))?
            .as_millis();
        for attempt in 0..1000 {
            let path = self.directory.join(format!(
                "umbranet-session-{now}-{}-{attempt}.jsonl",
                std::process::id()
            ));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => {
                    if let Err(error) = file.try_lock() {
                        drop(file);
                        let _ = fs::remove_file(&path);
                        return Err(format!(
                            "Не удалось защитить файл журнала от удаления: {error}"
                        ));
                    }
                    self.path = Some(path);
                    self.file = Some(file);
                    return Ok(());
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("Не удалось создать файл журнала в logs: {e}")),
            }
        }
        Err("Не удалось выбрать свободное имя файла журнала.".into())
    }

    /// Повтор подтверждённой партии с тем же содержимым безопасен, даже если ответ IPC был потерян.
    pub fn append(&mut self, batch: u64, records: Vec<String>) -> Result<(), String> {
        if self.damaged {
            return Err("Запись журнала остановлена: не удалось восстановить файл после ошибки. Скопируйте журнал вручную.".into());
        }
        if batch == self.acknowledged && batch != 0 && records == self.last_batch {
            return Ok(());
        }
        if batch != self.acknowledged + 1 {
            return Err("Неверный порядок партий журнала.".into());
        }
        if records.is_empty()
            || records.len() > MAX_BATCH
            || records.iter().map(|s| s.len()).sum::<usize>() > MAX_BYTES
        {
            return Err("Партия журнала пустая или слишком большая.".into());
        }
        for record in &records {
            let value: serde_json::Value =
                serde_json::from_str(record).map_err(|_| "Неверный формат записи журнала.")?;
            if !value.is_object() || record.contains('\n') || record.contains('\r') {
                return Err("Неверный формат записи журнала.".into());
            }
        }
        if self.file.is_none() {
            self.create_file()?;
        }
        let file = self.file.as_mut().expect("файл открыт");
        let old_len = file
            .seek(SeekFrom::End(0))
            .map_err(|e| format!("Не удалось определить конец журнала: {e}"))?;
        let result = (|| -> std::io::Result<()> {
            for record in &records {
                file.write_all(record.as_bytes())?;
                file.write_all(b"\n")?;
            }
            file.sync_data()
        })();
        if let Err(error) = result {
            if file
                .set_len(old_len)
                .and_then(|_| file.seek(SeekFrom::Start(old_len)).map(|_| ()))
                .and_then(|_| file.sync_data())
                .is_err()
            {
                self.damaged = true;
                return Err(format!("Не удалось записать журнал ({error}) и восстановить файл. Скопируйте журнал вручную."));
            }
            return Err(format!("Не удалось записать журнал в logs: {error}"));
        }
        self.acknowledged = batch;
        self.last_batch = records;
        Ok(())
    }

    /// Удаляем только собственные журналы прошлых запусков и только после
    /// успешной записи первого события нового запуска. Другие файлы не трогаем.
    pub fn cleanup_previous(&mut self) -> Result<(), String> {
        if !self.cleanup_pending {
            return Ok(());
        }
        if self.acknowledged == 0 {
            return Err("Новый журнал ещё не сохранён".into());
        }
        let entries = fs::read_dir(&self.directory)
            .map_err(|e| format!("Не удалось прочитать папку logs: {e}"))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("Не удалось прочитать папку logs: {e}"))?;
            let path = entry.path();
            if self.path.as_deref() == Some(path.as_path()) {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(middle) = name
                .strip_prefix("umbranet-session-")
                .and_then(|s| s.strip_suffix(".jsonl"))
            else {
                continue;
            };
            let parts: Vec<_> = middle.split('-').collect();
            if parts.len() != 3
                || parts
                    .iter()
                    .any(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()))
            {
                continue;
            }
            let file_type = entry
                .file_type()
                .map_err(|e| format!("Не удалось проверить старый журнал: {e}"))?;
            if !file_type.is_file() {
                continue;
            } // не следуем символическим ссылкам
            let old = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .map_err(|e| format!("Не удалось открыть старый журнал {}: {e}", name))?;
            old.try_lock()
                .map_err(|e| format!("Старый журнал {} используется или недоступен: {e}", name))?;
            fs::remove_file(&path)
                .map_err(|e| format!("Не удалось удалить старый журнал {}: {e}", name))?;
            drop(old);
        }
        self.cleanup_pending = false;
        Ok(())
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}
