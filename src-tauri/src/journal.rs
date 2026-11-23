//! Мост файлового журнала и согласованного закрытия окна.
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tauri::State;
use umbranet_dpi::journal_store::JournalStore;

struct Sessions {
    next: u64,
    stores: HashMap<u64, Result<JournalStore, String>>,
}
pub struct JournalState {
    sessions: Mutex<Sessions>,
    pub ready: AtomicBool,
    pub allow_close: AtomicBool,
}
impl JournalState {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(Sessions {
                next: 1,
                stores: HashMap::new(),
            }),
            ready: AtomicBool::new(false),
            allow_close: AtomicBool::new(false),
        }
    }
}

#[tauri::command]
pub fn journal_ready(state: State<'_, JournalState>) -> Result<u64, String> {
    let root = crate::dpi_bridge::app_root();
    let mut sessions = state
        .sessions
        .lock()
        .map_err(|_| "Файловый журнал недоступен".to_string())?;
    let id = sessions.next;
    sessions.next = id.checked_add(1).ok_or("Слишком много сессий журнала")?;
    sessions
        .stores
        .insert(id, root.map(|root| JournalStore::new(&root, id == 1)));
    state.ready.store(true, Ordering::Release);
    Ok(id)
}

#[tauri::command]
pub fn journal_write(
    state: State<'_, JournalState>,
    session: u64,
    batch: u64,
    records: Vec<String>,
) -> Result<(), String> {
    let mut sessions = state
        .sessions
        .lock()
        .map_err(|_| "Файловый журнал недоступен".to_string())?;
    let store = sessions
        .stores
        .get_mut(&session)
        .ok_or("Сессия журнала не найдена")?;
    match store {
        Ok(store) => store.append(batch, records),
        Err(error) => Err(error.clone()),
    }
}

#[tauri::command]
pub fn journal_cleanup(state: State<'_, JournalState>, session: u64) -> Result<(), String> {
    let mut sessions = state
        .sessions
        .lock()
        .map_err(|_| "Файловый журнал недоступен".to_string())?;
    let store = sessions
        .stores
        .get_mut(&session)
        .ok_or("Сессия журнала не найдена")?;
    match store {
        Ok(store) => store.cleanup_previous(),
        Err(error) => Err(error.clone()),
    }
}

#[tauri::command]
pub fn journal_finish_close(
    window: tauri::WebviewWindow,
    state: State<'_, JournalState>,
) -> Result<(), String> {
    state.allow_close.store(true, Ordering::Release);
    if let Err(error) = window.close() {
        state.allow_close.store(false, Ordering::Release);
        return Err(format!("Не удалось закрыть окно: {error}"));
    }
    Ok(())
}
