"use strict";

(() => {
  const list = document.querySelector("#journal-list");
  const search = document.querySelector("#journal-search");
  const filter = document.querySelector("#journal-filter");
  const menu = document.querySelector("#journal-menu");
  const exportButton = document.querySelector("#journal-export-button");
  const actionStatus = document.querySelector("#journal-action-status");
  const saveStatus = document.querySelector("#journal-save-status");
  const invoke = window.__TAURI_INTERNALS__?.invoke;
  const dialog = document.querySelector("#journal-export-dialog");
  const title = document.querySelector("#journal-export-title");
  const report = document.querySelector("#journal-report");
  const copy = document.querySelector("#journal-copy");
  const copyStatus = document.querySelector("#journal-copy-status");
  const entries = [];
  let recording = true;
  let renderPending = false;
  let session = null;
  let lastSequence = 0;
  let skipNextView = false;

  // Очередь принадлежит только приложению Tauri, а не браузерному предпросмотру.
  const pending = [];
  let sessionId = null, batchNumber = 1, writing = null, retryTimer = null, closing = false, cleanupFailed = false;
  function saveError(error) {
    saveStatus.textContent = `Журнал не сохранён в logs: ${String(error).slice(0, 300)}. Записи остаются в окне; можно скопировать их вручную.`;
    saveStatus.hidden = false;
  }
  function clearSaveError() { saveStatus.hidden = true; saveStatus.textContent = ""; }
  function scheduleSave(delay = 0) {
    if (typeof invoke !== "function" || retryTimer !== null || writing || closing) return;
    retryTimer = setTimeout(() => { retryTimer = null; void flush(); }, delay);
  }
  async function flush() {
    if (writing) return writing;
    writing = (async () => {
      try {
        if (sessionId === null) sessionId = await invoke("journal_ready");
        while (pending.length) {
          const records = [];
          let bytes = 0;
          const encoder = new TextEncoder();
          for (const record of pending) {
            const size = encoder.encode(record).length;
            if (size > 2 * 1024 * 1024) throw new Error("Одна запись превышает 2 МБ");
            if (records.length === 64 || bytes + size > 2 * 1024 * 1024) break;
            records.push(record); bytes += size;
          }
          await invoke("journal_write", {session: sessionId, batch: batchNumber, records});
          pending.splice(0, records.length);
          batchNumber++;
        }
        try {
          await invoke("journal_cleanup", {session: sessionId});
          cleanupFailed = false;
          clearSaveError();
        } catch (error) {
          cleanupFailed = true;
          saveStatus.textContent = `Не удалось удалить журнал прошлого сеанса: ${String(error).slice(0, 300)}. Новый журнал сохраняется; повторим попытку.`;
          saveStatus.hidden = false;
        }
        return true;
      } catch (error) {
        saveError(error);
        return false;
      }
    })();
    const result = await writing;
    writing = null;
    if ((pending.length || cleanupFailed) && !closing) scheduleSave(result && !cleanupFailed ? 0 : 5000);
    return result;
  }
  function queueForFile(entry) {
    if (typeof invoke !== "function") return;
    pending.push(JSON.stringify({время: time(entry.timestamp), тип: entry.kind, событие: summary(entry, true)}));
    // Ошибка удаления старого файла не должна задерживать запись новых событий.
    if (cleanupFailed && retryTimer !== null) { clearTimeout(retryTimer); retryTimer = null; }
    scheduleSave();
  }
  if (typeof invoke === "function") {
    window.addEventListener("umbra-journal-close-request", async () => {
      if (closing) return;
      closing = true;
      if (retryTimer !== null) { clearTimeout(retryTimer); retryTimer = null; }
      // Не зависаем при отказавшем IPC; перед потерей данных спрашиваем пользователя.
      let timeout;
      const ok = await Promise.race([flush(), new Promise(resolve => { timeout = setTimeout(() => resolve(false), 5000); })]);
      clearTimeout(timeout);
      if ((!ok || pending.length) && !window.confirm("Не удалось сохранить все записи в папку logs. Закрыть приложение без них? Можно отменить и скопировать журнал вручную.")) {
        closing = false;
        scheduleSave(5000);
        return;
      }
      try { await invoke("journal_finish_close"); }
      catch (error) { closing = false; saveError(`Не удалось закрыть окно: ${error}`); scheduleSave(5000); }
    });
  }

  function append(kind, text, details = null, timestamp = Date.now()) {
    const entry = {kind, text: String(text), details, timestamp};
    entries.push(entry);
    queueForFile(entry);
    if (!renderPending) {
      renderPending = true;
      requestAnimationFrame(() => { renderPending = false; render(true); });
    }
  }
  function add(kind, text, details = null, timestamp = Date.now()) {
    if (recording) append(kind, text, details, timestamp);
  }
  // Нажатие Stop и ошибки видны даже после предыдущей остановки записи.
  function addRequired(kind, text) { append(kind, text); }
  function startForDpi() {
    if (!recording) skipNextView = true;
    recording = true;
    append("system", "Запись журнала включена после запуска DPI.");
  }
  function stopAfterDpi() {
    append("system", "Запись журнала остановлена после остановки DPI.");
    recording = false;
  }
  function processName(name) {
    return name || "не определён";
  }
  function endpoint(ip, port) {
    if (!ip) return "неизвестно";
    const host = ip.includes(":") ? `[${ip}]` : ip;
    return port == null ? host : `${host}:${port}`;
  }
  // Свободный текст может содержать любые адреса, пути или личные сведения.
  // Сокращённый вариант включает только известные безопасные системные строки.
  const SAFE_SYSTEM_MESSAGES = new Set([
    "Приложение открыто.",
    "Запись журнала включена после запуска DPI.",
    "Запись журнала остановлена после остановки DPI.",
    "Пользователь нажал «Старт» DPI.",
    "Пользователь нажал «Стоп» DPI.",
    "Пользователь запустил пассивную FLOW-проверку.",
    "Пользователь запустил пассивную TCP-проверку.",
    "Пользователь запросил остановку пассивной проверки.",
    "Пассивная проверка: запуск.",
    "Пассивная проверка работает.",
    "Пассивная проверка: запрошена остановка.",
    "Пассивная проверка остановлена.",
    "Доступ к состоянию пассивной проверки восстановлен.",
    "DPI запущен."
  ]);
  function summary(e, full) {
    if (e.kind === "error") return full ? e.text : "Ошибка: подробности скрыты";
    if (e.kind !== "flow") return full || SAFE_SYSTEM_MESSAGES.has(e.text) ? e.text : "Системное событие: подробности скрыты";
    const d = e.details || {};
    const event = d.established ? "Новое соединение" : "Соединение закрыто (не обязательно обрыв)";
    // В сокращённый отчёт не попадают произвольные значения из события.
    if (!full) return `${event} · ${["TCP", "UDP"].includes(d.protocol) ? d.protocol : "протокол неизвестен"}`;
    let text = `${event} · ${processName(d.process)} · PID ${d.pid ?? "—"} · ${d.protocol || "протокол неизвестен"} · порт ${d.remote_port ?? "—"}`;
    if (d.selected_process) text += " · предварительно выбранный процесс";
    if (d.local_ip || d.remote_ip) text += ` · ${endpoint(d.local_ip, d.local_port)} → ${endpoint(d.remote_ip, d.remote_port)}`;
    return text;
  }
  function time(ms, short = false) {
    const d = new Date(ms);
    if (Number.isNaN(d.getTime())) return "время неизвестно";
    return short ? d.toLocaleTimeString("ru-RU") : d.toLocaleString("ru-RU");
  }
  function sensitive(container, text) {
    const part = document.createElement("span");
    part.className = "journal-sensitive";
    part.textContent = String(text);
    container.append(part);
  }
  // Подсветка типичных шаблонов не гарантирует обнаружение всех личных данных.
  // Текст никогда не интерпретируется как HTML.
  function highlightedText(container, value) {
    const text = String(value);
    const pattern = /(?:[a-z][a-z0-9+.-]*:\/\/[^\s<>"']+|[a-z]:[\\/][^\r\n<>|"']+|\\\\[^\s<>|"']+(?:[\\/][^\r\n<>|"']+)?|\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b|\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:[a-f0-9]{0,4}:){2,}[a-f0-9:.%]*|\b[\w.-]+\.exe\b|\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b)/gi;
    let from = 0;
    for (const match of text.matchAll(pattern)) {
      if (match.index > from) {
        const plain = document.createElement("span");
        plain.textContent = text.slice(from, match.index);
        container.append(plain);
      }
      sensitive(container, match[0]);
      from = match.index + match[0].length;
    }
    if (from < text.length) {
      const plain = document.createElement("span");
      plain.textContent = text.slice(from);
      container.append(plain);
    }
  }
  function makeRow(item) {
    const row = document.createElement("div");
    row.className = `journal-row${item.kind === "error" ? " is-error" : ""}`;
    const stamp = document.createElement("time");
    stamp.className = "journal-time";
    stamp.textContent = time(item.timestamp, true);
    stamp.title = time(item.timestamp);
    const content = document.createElement("div");
    content.className = "journal-content";
    const d = item.details || {};
    if (item.kind === "flow") {
      const event = document.createElement("span");
      event.textContent = d.established ? "Новое соединение · " : "Соединение закрыто (не обязательно обрыв) · ";
      content.append(event);
      if (d.process) sensitive(content, processName(d.process));
      else { const missing = document.createElement("span"); missing.textContent = "процесс не определён"; content.append(missing); }
      if (d.pid != null) sensitive(content, ` · PID ${d.pid}`);
      const info = document.createElement("span");
      info.textContent = ` · ${d.protocol || "протокол неизвестен"} · порт ${d.remote_port ?? "—"}${d.selected_process ? " · предварительно выбранный процесс" : ""}`;
      content.append(info);
      if (d.local_ip || d.remote_ip) sensitive(content, ` · ${endpoint(d.local_ip, d.local_port)} → ${endpoint(d.remote_ip, d.remote_port)}`);
    } else highlightedText(content, item.text);
    row.append(stamp, content);
    return row;
  }
  function render(preservePosition = false) {
    const oldTop = list.scrollTop;
    const oldHeight = list.scrollHeight;
    const query = search.value.trim().toLocaleLowerCase("ru");
    const fragment = document.createDocumentFragment();
    let shown = 0;
    for (let i = entries.length - 1; i >= 0; i--) {
      const item = entries[i];
      if (filter.value !== "all" && item.kind !== filter.value) continue;
      if (query && !summary(item, true).toLocaleLowerCase("ru").includes(query)) continue;
      fragment.append(makeRow(item)); shown++;
    }
    list.replaceChildren(fragment);
    if (!shown) {
      const empty = document.createElement("div"); empty.className = "journal-empty";
      empty.textContent = query || filter.value !== "all" ? "Ничего не найдено" : "Пока нет событий";
      list.append(empty);
    }
    // При чтении старых событий новые строки не должны сбрасывать позицию.
    if (preservePosition && oldTop > 2) list.scrollTop = oldTop + Math.max(0, list.scrollHeight - oldHeight);
    else list.scrollTop = 0;
  }
  function addFlowView(view) {
    if (!view || !view.session_id) return;
    if (session !== view.session_id) { session = view.session_id; lastSequence = 0; skipNextView = false; }
    const events = view.events || [];
    if (skipNextView) {
      if (events.length) lastSequence = events[events.length - 1].sequence;
      skipNextView = false;
      return;
    }
    if (events.length && events[0].sequence > lastSequence + 1 && recording) {
      add("system", `Часть событий проверки не попала в журнал: пропущено ${events[0].sequence - lastSequence - 1}.`);
    }
    for (const event of events) {
      if (event.sequence <= lastSequence) continue;
      lastSequence = event.sequence;
      add("flow", "", event, event.observed_ms);
    }
  }
  window.umbraJournal = { add, addRequired, addFlowView, startForDpi, stopAfterDpi };
  search.addEventListener("input", () => render());
  filter.addEventListener("change", () => render());

  function closeMenu() {
    menu.hidden = true;
    exportButton.setAttribute("aria-expanded", "false");
  }
  function openMenu(x, y, above = false) {
    menu.hidden = false;
    const box = menu.getBoundingClientRect();
    menu.style.left = `${Math.max(4, Math.min(x, window.innerWidth - box.width - 4))}px`;
    menu.style.top = `${Math.max(4, Math.min(above ? y - box.height - 4 : y, window.innerHeight - box.height - 4))}px`;
    exportButton.setAttribute("aria-expanded", "true");
  }
  exportButton.addEventListener("click", () => {
    if (!menu.hidden) { closeMenu(); return; }
    const box = exportButton.getBoundingClientRect();
    openMenu(box.left, box.top, true);
    document.querySelector("#journal-export-full").focus();
  });
  list.addEventListener("contextmenu", event => { event.preventDefault(); openMenu(event.clientX, event.clientY); });
  list.addEventListener("keydown", event => {
    if (event.key === "ContextMenu" || (event.shiftKey && event.key === "F10")) {
      event.preventDefault(); const box = list.getBoundingClientRect(); openMenu(box.left + 15, box.top + 15);
      document.querySelector("#journal-export-redacted").focus();
    }
  });
  document.addEventListener("click", event => { if (!menu.contains(event.target) && !exportButton.contains(event.target)) closeMenu(); });
  document.addEventListener("keydown", event => { if (event.key === "Escape" && !menu.hidden) { closeMenu(); exportButton.focus(); } });
  let statusTimer;
  async function prepare(full) {
    closeMenu();
    title.textContent = full ? "Со всеми данными · содержит личные данные" : "Без IP, процессов и PID";
    report.value = [`UmbraNet WiFi — журнал (${full ? "со всеми данными" : "без IP, процессов, PID, портов и произвольных подробностей"})`, `Записей: ${entries.length}. Все записи независимо от фильтра.`, full ? "Отчёт содержит личные данные." : "Время и тип событий остаются и тоже могут быть чувствительными. Полная анонимность не гарантируется.", "Пассивная проверка не подтверждает обход, домены или голос.", ...entries.map(e => `[${time(e.timestamp)}] ${summary(e, full)}`)].join("\n");
    copyStatus.textContent = "";
    clearTimeout(statusTimer);
    try {
      if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
      await navigator.clipboard.writeText(report.value);
      actionStatus.textContent = "Скопировано";
      statusTimer = setTimeout(() => { actionStatus.textContent = ""; }, 3000);
    } catch {
      actionStatus.textContent = "";
      if (!dialog.open) dialog.showModal();
      report.focus(); report.select();
      copyStatus.textContent = "Нажмите Ctrl+C";
    }
  }
  document.querySelector("#journal-export-redacted").addEventListener("click", () => prepare(false));
  document.querySelector("#journal-export-full").addEventListener("click", () => prepare(true));
  document.querySelector("#journal-export-close").addEventListener("click", () => dialog.close());
  copy.addEventListener("click", async () => {
    try {
      if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
      await navigator.clipboard.writeText(report.value);
      copyStatus.textContent = "Скопировано";
    } catch {
      report.focus(); report.select();
      copyStatus.textContent = "Нажмите Ctrl+C";
    }
  });
  add("system", "Приложение открыто.");
  render();
})();
