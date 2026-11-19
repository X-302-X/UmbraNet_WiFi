"use strict";

(() => {
  const list = document.querySelector("#journal-list");
  const search = document.querySelector("#journal-search");
  const filter = document.querySelector("#journal-filter");
  const count = document.querySelector("#journal-count");
  const state = document.querySelector("#journal-state");
  const pauseButton = document.querySelector("#journal-pause");
  const report = document.querySelector("#journal-report");
  const mode = document.querySelector("#journal-export-mode");
  const copy = document.querySelector("#journal-copy");
  const copyStatus = document.querySelector("#journal-copy-status");
  const metrics = {
    total: document.querySelector("#journal-total"),
    flow: document.querySelector("#journal-flows"),
    system: document.querySelector("#journal-system"),
    error: document.querySelector("#journal-errors")
  };
  const entries = [];
  const BATCH_SIZE = 200;
  let displayLimit = BATCH_SIZE;
  const totals = {flow: 0, system: 0, error: 0};
  const more = document.querySelector("#journal-more");
  let recording = true;
  let renderPending = false;
  let session = null;
  let lastSequence = 0;
  let skipNextView = false;

  function append(kind, text, details = null, timestamp = Date.now()) {
    entries.push({kind, text: String(text), details, timestamp});
    if (Object.hasOwn(totals, kind)) totals[kind]++;
    if (!renderPending) {
      renderPending = true;
      requestAnimationFrame(() => { renderPending = false; render(); });
    }
  }
  function add(kind, text, details = null, timestamp = Date.now()) {
    if (recording) append(kind, text, details, timestamp);
  }
  // Нажатие Stop и ошибки видны даже при ручной паузе.
  function addRequired(kind, text) { append(kind, text); }
  function startForDpi() {
    recording = true;
    append("system", "Запись журнала включена после запуска DPI.");
    render();
  }
  function stopAfterDpi() {
    append("system", "Запись журнала остановлена после остановки DPI.");
    recording = false;
    render();
  }
  function processName(name, redacted) {
    if (!name) return "не определён";
    // Имя процесса также может содержать личные данные; в сокращённом отчёте
    // не выдаём похожие на адрес/путь значения под видом имени программы.
    if (redacted && (/\d{1,3}(?:\.\d{1,3}){3}/.test(name) || /[:\\/@]/.test(name))) return "[имя скрыто]";
    return name;
  }
  function endpoint(ip, port) {
    if (!ip) return "неизвестно";
    const host = ip.includes(":") ? `[${ip}]` : ip;
    return port == null ? host : `${host}:${port}`;
  }
  // В сокращённый отчёт попадают только заранее известные системные сообщения.
  // Произвольная ошибка или текст системы могут содержать любые личные данные.
  const SAFE_SYSTEM_MESSAGES = new Set([
    "Приложение открыто. Журнал хранится только в памяти.",
    "Запись журнала включена после запуска DPI.",
    "Запись журнала остановлена после остановки DPI.",
    "Пользователь нажал «Старт» DPI.",
    "Пользователь нажал «Стоп» DPI.",
    "Пользователь приостановил журнал.",
    "Пользователь продолжил журнал; события за время паузы недоступны.",
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
    let text = `${d.established ? "Новое соединение" : "Соединение закрыто (не обязательно обрыв)"} · ${processName(d.process, !full)} · PID ${d.pid ?? "—"} · ${d.protocol || "протокол неизвестен"} · порт ${d.remote_port ?? "—"}`;
    if (d.selected_process) text += " · предварительно выбранный процесс";
    if (full && (d.local_ip || d.remote_ip)) text += ` · ${endpoint(d.local_ip, d.local_port)} → ${endpoint(d.remote_ip, d.remote_port)}`;
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
    part.title = "Может содержать личные данные";
    part.textContent = String(text);
    container.append(part);
  }
  // Это только подсветка наиболее типичных шаблонов, не надёжный детектор
  // всех личных данных. Все узлы создаются через textContent, без HTML.
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
      if (d.process) sensitive(content, processName(d.process, false));
      else { const missing = document.createElement("span"); missing.textContent = "процесс не определён"; content.append(missing); }
      if (d.pid != null) sensitive(content, ` · PID ${d.pid}`);
      const info = document.createElement("span");
      info.textContent = ` · ${d.protocol || "протокол неизвестен"} · порт ${d.remote_port ?? "—"}${d.selected_process ? " · предварительно выбранный процесс" : ""}`;
      content.append(info);
      if (d.local_ip || d.remote_ip) sensitive(content, ` · ${endpoint(d.local_ip, d.local_port)} → ${endpoint(d.remote_ip, d.remote_port)}`);
    } else highlightedText(content, item.text);
    const kind = document.createElement("span");
    kind.className = "journal-kind";
    kind.textContent = item.kind === "error" ? "✕ ОШИБКА" : item.kind === "flow" ? "СОЕДИНЕНИЕ" : "ПРОГРАММА";
    row.append(stamp, content, kind);
    return row;
  }
  function render() {
    const query = search.value.trim().toLocaleLowerCase("ru");
    const fragment = document.createDocumentFragment();
    const stats = {total: entries.length, ...totals};
    let matched = 0, shown = 0;
    // Новые записи сверху; старые сохраняются до очистки или закрытия приложения.
    for (let i = entries.length - 1; i >= 0; i--) {
      const item = entries[i];
      if (filter.value !== "all" && item.kind !== filter.value) continue;
      if (query && !summary(item, true).toLocaleLowerCase("ru").includes(query)) continue;
      matched++;
      if (shown >= displayLimit) continue;
      fragment.append(makeRow(item));
      shown++;
    }
    list.replaceChildren(fragment);
    if (!shown) {
      const empty = document.createElement("div");
      empty.className = "journal-empty";
      empty.textContent = query || filter.value !== "all" ? "Ничего не найдено. Измените поиск или фильтр." : "Пока нет событий.\nЗдесь появятся действия программы и результаты проверки.";
      list.append(empty);
    }
    for (const [key, node] of Object.entries(metrics)) node.textContent = String(stats[key]);
    count.textContent = `Показано: ${shown}${matched > shown ? ` из ${matched}` : ""}`;
    more.hidden = shown >= matched;
    state.textContent = recording ? "● Запись включена" : "⏸ Запись на паузе";
    state.classList.toggle("is-paused", !recording);
    pauseButton.textContent = recording ? "⏸ Пауза" : "▶ Продолжить";
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
  search.addEventListener("input", () => { displayLimit = BATCH_SIZE; render(); });
  filter.addEventListener("change", () => { displayLimit = BATCH_SIZE; render(); });
  more.addEventListener("click", () => { displayLimit += BATCH_SIZE; render(); });
  pauseButton.addEventListener("click", () => {
    if (recording) { add("system", "Пользователь приостановил журнал."); recording = false; }
    else { recording = true; skipNextView = true; add("system", "Пользователь продолжил журнал; события за время паузы недоступны."); }
    render();
  });
  document.querySelector("#journal-clear").addEventListener("click", async () => {
    try {
      if (typeof window.__TAURI_INTERNALS__?.invoke === "function") await window.umbraDiagnosticClear();
      entries.length = 0; totals.flow = 0; totals.system = 0; totals.error = 0;
      displayLimit = BATCH_SIZE; report.value = ""; copy.disabled = true;
      copyStatus.textContent = "Журнал и сохранённые события проверки очищены.";
    } catch (error) {
      copyStatus.textContent = `Не удалось очистить события проверки: ${String(error)}`;
    }
    render();
  });
  mode.addEventListener("change", () => { report.value = ""; copy.disabled = true; copyStatus.textContent = "Подготовьте отчёт заново."; });
  document.querySelector("#journal-prepare").addEventListener("click", () => {
    const full = mode.value === "full";
    report.value = [`UmbraNet WiFi — журнал (${full ? "подробный, содержит личные данные" : "без полей IP и произвольных подробностей"})`, `Записей: ${entries.length}. Все записи независимо от фильтра.`, "Имена программ и PID могут быть личными данными. Пассивная проверка не подтверждает обход, домены или голос.", ...entries.map(e => `[${time(e.timestamp)}] ${summary(e, full)}`)].join("\n");
    copy.disabled = false; copyStatus.textContent = "Проверьте текст перед отправкой.";
  });
  copy.addEventListener("click", async () => {
    try {
      if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
      await navigator.clipboard.writeText(report.value);
      copyStatus.textContent = "Отчёт скопирован. Отправка выполняется только вами.";
    } catch {
      report.focus(); report.select();
      copyStatus.textContent = "Автоматическое копирование недоступно. Текст выделен — нажмите Ctrl+C.";
    }
  });
  add("system", "Приложение открыто. Журнал хранится только в памяти.");
  render();
})();
