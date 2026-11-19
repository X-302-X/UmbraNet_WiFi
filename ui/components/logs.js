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
  const entries = [];
  const LIMIT = 500;
  let dropped = 0;
  let recording = true;
  let renderPending = false;
  let session = null;
  let lastSequence = 0;
  let skipNextView = false;

  function append(kind, text, details = null, timestamp = Date.now()) {
    if (entries.length === LIMIT) { entries.shift(); dropped++; }
    entries.push({kind, text: String(text), details, timestamp});
    if (!renderPending) {
      renderPending = true;
      requestAnimationFrame(() => { renderPending = false; render(); });
    }
  }
  function add(kind, text, details = null, timestamp = Date.now()) {
    if (recording) append(kind, text, details, timestamp);
  }
  // Действие Stop и ошибки его выполнения видны даже при ручной паузе журнала.
  function addRequired(kind, text) { append(kind, text); }
  function startForDpi() {
    recording = true;
    append("system", "Запись журнала включена после запуска DPI.");
    render();
  }
  // Вызывать только после подтверждённой остановки движка и обработки ошибок.
  function stopAfterDpi() {
    append("system", "Запись журнала остановлена после остановки DPI.");
    recording = false;
    render();
  }
  function processName(name, redacted) {
    if (!name) return "не определён";
    // Произвольное имя может само содержать адрес; в отчёте без IP скрываем его целиком.
    if (redacted && (/\d{1,3}(?:\.\d{1,3}){3}/.test(name) || name.includes(":"))) return "[имя скрыто]";
    return name;
  }
  function endpoint(ip, port) { return `${ip.includes(":") ? `[${ip}]` : ip}:${port}`; }
  function summary(e, full) {
    if (e.kind === "error") return full ? e.text : "Ошибка: подробности скрыты в отчёте без IP";
    if (e.kind !== "flow") return e.text;
    const d = e.details;
    const process = processName(d.process, !full);
    let text = `${d.established ? "Новое соединение" : "Соединение закрыто (не обязательно обрыв)"} · ${process} · PID ${d.pid} · ${d.protocol || "протокол неизвестен"} · порт ${d.remote_port ?? "—"}`;
    if (d.selected_process) text += " · предварительно выбранный процесс";
    if (full && d.local_ip && d.remote_ip) text += ` · ${endpoint(d.local_ip, d.local_port)} → ${endpoint(d.remote_ip, d.remote_port)}`;
    return text;
  }
  function time(ms) { const d = new Date(ms); return Number.isNaN(d.getTime()) ? "время неизвестно" : d.toLocaleString("ru-RU"); }
  function render() {
    const query = search.value.trim().toLocaleLowerCase("ru");
    const fragment = document.createDocumentFragment();
    let shown = 0;
    for (const item of entries) {
      if (filter.value !== "all" && item.kind !== filter.value) continue;
      if (query && !summary(item, true).toLocaleLowerCase("ru").includes(query)) continue;
      shown++;
      const row = document.createElement("div"); row.className = `journal-row ${item.kind === "error" ? "is-error" : ""}`;
      const stamp = document.createElement("time"); stamp.className = "journal-time"; stamp.textContent = time(item.timestamp);
      const content = document.createElement("div"); content.className = "journal-content";
      const d = item.details;
      const text = document.createElement("span");
      if (item.kind === "flow") {
        text.textContent = d.established ? "• Новое соединение · " : "• Соединение закрыто (не обязательно обрыв) · ";
        content.append(text);
        const name = document.createElement("span"); name.className = "journal-sensitive"; name.textContent = processName(d.process, false); content.append(name);
        const meta = document.createElement("span"); meta.textContent = ` · PID ${d.pid} · ${d.protocol || "протокол неизвестен"} · порт ${d.remote_port ?? "—"}${d.selected_process ? " · предварительно выбранный процесс" : ""}`; content.append(meta);
      } else {
        text.textContent = (item.kind === "error" ? "✕ " : "• ") + item.text;
        content.append(text);
      }
      if (item.kind === "flow" && d?.local_ip && d?.remote_ip) {
        const ips = document.createElement("span"); ips.className = "journal-sensitive";
        ips.textContent = ` · ${endpoint(d.local_ip, d.local_port)} → ${endpoint(d.remote_ip, d.remote_port)}`;
        content.append(ips);
      }
      row.append(stamp, content); fragment.append(row);
    }
    list.replaceChildren(fragment);
    if (!shown) { const empty = document.createElement("div"); empty.className = "empty-box"; empty.textContent = "Подходящих событий пока нет"; list.append(empty); }
    count.textContent = `Записей: ${entries.length}, показано: ${shown}. ${dropped ? `Из-за лимита удалено старых: ${dropped}.` : ""}`;
    state.textContent = recording ? "Запись включена" : "Запись на паузе";
    pauseButton.textContent = recording ? "Пауза журнала" : "Продолжить журнал";
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
  search.addEventListener("input", render);
  filter.addEventListener("change", render);
  pauseButton.addEventListener("click", () => {
    if (recording) { add("system", "Пользователь приостановил журнал."); recording = false; }
    else { recording = true; skipNextView = true; add("system", "Пользователь продолжил журнал; события за время паузы недоступны."); }
    render();
  });
  document.querySelector("#journal-clear").addEventListener("click", async () => {
    try {
      if (typeof window.__TAURI_INTERNALS__?.invoke === "function") await window.umbraDiagnosticClear();
      entries.length = 0; dropped = 0; report.value = ""; copy.disabled = true;
      copyStatus.textContent = "Журнал и сохранённые события проверки очищены.";
    } catch (error) {
      copyStatus.textContent = `Не удалось очистить события проверки: ${String(error)}`;
    }
    render();
  });
  mode.addEventListener("change", () => { report.value = ""; copy.disabled = true; copyStatus.textContent = "Подготовьте отчёт заново."; });
  document.querySelector("#journal-prepare").addEventListener("click", () => {
    const full = mode.value === "full";
    report.value = [`UmbraNet WiFi — журнал событий (${full ? "подробный, содержит IP" : "без полей IP и подробностей ошибок"})`, `Записей: ${entries.length}; удалено из-за лимита: ${dropped}.`, "Пассивная проверка не подтверждает обход, домены или голос.", ...entries.map(e => `[${time(e.timestamp)}] ${summary(e, full)}`)].join("\n");
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
