"use strict";

(() => {
  const input = document.querySelector("#dpi-entry");
  const modeButton = document.querySelector("#dpi-entry-mode");
  const add = document.querySelector("#dpi-add");
  const entries = document.querySelector("#dpi-entries");
  const message = document.querySelector("#dpi-message");
  const count = document.querySelector("#dpi-count");
  const serviceRows = [...document.querySelectorAll(".catalog-row[data-service]")];
  const serviceButtons = serviceRows.map(row => row.querySelector(".toggle"));
  const invoke = window.__TAURI_INTERNALS__?.invoke;
  let state = null;
  let ready = false;
  let busy = false;
  let processMode = false;

  function enableControls() {
    const disabled = !ready || busy;
    input.disabled = disabled;
    add.disabled = disabled;
    modeButton.disabled = disabled;
    for (const button of serviceButtons) button.disabled = disabled;
    entries.querySelectorAll("button").forEach(button => { button.disabled = disabled; });
  }

  function status(text, isError = false) {
    message.textContent = text;
    message.classList.toggle("is-error", isError);
    message.hidden = !text;
  }

  function chip(text, kind, action, value) {
    const el = document.createElement("span");
    el.className = "dispatcher-chip";
    const label = document.createElement("span");
    label.textContent = text;
    el.append(label);
    if (kind) {
      const hint = document.createElement("small");
      hint.textContent = kind;
      el.append(hint);
    }
    if (action) {
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "dispatcher-remove";
      remove.textContent = "×";
      remove.setAttribute("aria-label", `Удалить ${text}`);
      remove.addEventListener("click", () => change(action, value, false));
      el.append(remove);
    }
    return el;
  }

  function render(next) {
    state = next;
    for (const row of serviceRows) {
      const selected = state.services.includes(row.dataset.service);
      const button = row.querySelector(".toggle");
      button.setAttribute("aria-pressed", String(selected));
      button.classList.toggle("active", selected);
    }
    entries.replaceChildren();
    for (const id of state.services) {
      const row = serviceRows.find(item => item.dataset.service === id);
      const name = row?.querySelector("strong")?.textContent || id;
      entries.append(chip(name, "сервис", "service", id));
    }
    for (const domain of state.domains) entries.append(chip(domain, "домен", "remove_domain", domain));
    for (const process of state.protected_processes) entries.append(chip(process, "защищён", null, process));
    for (const process of state.processes) entries.append(chip(process, "процесс", "remove_process", process));
    count.textContent = `Доменов: ${state.active_domains.length}`;
    status(state.warning || "", Boolean(state.warning));
    enableControls();
  }

  async function change(action, value, enabled = true) {
    if (!ready || busy) return false;
    busy = true;
    enableControls();
    try {
      const next = await invoke("dpi_apply", { action, value, enabled });
      render(next);
      return true;
    } catch (error) {
      status(String(error), true);
      return false;
    } finally {
      busy = false;
      enableControls();
    }
  }

  for (const row of serviceRows) {
    row.querySelector(".toggle").addEventListener("click", () => {
      if (state) change("service", row.dataset.service, !state.services.includes(row.dataset.service));
    });
  }
  modeButton.addEventListener("click", () => {
    processMode = !processMode;
    modeButton.setAttribute("aria-pressed", String(processMode));
    modeButton.textContent = processMode ? "Домен" : "Процесс";
    input.placeholder = processMode ? "Например, Discord.exe" : "example.com или Discord.exe";
    input.focus();
  });
  async function addEntry() {
    const value = input.value.trim();
    if (!value) { status("Введите домен или имя процесса.", true); input.focus(); return; }
    const isProcess = processMode || value.toLowerCase().endsWith(".exe");
    if (await change(isProcess ? "add_process" : "add_domain", value)) {
      input.value = "";
      input.focus();
    }
  }
  add.addEventListener("click", addEntry);
  input.addEventListener("keydown", event => {
    if (event.key === "Enter") { event.preventDefault(); addEntry(); }
  });

  enableControls();
  if (typeof invoke !== "function") {
    status("Выбор целей доступен в приложении UmbraNet.", true);
    return;
  }
  invoke("dpi_get").then(next => {
    ready = true;
    render(next);
  }).catch(error => status(`Не удалось загрузить цели: ${error}`, true));
})();
