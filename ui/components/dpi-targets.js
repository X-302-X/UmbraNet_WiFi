"use strict";

(() => {
  const input = document.querySelector("#dpi-entry");
  const picker = document.querySelector("#dpi-entry-mode");
  const add = document.querySelector("#dpi-add");
  const filter = document.querySelector("#dpi-filter");
  const entries = document.querySelector("#dpi-entries");
  const message = document.querySelector("#dpi-message");
  const count = document.querySelector("#dpi-count");
  const serviceRows = [...document.querySelectorAll(".catalog-row[data-service]")];
  const rowMap = new Map(serviceRows.map(row => [row.dataset.service, row]));
  const serviceButtons = serviceRows.map(row => row.querySelector(".toggle"));
  const dialog = document.querySelector("#process-dialog");
  const processSearch = document.querySelector("#process-search");
  const processList = document.querySelector("#process-list");
  const processMessage = document.querySelector("#process-message");
  const invoke = window.__TAURI_INTERNALS__?.invoke;
  let confirmed = null;
  let ready = false;
  let pending = [];
  let tail = Promise.resolve();
  let processNames = [];
  let errorMessage = "";

  function enableControls() {
    input.disabled = !ready;
    add.disabled = !ready;
    picker.disabled = !ready;
    filter.disabled = !ready;
    for (const button of serviceButtons) button.disabled = !ready;
  }
  function status(text, isError = false) {
    message.textContent = text;
    message.classList.toggle("is-error", isError);
    message.hidden = !text;
  }
  function projectedServices() {
    const selected = new Set(confirmed?.services || []);
    for (const op of pending) {
      if (op.action !== "service") continue;
      if (op.enabled) selected.add(op.value); else selected.delete(op.value);
    }
    return selected;
  }
  function renderToggles() {
    const selected = projectedServices();
    for (const row of serviceRows) {
      const enabled = selected.has(row.dataset.service);
      const button = row.querySelector(".toggle");
      button.setAttribute("aria-pressed", String(enabled));
      button.classList.toggle("active", enabled);
    }
  }
  function serviceName(id) {
    return rowMap.get(id)?.querySelector("strong")?.textContent || id;
  }
  function lock() {
    const mark = document.createElement("span");
    mark.className = "dispatcher-lock";
    mark.title = "Защищённая запись: удалить нельзя";
    mark.setAttribute("aria-label", "Защищённая запись: удалить нельзя");
    mark.textContent = "🔒";
    return mark;
  }
  function makeRow(name, kind, sources, removeAction, removeValue, note) {
    const row = document.createElement("div");
    row.className = "dispatcher-row";
    row.dataset.name = name;
    row.dataset.kind = kind;
    const icon = document.createElement("span");
    icon.className = "dispatcher-icon";
    icon.textContent = kind === "домен" ? "🌐" : "🎮";
    icon.setAttribute("aria-hidden", "true");
    const badge = document.createElement("span");
    badge.className = `dispatcher-kind ${kind === "домен" ? "is-domain" : "is-process"}`;
    badge.textContent = kind;
    const title = document.createElement("span");
    title.className = "dispatcher-name";
    title.title = name;
    title.textContent = name;
    row.append(icon, badge, title);
    if (sources.length) {
      const source = document.createElement("span");
      source.className = "dispatcher-source";
      source.textContent = sources.join(", ");
      source.title = sources.join(", ");
      row.append(source);
    }
    if (removeAction) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "dispatcher-remove";
      button.textContent = "×";
      button.title = note || `Удалить ${name}`;
      button.setAttribute("aria-label", note || `Удалить ${name}`);
      button.addEventListener("click", () => change(removeAction, removeValue, false));
      row.append(button);
    } else if (kind === "процесс") {
      row.append(lock());
    } else {
      const info = document.createElement("span");
      info.className = "dispatcher-shared";
      info.textContent = "•";
      info.title = note || "Общий домен выбранных сервисов";
      info.setAttribute("aria-label", info.title);
      row.append(info);
    }
    return row;
  }
  function renderEntries() {
    if (!confirmed) return;
    const position = entries.scrollTop;
    entries.replaceChildren();
    const serviceDomains = confirmed.service_domains || {};
    const query = filter.value.trim().toLocaleLowerCase("ru");
    let shown = 0;
    function append(row, search) {
      if (query && !search.toLocaleLowerCase("ru").includes(query)) return;
      entries.append(row); shown++;
    }
    for (const domain of confirmed.active_domains) {
      const owners = confirmed.services.filter(id => (serviceDomains[id] || []).includes(domain));
      const manual = confirmed.domains.includes(domain);
      const sources = owners.map(serviceName);
      if (manual && owners.length) sources.unshift("вручную");
      let action = null, value = null, note = "";
      if (manual) {
        action = "remove_domain"; value = domain;
        note = owners.length ? `Удалить ручную запись ${domain}; домен останется у выбранного сервиса` : `Удалить ${domain}`;
      } else if (owners.length === 1) {
        action = "service"; value = owners[0]; note = `Выключить сервис «${serviceName(value)}»`;
      } else if (owners.length > 1) {
        note = "Общий домен: выключите нужный сервис в списке выше";
      }
      append(makeRow(domain, "домен", sources, action, value, note), `${domain} ${sources.join(" ")}`);
    }
    const protectedSet = new Set(confirmed.protected_processes);
    const processes = [...new Set([...confirmed.protected_processes, ...confirmed.processes])].sort();
    for (const name of processes) {
      const isProtected = protectedSet.has(name);
      append(makeRow(name, "процесс", [], isProtected ? null : "remove_process", name, ""), name);
    }
    if (!shown) {
      const empty = document.createElement("div");
      empty.className = "dispatcher-empty";
      empty.textContent = query ? "Записи не найдены" : "Нет активных записей";
      entries.append(empty);
    }
    entries.scrollTop = position;
    count.textContent = `${confirmed.active_domains.length} дом. • ${processes.length} проц.`;
  }
  function render() {
    renderToggles();
    renderEntries();
    status(errorMessage || confirmed?.warning || "", Boolean(errorMessage || confirmed?.warning));
  }
  function change(action, value, enabled = true) {
    if (!ready) return Promise.resolve(false);
    const operation = { action, value, enabled };
    pending.push(operation);
    errorMessage = "";
    renderToggles();
    const result = tail.then(async () => {
      try {
        confirmed = await invoke("dpi_apply", operation);
        return true;
      } catch (error) {
        errorMessage = String(error);
        return false;
      } finally {
        pending = pending.filter(item => item !== operation);
        render();
      }
    });
    tail = result.then(() => undefined, () => undefined);
    return result;
  }

  for (const row of serviceRows) {
    row.querySelector(".toggle").addEventListener("click", () => {
      if (ready) change("service", row.dataset.service, !projectedServices().has(row.dataset.service));
    });
  }
  filter.addEventListener("input", renderEntries);
  async function addEntry() {
    const value = input.value.trim();
    if (!value) { errorMessage = "Введите домен или имя процесса."; render(); input.focus(); return; }
    const isProcess = value.toLowerCase().endsWith(".exe");
    if (await change(isProcess ? "add_process" : "add_domain", value)) {
      if (input.value.trim() === value) input.value = "";
      input.focus();
    }
  }
  add.addEventListener("click", addEntry);
  input.addEventListener("keydown", event => {
    if (event.key === "Enter") { event.preventDefault(); addEntry(); }
  });

  function closePicker() {
    dialog.hidden = true;
    picker.focus();
  }
  function renderProcesses() {
    const query = processSearch.value.trim().toLocaleLowerCase("ru");
    const names = processNames.filter(name => name.toLocaleLowerCase("ru").includes(query));
    processList.replaceChildren();
    processMessage.textContent = names.length ? `Запущенных процессов: ${names.length}` : "Процессы не найдены";
    for (const name of names) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "process-choice";
      button.textContent = `🎮  ${name}`;
      button.addEventListener("click", async () => {
        if (await change("add_process", name)) closePicker();
      });
      processList.append(button);
    }
  }
  picker.addEventListener("click", async () => {
    dialog.hidden = false;
    processSearch.value = "";
    processNames = [];
    processList.replaceChildren();
    processMessage.textContent = "Загрузка…";
    processSearch.focus();
    try {
      const names = await invoke("running_processes");
      if (dialog.hidden) return;
      processNames = names;
      renderProcesses();
    } catch (error) {
      processMessage.textContent = `Не удалось получить список: ${error}`;
    }
  });
  processSearch.addEventListener("input", renderProcesses);
  document.querySelector("#process-close").addEventListener("click", closePicker);
  dialog.addEventListener("click", event => { if (event.target === dialog) closePicker(); });
  dialog.addEventListener("keydown", event => { if (event.key === "Escape") closePicker(); });

  enableControls();
  if (typeof invoke !== "function") {
    status("Выбор целей доступен в приложении UmbraNet.", true);
    return;
  }
  invoke("dpi_get").then(next => {
    confirmed = next;
    ready = true;
    enableControls();
    render();
  }).catch(error => status(`Не удалось загрузить цели: ${error}`, true));
})();
