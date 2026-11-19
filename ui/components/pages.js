"use strict";

(() => {
  const search = document.querySelector("#catalog-search");
  const groups = [...document.querySelectorAll(".catalog-group")];
  const empty = document.querySelector("#catalog-empty");
  search.addEventListener("input", () => {
    const query = search.value.trim().toLocaleLowerCase("ru");
    let found = 0;
    for (const group of groups) {
      let groupFound = 0;
      for (const row of group.querySelectorAll("[data-service]")) {
        const matches = row.dataset.service.includes(query);
        row.hidden = !matches;
        if (matches) { found++; groupFound++; }
      }
      group.hidden = groupFound === 0;
    }
    empty.hidden = found !== 0;
  });

  const notice = document.querySelector("#action-notice");
  const mainButton = document.querySelector(".action-start");
  const mainText = mainButton.querySelector("span");
  const restartButton = document.querySelector(".action-restart");
  let noticeTimer;
  function showNotice(text, error = false) {
    notice.textContent = text;
    notice.classList.toggle("is-error", error);
    notice.hidden = false;
    clearTimeout(noticeTimer);
    // Ошибку не скрываем по таймеру: пользователь должен успеть её прочитать.
    if (!error) noticeTimer = setTimeout(() => { notice.hidden = true; }, 6000);
  }
  restartButton.addEventListener("click", () => showNotice("«Перезапуск» пока не подключён."));

  // Mode and route pickers are visual until network components are connected.
  const modes = [...document.querySelectorAll("[data-mode]")];
  const comboTabs = [...document.querySelectorAll("[data-route-tab]")];
  const comboGroup = document.querySelector("#combo-tabs");
  const panels = { vpn: document.querySelector("#route-vpn"), dpi: document.querySelector("#route-dpi") };
  let currentMode = "vpn";
  let comboView = "vpn";
  const invoke = window.__TAURI_INTERNALS__?.invoke;
  let dpiRunning = null; // null = состояние не подтверждено
  let controlBusy = false;
  let stopUnconfirmed = false;

  function renderMain() {
    const stopping = currentMode === "dpi" && dpiRunning === true;
    const unknown = currentMode === "dpi" && (dpiRunning === null || stopUnconfirmed);
    mainButton.dataset.state = stopping ? "stop" : "start";
    mainButton.firstChild.textContent = stopping ? "■ " : "▶ ";
    mainText.textContent = unknown ? "Проверить состояние" : stopping ? "Стоп" : "Старт";
    mainButton.disabled = controlBusy || (currentMode === "dpi" && stopUnconfirmed);
    for (const button of modes) button.disabled = controlBusy || ((dpiRunning === true || stopUnconfirmed) && button.dataset.mode !== "dpi");
  }
  function parseDpiView(raw) {
    const view = typeof raw === "string" ? JSON.parse(raw) : raw;
    if (!view || typeof view.running !== "boolean") throw new Error("Неизвестное состояние DPI");
    return view;
  }
  async function readDpiState() {
    if (typeof invoke !== "function") throw new Error("Управление DPI доступно только в приложении Windows");
    const view = parseDpiView(await invoke("dpi_strategy_list"));
    dpiRunning = view.running;
    return view;
  }
  function parseStop(value) {
    const view = typeof value === "string" ? JSON.parse(value) : value;
    if (!view || !["idle", "stopping", "complete", "failed"].includes(view.phase) || typeof view.owned_closed !== "boolean") {
      throw new Error("Неизвестное состояние общей остановки");
    }
    return view;
  }
  async function waitStop(view) {
    view = parseStop(view);
    while (view.phase === "stopping") {
      showNotice("Остановка DPI выполняется. Если она затянулась, состояние ресурсов ещё не подтверждено.", true);
      await new Promise(resolve => setTimeout(resolve, 600));
      view = parseStop(await invoke("dpi_control_status"));
    }
    return view;
  }
  function applyStop(view) {
    if (view.phase === "complete" && view.owned_closed && ["stopped", "absent"].includes(view.service_status)) {
      dpiRunning = false;
      stopUnconfirmed = false;
      const text = `DPI остановлен. Состояние службы WinDivert в SCM: ${view.service_status === "stopped" ? "остановлена" : "отсутствует"}; это не доказывает выгрузку драйвера из памяти.`;
      window.umbraJournal?.addRequired("system", text);
      window.umbraJournal?.stopAfterDpi();
      showNotice(text);
      return;
    }
    stopUnconfirmed = true;
    dpiRunning = null;
    const text = `Остановка DPI не подтверждена: ${view.message || "неизвестное состояние"}`;
    window.umbraJournal?.addRequired("error", text);
    if (view.owned_closed) window.umbraJournal?.stopAfterDpi();
    showNotice(text, true);
  }
  mainButton.addEventListener("click", async () => {
    if (controlBusy) return;
    if (currentMode !== "dpi") {
      showNotice("«Старт» для этого режима пока не подключён.");
      return;
    }
    if (stopUnconfirmed) return;
    controlBusy = true;
    const expected = dpiRunning;
    const intendedStop = expected === true;
    if (intendedStop) window.umbraJournal?.addRequired("system", "Пользователь нажал «Стоп» DPI.");
    let sent = null;
    renderMain();
    try {
      // Если состояние изменилось, не выполнять действие, отличное от надписи на кнопке.
      const before = await readDpiState();
      if (expected === null || expected !== before.running) {
        const text = "Состояние DPI обновлено. Проверьте кнопку и нажмите её ещё раз.";
        if (intendedStop) window.umbraJournal?.addRequired("system", `Команда остановки не отправлена: ${text}`);
        showNotice(text);
        return;
      }
      const stopping = before.running;
      sent = stopping ? "stop" : "start";
      if (!stopping) window.umbraJournal?.add("system", "Пользователь нажал «Старт» DPI.");
      if (stopping) {
        const final = await waitStop(await invoke("dpi_engine_stop"));
        applyStop(final);
        return;
      }
      const after = parseDpiView(await invoke("dpi_engine_start"));
      dpiRunning = after.running;
      if (after.last_error) throw new Error(after.last_error);
      if (!after.running) throw new Error("DPI не запущен.");
      showNotice("DPI запущен.");
      window.umbraJournal?.startForDpi();
      window.umbraJournal?.add("system", "DPI запущен.");
    } catch (error) {
      const text = `DPI: ${String(error)}`;
      showNotice(text, true);
      if (intendedStop) window.umbraJournal?.addRequired("error", text);
      else window.umbraJournal?.add("error", text);
      if (sent === "stop") {
        // Текущий список стратегий не подтверждает закрытие ресурсов или службы.
        stopUnconfirmed = true;
        dpiRunning = null;
      } else {
        try { await readDpiState(); } catch (_) { dpiRunning = null; }
      }
    } finally {
      controlBusy = false;
      renderMain();
    }
  });


  function renderRoutePicker() {
    const shown = currentMode === "combo" ? comboView : currentMode;
    comboGroup.hidden = currentMode !== "combo";
    for (const [id, panel] of Object.entries(panels)) panel.hidden = id !== shown;
    for (const tab of comboTabs) {
      const selected = tab.dataset.routeTab === comboView;
      tab.classList.toggle("active", selected);
      tab.setAttribute("aria-pressed", String(selected));
    }
    for (const button of modes) button.setAttribute("aria-pressed", String(button.dataset.mode === currentMode));
  }

  for (const button of modes) button.addEventListener("click", async () => {
    if (controlBusy || ((dpiRunning === true || stopUnconfirmed) && button.dataset.mode !== "dpi")) return;
    currentMode = button.dataset.mode;
    renderRoutePicker();
    renderMain();
    if (currentMode === "dpi") {
      showNotice("Изменённые цели применяются при следующем запуске DPI. Конфликтующие программы WinDivert могут быть завершены; остановка общего драйвера может повлиять на другие программы.");
      if (dpiRunning === null && !stopUnconfirmed) {
        controlBusy = true; renderMain();
        try {
          const control = parseStop(await invoke("dpi_control_status"));
          if (control.phase === "stopping") applyStop(await waitStop(control));
          else if (control.phase === "failed") applyStop(control);
          else await readDpiState();
        }
        catch (error) { dpiRunning = null; showNotice(`DPI: ${String(error)}`, true); }
        finally { controlBusy = false; renderMain(); }
      }
    }
  });
  for (const tab of comboTabs) tab.addEventListener("click", () => {
    comboView = tab.dataset.routeTab;
    renderRoutePicker();
  });
  for (const button of document.querySelectorAll("[data-preview-picker]")) {
    button.addEventListener("click", () => {
      const selected = button.getAttribute("aria-pressed") !== "true";
      button.setAttribute("aria-pressed", String(selected));
    });
  }
  renderRoutePicker();
  renderMain();

  for (const button of document.querySelectorAll(".catalog-row .favorite")) {
    button.addEventListener("click", () => {
      const selected = button.getAttribute("aria-pressed") !== "true";
      button.setAttribute("aria-pressed", String(selected));
      button.classList.toggle("active", selected);
      if (button.classList.contains("favorite")) button.textContent = selected ? "★" : "☆";
    });
  }

  const subtabs = [...document.querySelectorAll("[data-group][data-panel]")];
  for (const tab of subtabs) {
    tab.addEventListener("click", () => {
      for (const other of subtabs.filter(item => item.dataset.group === tab.dataset.group)) {
        const selected = other === tab;
        other.classList.toggle("active", selected);
        other.setAttribute("aria-pressed", String(selected));
        document.getElementById(other.dataset.panel).hidden = !selected;
      }
    });
  }
})();
