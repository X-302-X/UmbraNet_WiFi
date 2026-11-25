"use strict";

(() => {
  const list = document.querySelector("#strategy-list");
  const count = document.querySelector("#strategy-count");
  const message = document.querySelector("#strategy-message");
  const stateLabel = document.querySelector("#engine-state");
  const autoList = document.querySelector("#auto-list");
  const autoCount = document.querySelector("#auto-count");
  const autoClear = document.querySelector("#auto-clear");
  const invoke = window.__TAURI_INTERNALS__?.invoke;

  if (!list || typeof invoke !== "function") return;

  let view = null;
  let busy = false;

  // Команды моста возвращают JSON-строку (без serde-derive в src-tauri).
  function parse(payload) {
    if (typeof payload !== "string") return payload || null;
    try {
      return JSON.parse(payload);
    } catch {
      return null;
    }
  }

  function status(text, isError = false) {
    message.textContent = text;
    message.classList.toggle("is-error", isError);
    message.hidden = !text;
  }

  function render() {
    const items = view?.strategies || [];
    list.replaceChildren();
    if (!items.length) {
      const empty = document.createElement("div");
      empty.className = "empty-box tall";
      empty.textContent = view?.last_error || "В папке strtegs_Uz нет стратегий";
      list.append(empty);
    }
    for (const item of items) {
      const row = document.createElement("button");
      row.type = "button";
      row.className = "strategy-row";
      row.dataset.strategy = item.id;
      row.setAttribute("role", "option");
      row.setAttribute("aria-selected", String(item.id === view.selected));
      row.title = item.file;

      const name = document.createElement("strong");
      name.textContent = item.name;
      const id = document.createElement("span");
      id.className = "strategy-id";
      id.textContent = item.id;
      row.append(name, id);
      if (item.implementation_pending) {
        const badge = document.createElement("span");
        badge.className = "strategy-badge";
        badge.textContent = "подключение не завершено";
        row.append(badge);
      }
      if (item.id === view.running_id) {
        const badge = document.createElement("span");
        badge.className = "strategy-badge";
        badge.textContent = "активна";
        row.append(badge);
      }
      row.addEventListener("click", () => select(item.id));
      list.append(row);
    }

    count.textContent = view?.selected ? `Выбрано: ${view.selected}` : "Выбрано: —";

    const auto = view?.auto_domains || [];
    autoCount.textContent = `${auto.length} доменов`;
    autoClear.disabled = busy || auto.length === 0;
    autoList.replaceChildren();
    if (!auto.length) {
      const empty = document.createElement("div");
      empty.className = "empty-box";
      empty.textContent = "Пока пусто";
      autoList.append(empty);
    }
    for (const domain of auto) {
      const row = document.createElement("div");
      row.className = "strategy-row auto-row";
      const name = document.createElement("strong");
      name.textContent = domain;
      row.append(name);
      autoList.append(row);
    }
    const running = Boolean(view?.running);
    stateLabel.textContent = running
      ? `Обход включён: ${view.running_id || "—"}`
      : "Движок выключен";
  }

  // Пока движок включён, раз в 2 секунды забираем статус: так ошибки
  // (например, падение драйвера) доходят до интерфейса.
  let timer = null;
  function schedulePoll() {
    if (timer || !view?.running) return;
    timer = setInterval(async () => {
      try {
        view = parse(await invoke("dpi_strategy_list"));
        if (view?.last_error) status(view.last_error, true);
        render();
      } finally {
        if (!view?.running) {
          clearInterval(timer);
          timer = null;
        }
      }
    }, 2000);
  }

  async function refresh() {
    try {
      view = parse(await invoke("dpi_strategy_list"));
      render();
      schedulePoll();
    } catch (error) {
      status(String(error), true);
    }
  }

  async function select(id) {
    if (busy || id === view?.selected) return;
    busy = true;
    try {
      view = parse(await invoke("dpi_strategy_select", { id }));
      status("");
    } catch (error) {
      status(String(error), true);
    } finally {
      busy = false;
      render();
    }
  }

  autoClear.addEventListener("click", async () => {
    if (busy) return;
    busy = true;
    render();
    try {
      view = parse(await invoke("dpi_autohostlist_clear"));
      status("");
    } catch (error) {
      status(String(error), true);
    } finally {
      busy = false;
      render();
    }
  });

  refresh();
})();
