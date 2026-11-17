"use strict";

(() => {
  const list = document.querySelector("#strategy-list");
  const count = document.querySelector("#strategy-count");
  const message = document.querySelector("#strategy-message");
  const startButton = document.querySelector("#engine-start");
  const stopButton = document.querySelector("#engine-stop");
  const stateLabel = document.querySelector("#engine-state");
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
    const running = Boolean(view?.running);
    startButton.disabled = busy || running || !view?.selected;
    stopButton.disabled = busy || !running;
    stateLabel.textContent = running
      ? `Обход включён: ${view.running_id || "—"}`
      : "Движок выключен";
    startButton.classList.toggle("action-accent", !running);
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
    startButton.disabled = true;
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

  async function toggle(start) {
    if (busy) return;
    busy = true;
    status("");
    render();
    try {
      view = parse(await invoke(start ? "dpi_engine_start" : "dpi_engine_stop"));
      if (view?.last_error) status(view.last_error, true);
    } catch (error) {
      status(String(error), true);
    } finally {
      busy = false;
      render();
      schedulePoll();
    }
  }

  startButton.addEventListener("click", () => toggle(true));
  stopButton.addEventListener("click", () => toggle(false));

  refresh();
})();
