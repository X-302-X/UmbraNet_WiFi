"use strict";

(() => {
  const invoke = window.__TAURI_INTERNALS__?.invoke;
  const start = document.querySelector("#diagnostic-start");
  const stop = document.querySelector("#diagnostic-stop");
  const phase = document.querySelector("#diagnostic-state");
  const message = document.querySelector("#diagnostic-message");
  const counts = {
    established: document.querySelector("#diagnostic-established"),
    identified: document.querySelector("#diagnostic-identified"),
    selected_process: document.querySelector("#diagnostic-selected"),
    unresolved: document.querySelector("#diagnostic-unresolved")
  };
  const labels = {
    idle: "Не запущена", starting: "Запуск…", running: "Выполняется",
    stopping: "Остановка…", finished: "Завершена", error: "Ошибка", stop_failed: "Ошибка остановки"
  };
  let ready = false;
  let submitting = false;
  let state = null;
  let pollTimer = null;
  let polling = false;
  let requestSequence = 0;
  let appliedSequence = 0;
  let lastStatusError = null;

  function displayError(text) {
    message.textContent = text || "";
    message.hidden = !text;
  }
  function controls() {
    start.disabled = !ready || submitting || Boolean(state?.busy);
    stop.disabled = !ready || submitting || !state?.busy || ["stopping", "stop_failed"].includes(state?.phase);
  }
  function schedule() {
    clearTimeout(pollTimer);
    if (state?.busy || !ready) pollTimer = setTimeout(refresh, ready ? 600 : 1500);
  }
  function render(view) {
    const previous = state;
    const terminal = ["finished", "error", "stop_failed"].includes(view.phase);
    if (terminal) window.umbraJournal?.addFlowView(view);
    if (view.phase !== previous?.phase && view.phase !== "idle") {
      const text = {
        starting: "Пассивная проверка: запуск.", running: "Пассивная проверка работает.",
        stopping: "Пассивная проверка: запрошена остановка.", finished: "Пассивная проверка остановлена.",
        error: "Пассивная проверка завершилась с ошибкой.", stop_failed: "Ошибка остановки пассивной проверки."
      }[view.phase];
      if (text) window.umbraJournal?.add(["error", "stop_failed"].includes(view.phase) ? "error" : "system", view.message || text);
    } else if (view.message && view.message !== previous?.message && ["error", "stop_failed"].includes(view.phase)) {
      window.umbraJournal?.add("error", view.message);
    }
    if (!terminal) window.umbraJournal?.addFlowView(view);
    state = view;
    phase.textContent = labels[view.phase] || "Неизвестное состояние";
    phase.classList.toggle("is-error", ["error", "stop_failed"].includes(view.phase));
    for (const [key, node] of Object.entries(counts)) node.textContent = String(view[key] ?? 0);
    displayError(view.message);
    controls();
    schedule();
  }
  async function refresh() {
    if (polling || submitting) return;
    polling = true;
    const sequence = ++requestSequence;
    try {
      const view = await invoke("dpi_diagnostic_status");
      ready = true;
      if (sequence >= appliedSequence) {
        if (lastStatusError) window.umbraJournal?.add("system", "Доступ к состоянию пассивной проверки восстановлен.");
        lastStatusError = null;
        appliedSequence = sequence;
        render(view);
      }
    } catch (error) {
      if (sequence >= appliedSequence) {
        const text = `Не удалось получить состояние проверки: ${error}`;
        displayError(text);
        if (text !== lastStatusError) window.umbraJournal?.add("error", text);
        lastStatusError = text;
      }
      if (state?.busy || !ready) pollTimer = setTimeout(refresh, 1500);
    } finally {
      polling = false;
      controls();
      if (sequence < appliedSequence && !submitting) schedule();
    }
  }
  async function command(name) {
    if (!ready || submitting) return;
    submitting = true;
    window.umbraJournal?.add("system", name === "dpi_diagnostic_start" ? "Пользователь запустил пассивную проверку." : "Пользователь запросил остановку пассивной проверки.");
    controls();
    const sequence = ++requestSequence;
    appliedSequence = sequence;
    clearTimeout(pollTimer);
    let failure = null;
    try {
      const view = await invoke(name);
      if (sequence >= appliedSequence) { appliedSequence = sequence; render(view); }
    } catch (error) {
      failure = String(error);
      window.umbraJournal?.add("error", `Ошибка команды проверки: ${failure}`);
    } finally {
      submitting = false;
      controls();
      schedule();
    }
    if (failure) {
      // Команда могла завершиться ошибкой после запуска.
      await refresh();
      displayError(failure);
    }
  }
  window.umbraDiagnosticClear = async () => {
    const sequence = ++requestSequence;
    appliedSequence = sequence;
    await invoke("dpi_diagnostic_clear_events");
    if (state) state.events = [];
  };
  start.addEventListener("click", () => command("dpi_diagnostic_start"));
  stop.addEventListener("click", () => command("dpi_diagnostic_stop"));
  if (typeof invoke !== "function") {
    phase.textContent = "Доступна только в приложении";
    return;
  }
  refresh();
})();
