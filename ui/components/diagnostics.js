"use strict";

(() => {
  const invoke = window.__TAURI_INTERNALS__?.invoke;
  const start = document.querySelector("#diagnostic-start");
  const tcpStart = document.querySelector("#diagnostic-tcp-start");
  const flowStats = document.querySelector("#diagnostic-flow-stats");
  const tcpResults = document.querySelector("#diagnostic-tcp-results");
  const tcpReport = document.querySelector("#diagnostic-tcp-report");
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
    tcpStart.disabled = start.disabled;
    stop.disabled = !ready || submitting || !state?.busy || ["stopping", "stop_failed"].includes(state?.phase);
  }
  function schedule() {
    clearTimeout(pollTimer);
    if (state?.busy || !ready) pollTimer = setTimeout(refresh, ready ? 600 : 1500);
  }
  function tcpSummary(view) {
    function matrix(label, m = {}) {
      return `${label}: флаг=1/сумма верна ${m.flag_set_valid ?? 0}; флаг=1/сумма неверна ${m.flag_set_invalid ?? 0}; флаг=0/сумма верна ${m.flag_unset_valid ?? 0}; флаг=0/сумма неверна ${m.flag_unset_invalid ?? 0}`;
    }
    function direction(label, d = {}) {
      return [label, `Всего ${d.total ?? 0}; IPv4 ${d.ipv4 ?? 0}; IPv6 ${d.ipv6 ?? 0}; больше 1500 байт ${d.over_1500_bytes ?? 0}; не разобрано ${d.unsupported ?? 0}`, matrix("TCP", d.tcp_checksum), matrix("IPv4 заголовок (только IPv4)", d.ipv4_checksum)].join("\n");
    }
    return ["UmbraNet — пассивная TCP-проверка", `Состояние: ${labels[view.phase] || "неизвестно"}; лимит ${view.duration_seconds ?? 30} с.`, "Охват: все приложения на web-портах, не только выбранные цели.", direction("Исходящие", view.tcp_stats?.outbound), direction("Входящие", view.tcp_stats?.inbound), "Размер >1500, флаги и суммы не доказывают наличие или отсутствие LSO; потери копий не измеряются."].join("\n\n");
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
    if (terminal && view.phase !== previous?.phase) window.dispatchEvent(new Event("umbra-diagnostic-finished"));
    state = view;
    if (view.busy !== previous?.busy) window.dispatchEvent(new Event("umbra-diagnostic-busy"));
    phase.textContent = labels[view.phase] || "Неизвестное состояние";
    phase.classList.toggle("is-error", ["error", "stop_failed"].includes(view.phase));
    for (const [key, node] of Object.entries(counts)) node.textContent = String(view[key] ?? 0);
    const tcpMode = view.kind === "tcp_metadata";
    flowStats.hidden = tcpMode;
    tcpResults.hidden = !tcpMode;
    if (tcpMode) tcpReport.value = tcpSummary(view);
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
    const action = name === "dpi_tcp_diagnostic_start" ? "Пользователь запустил пассивную TCP-проверку." : name === "dpi_diagnostic_start" ? "Пользователь запустил пассивную FLOW-проверку." : "Пользователь запросил остановку пассивной проверки.";
    window.umbraJournal?.add("system", action);
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
  window.umbraDiagnosticBusy = () => !state || Boolean(state.busy);
  window.umbraDiagnosticClear = async () => {
    const sequence = ++requestSequence;
    appliedSequence = sequence;
    await invoke("dpi_diagnostic_clear_events");
    if (state) state.events = [];
  };
  start.addEventListener("click", () => command("dpi_diagnostic_start"));
  tcpStart.addEventListener("click", () => {
    if (!ready || submitting || state?.busy) return;
    if (!window.confirm("Пассивно прочитать копии TCP-пакетов на web-портах всех приложений в течение 30 секунд? Содержимое и адреса не сохраняются. Может запуститься общий драйвер WinDivert.")) return;
    command("dpi_tcp_diagnostic_start");
  });
  stop.addEventListener("click", () => command("dpi_diagnostic_stop"));
  if (typeof invoke !== "function") {
    phase.textContent = "Доступна только в приложении";
    return;
  }
  refresh();
})();
