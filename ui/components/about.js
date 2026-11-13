"use strict";

(() => {
  const label = document.querySelector("#admin-status");
  const invoke = window.__TAURI_INTERNALS__?.invoke;
  if (typeof invoke !== "function") {
    label.textContent = "Недоступно";
    return;
  }
  invoke("admin_status").then(elevated => {
    label.textContent = elevated ? "Есть" : "Нет";
    label.classList.toggle("status-positive", elevated);
    label.classList.toggle("status-negative", !elevated);
  }).catch(() => {
    label.textContent = "Не удалось определить";
    label.classList.add("status-negative");
  });
})();
