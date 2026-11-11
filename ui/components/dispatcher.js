"use strict";

(() => {
  const container = document.querySelector(".routing-main");
  const handle = document.querySelector("#dispatcher-handle");
  const panel = document.querySelector(".task-panel");
  const key = "umbranet-wifi.dispatcher-height.v1";
  const minimum = 80;
  const title = container.querySelector(".page-title");
  const catalogMinimum = () => 130 + (title ? title.offsetHeight : 0);
  let preferred = 175;
  let drag = null;

  try {
    const saved = Number(localStorage.getItem(key));
    if (Number.isFinite(saved) && saved >= minimum) preferred = saved;
  } catch (_) { /* Use the default size if storage is unavailable. */ }

  function updateHeight() {
    const available = container.clientHeight;
    if (!available) return;
    const maximum = Math.max(minimum, available - catalogMinimum());
    const height = Math.max(minimum, Math.min(maximum, preferred));
    panel.style.setProperty("--dispatcher-height", `${height}px`);
    handle.setAttribute("aria-valuemax", String(Math.round(maximum)));
    handle.setAttribute("aria-valuenow", String(Math.round(height)));
  }

  function persist() {
    try { localStorage.setItem(key, String(preferred)); }
    catch (_) { /* Resizing still works for the current session. */ }
  }

  handle.addEventListener("pointerdown", event => {
    if (!event.isPrimary || event.button !== 0) return;
    drag = { pointerId: event.pointerId, y: event.clientY, height: panel.getBoundingClientRect().height };
    handle.setPointerCapture(event.pointerId);
    event.preventDefault();
  });
  handle.addEventListener("pointermove", event => {
    if (!drag || drag.pointerId !== event.pointerId) return;
    const maximum = Math.max(minimum, container.clientHeight - catalogMinimum());
    preferred = Math.max(minimum, Math.min(maximum, drag.height + drag.y - event.clientY));
    updateHeight();
    event.preventDefault();
  });
  function endDrag(event) {
    if (!drag || drag.pointerId !== event.pointerId) return;
    drag = null;
    persist();
  }
  handle.addEventListener("pointerup", endDrag);
  handle.addEventListener("pointercancel", endDrag);
  handle.addEventListener("keydown", event => {
    if (!["ArrowUp", "ArrowDown", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const maximum = Math.max(minimum, container.clientHeight - catalogMinimum());
    const current = panel.getBoundingClientRect().height;
    if (event.key === "Home") preferred = minimum;
    else if (event.key === "End") preferred = maximum;
    else preferred = Math.max(minimum, Math.min(maximum, current + (event.key === "ArrowUp" ? 12 : -12)));
    updateHeight();
    persist();
  });

  new ResizeObserver(updateHeight).observe(container);
  updateHeight();
})();
