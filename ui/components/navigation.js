"use strict";

(() => {
  const nav = document.querySelector("#navigation");
  const pages = [...document.querySelectorAll(".page")];
  const buttons = [...nav.querySelectorAll(".nav-item")];
  const orderKey = "umbranet-wifi.navigation-order.v1";
  const announcer = document.querySelector("#announcer");
  const dragThreshold = 6;
  let pointerDrag = null;
  let suppressClick = false;

  function saveOrder() {
    try {
      localStorage.setItem(orderKey, JSON.stringify([...nav.children].map(button => button.dataset.page)));
    } catch (_) { /* Interface remains usable if browser storage is unavailable. */ }
  }

  function announce(button) {
    announcer.textContent = `${button.textContent.trim()}: позиция ${[...nav.children].indexOf(button) + 1} из ${buttons.length}`;
  }

  try {
    const order = JSON.parse(localStorage.getItem(orderKey) || "null");
    if (Array.isArray(order) && order.length === buttons.length &&
        new Set(order).size === buttons.length &&
        order.every(id => buttons.some(button => button.dataset.page === id))) {
      for (const id of order) nav.append(buttons.find(button => button.dataset.page === id));
    }
  } catch (_) { /* Ignore invalid or unavailable stored state. */ }

  function showPage(id) {
    if (!pages.some(page => page.id === id)) return;
    for (const page of pages) page.hidden = page.id !== id;
    for (const button of buttons) {
      const selected = button.dataset.page === id;
      button.classList.toggle("selected", selected);
      if (selected) button.setAttribute("aria-current", "page");
      else button.removeAttribute("aria-current");
    }
  }

  function finishDrag(cancelled) {
    if (!pointerDrag) return;
    const { button, active, originalOrder } = pointerDrag;
    pointerDrag = null;
    button.classList.remove("dragging");
    if (!active) return;
    if (cancelled) {
      for (const item of originalOrder) nav.append(item);
    } else {
      saveOrder();
      announce(button);
    }
    // A pointer release after a drag must not activate a navigation button.
    suppressClick = true;
    setTimeout(() => { suppressClick = false; }, 0);
  }

  nav.addEventListener("click", event => {
    if (suppressClick) {
      event.preventDefault();
      event.stopImmediatePropagation();
      suppressClick = false;
    }
  }, true);

  document.addEventListener("pointermove", event => {
    if (!pointerDrag || event.pointerId !== pointerDrag.pointerId) return;
    if (event.pointerType === "mouse" && !(event.buttons & 1)) {
      finishDrag(true);
      return;
    }
    const { button, startX, startY } = pointerDrag;
    if (!pointerDrag.active) {
      if (Math.hypot(event.clientX - startX, event.clientY - startY) < dragThreshold) return;
      pointerDrag.active = true;
      button.classList.add("dragging");
    }
    event.preventDefault();
    const others = [...nav.children].filter(item => item !== button);
    const next = others.find(item => {
      const rect = item.getBoundingClientRect();
      return event.clientY < rect.top + rect.height / 2;
    });
    nav.insertBefore(button, next || null);
  });

  document.addEventListener("pointerup", event => {
    if (pointerDrag && event.pointerId === pointerDrag.pointerId) finishDrag(false);
  });
  document.addEventListener("pointercancel", event => {
    if (pointerDrag && event.pointerId === pointerDrag.pointerId) finishDrag(true);
  });
  window.addEventListener("blur", () => finishDrag(true));
  nav.addEventListener("dragstart", event => event.preventDefault());

  for (const button of buttons) {
    // HTML drag-and-drop is unreliable in some embedded WebView environments.
    button.draggable = false;
    button.addEventListener("click", () => showPage(button.dataset.page));
    button.addEventListener("pointerdown", event => {
      if (!event.isPrimary || event.button !== 0 || event.pointerType === "touch") return;
      pointerDrag = {
        button,
        pointerId: event.pointerId,
        startX: event.clientX,
        startY: event.clientY,
        originalOrder: [...nav.children],
        active: false,
      };
    });
    button.addEventListener("keydown", event => {
      if (!event.altKey || !["ArrowUp", "ArrowDown"].includes(event.key)) return;
      event.preventDefault();
      const neighbor = event.key === "ArrowUp" ? button.previousElementSibling : button.nextElementSibling;
      if (!neighbor) return;
      if (event.key === "ArrowUp") nav.insertBefore(button, neighbor);
      else nav.insertBefore(neighbor, button);
      button.focus();
      saveOrder();
      announce(button);
    });
  }
  for (const button of document.querySelectorAll("[data-open]")) {
    button.addEventListener("click", () => showPage(button.dataset.open));
  }
})();
