"use strict";

(() => {
  const nav = document.querySelector("#navigation");
  const app = document.querySelector(".app");
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

  function motionAllowed() {
    return !app.classList.contains("no-motion") && !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }

  function createGhost(drag) {
    const rect = drag.button.getBoundingClientRect();
    const ghost = drag.button.cloneNode(true);
    ghost.classList.remove("dragging");
    ghost.classList.add("nav-drag-ghost");
    if (drag.button.closest(".sidebar").classList.contains("collapsed")) ghost.classList.add("ghost-collapsed");
    ghost.setAttribute("aria-hidden", "true");
    ghost.removeAttribute("aria-current");
    ghost.removeAttribute("data-page");
    ghost.removeAttribute("aria-label");
    ghost.removeAttribute("title");
    ghost.tabIndex = -1;
    ghost.draggable = false;
    ghost.style.left = `${rect.left}px`;
    ghost.style.top = `${rect.top}px`;
    ghost.style.width = `${rect.width}px`;
    ghost.style.height = `${rect.height}px`;
    app.append(ghost);
    drag.ghost = ghost;
  }

  function moveGhost(drag, x, y) {
    if (!drag.ghost) return;
    drag.ghost.style.left = `${x - drag.offsetX}px`;
    drag.ghost.style.top = `${y - drag.offsetY}px`;
  }

  function slideNeighbors(button, next) {
    if (button.nextElementSibling === next) return;
    const siblings = buttons.filter(item => item !== button);
    for (const item of siblings) {
      for (const animation of item.getAnimations()) {
        if (animation.id === "nav-shift") animation.cancel();
      }
    }
    const before = new Map(siblings.map(item => [item, item.getBoundingClientRect().top]));
    nav.insertBefore(button, next);
    if (!motionAllowed()) return;
    for (const item of siblings) {
      const distance = before.get(item) - item.getBoundingClientRect().top;
      if (Math.abs(distance) < 1) continue;
      const animation = item.animate(
        [{ transform: `translateY(${distance}px)` }, { transform: "translateY(0)" }],
        { duration: 170, easing: "cubic-bezier(.2,.75,.2,1)" },
      );
      animation.id = "nav-shift";
    }
  }

  function settleGhost(drag) {
    if (!drag.ghost) return;
    const ghost = drag.ghost;
    if (!motionAllowed()) { ghost.remove(); return; }
    const target = drag.button.getBoundingClientRect();
    ghost.classList.add("ghost-landing");
    ghost.style.left = `${target.left}px`;
    ghost.style.top = `${target.top}px`;
    ghost.style.width = `${target.width}px`;
    ghost.style.opacity = "0";
    setTimeout(() => ghost.remove(), 210);
  }

  function finishDrag(cancelled) {
    if (!pointerDrag) return;
    const drag = pointerDrag;
    const { button, active, originalOrder } = drag;
    pointerDrag = null;
    button.classList.remove("dragging");
    if (!active) return;
    if (cancelled) {
      for (const item of originalOrder) nav.append(item);
    } else {
      saveOrder();
      announce(button);
    }
    settleGhost(drag);
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
      createGhost(pointerDrag);
      button.classList.add("dragging");
    }
    moveGhost(pointerDrag, event.clientX, event.clientY);
    event.preventDefault();
    const others = [...nav.children].filter(item => item !== button);
    const next = others.find(item => {
      const rect = item.getBoundingClientRect();
      return event.clientY < rect.top + rect.height / 2;
    });
    slideNeighbors(button, next || null);
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
      const rect = button.getBoundingClientRect();
      pointerDrag = {
        button,
        offsetX: event.clientX - rect.left,
        offsetY: event.clientY - rect.top,
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
