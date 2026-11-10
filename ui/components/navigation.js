"use strict";

(() => {
  const nav = document.querySelector("#navigation");
  const pages = [...document.querySelectorAll(".page")];
  const buttons = [...nav.querySelectorAll(".nav-item")];
  const orderKey = "umbranet-wifi.navigation-order.v1";
  const announcer = document.querySelector("#announcer");
  let dragged = null;

  function saveOrder() {
    try {
      localStorage.setItem(orderKey, JSON.stringify([...nav.children].map(button => button.dataset.page)));
    } catch (_) { /* Interface remains usable if browser storage is unavailable. */ }
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

  for (const button of buttons) {
    button.addEventListener("click", () => showPage(button.dataset.page));
    button.addEventListener("dragstart", event => {
      dragged = button;
      button.classList.add("dragging");
      event.dataTransfer.effectAllowed = "move";
      event.dataTransfer.setData("text/plain", button.dataset.page);
    });
    button.addEventListener("dragend", () => {
      button.classList.remove("dragging");
      dragged = null;
      saveOrder();
    });
    button.addEventListener("dragover", event => {
      if (!dragged || dragged === button) return;
      event.preventDefault();
      event.dataTransfer.dropEffect = "move";
      const below = event.clientY > button.getBoundingClientRect().top + button.offsetHeight / 2;
      nav.insertBefore(dragged, below ? button.nextElementSibling : button);
    });
    button.addEventListener("drop", event => {
      if (dragged) { event.preventDefault(); saveOrder(); }
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
      announcer.textContent = `${button.textContent.trim()}: позиция ${[...nav.children].indexOf(button) + 1} из ${buttons.length}`;
    });
  }
  for (const button of document.querySelectorAll("[data-open]")) {
    button.addEventListener("click", () => showPage(button.dataset.open));
  }
})();
