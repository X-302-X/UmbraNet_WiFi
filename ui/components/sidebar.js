"use strict";

(() => {
  const sidebar = document.querySelector(".sidebar");
  const toggle = document.querySelector("#sidebar-toggle");
  for (const button of document.querySelectorAll(".nav-item")) {
    const label = button.querySelector(".nav-label").textContent.trim();
    button.setAttribute("aria-label", label);
    button.title = label;
  }
  toggle.addEventListener("click", () => {
    const collapsed = sidebar.classList.toggle("collapsed");
    toggle.textContent = collapsed ? "»" : "«";
    toggle.setAttribute("aria-expanded", String(!collapsed));
    toggle.setAttribute("aria-label", collapsed ? "Развернуть меню" : "Свернуть меню");
  });
})();
