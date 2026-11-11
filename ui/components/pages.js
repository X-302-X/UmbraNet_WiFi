"use strict";

(() => {
  const search = document.querySelector("#catalog-search");
  const groups = [...document.querySelectorAll(".catalog-group")];
  const empty = document.querySelector("#catalog-empty");
  search.addEventListener("input", () => {
    const query = search.value.trim().toLocaleLowerCase("ru");
    let found = 0;
    for (const group of groups) {
      let groupFound = 0;
      for (const row of group.querySelectorAll("[data-service]")) {
        const matches = row.dataset.service.includes(query);
        row.hidden = !matches;
        if (matches) { found++; groupFound++; }
      }
      group.hidden = groupFound === 0;
    }
    empty.hidden = found !== 0;
  });

  // Visual selections are session-only and do not control network settings.
  const modes = [...document.querySelectorAll("[data-mode]")];
  const comboTabs = [...document.querySelectorAll("[data-route-tab]")];
  const comboGroup = document.querySelector("#combo-tabs");
  const panels = { vpn: document.querySelector("#route-vpn"), dpi: document.querySelector("#route-dpi") };
  let currentMode = "vpn";
  let comboView = "vpn";

  function renderRoutePicker() {
    const shown = currentMode === "combo" ? comboView : currentMode;
    comboGroup.hidden = currentMode !== "combo";
    for (const [id, panel] of Object.entries(panels)) panel.hidden = id !== shown;
    for (const tab of comboTabs) {
      const selected = tab.dataset.routeTab === comboView;
      tab.classList.toggle("active", selected);
      tab.setAttribute("aria-pressed", String(selected));
    }
    for (const button of modes) button.setAttribute("aria-pressed", String(button.dataset.mode === currentMode));
  }

  for (const button of modes) button.addEventListener("click", () => {
    currentMode = button.dataset.mode;
    renderRoutePicker();
  });
  for (const tab of comboTabs) tab.addEventListener("click", () => {
    comboView = tab.dataset.routeTab;
    renderRoutePicker();
  });
  for (const button of document.querySelectorAll("[data-preview-picker]")) {
    button.addEventListener("click", () => {
      const selected = button.getAttribute("aria-pressed") !== "true";
      button.setAttribute("aria-pressed", String(selected));
    });
  }
  renderRoutePicker();

  for (const button of document.querySelectorAll(".catalog-row .toggle, .catalog-row .favorite")) {
    button.addEventListener("click", () => {
      const selected = button.getAttribute("aria-pressed") !== "true";
      button.setAttribute("aria-pressed", String(selected));
      button.classList.toggle("active", selected);
      if (button.classList.contains("favorite")) button.textContent = selected ? "★" : "☆";
    });
  }

  const subtabs = [...document.querySelectorAll("[data-group][data-panel]")];
  for (const tab of subtabs) {
    tab.addEventListener("click", () => {
      for (const other of subtabs.filter(item => item.dataset.group === tab.dataset.group)) {
        const selected = other === tab;
        other.classList.toggle("active", selected);
        other.setAttribute("aria-pressed", String(selected));
        document.getElementById(other.dataset.panel).hidden = !selected;
      }
    });
  }
})();
