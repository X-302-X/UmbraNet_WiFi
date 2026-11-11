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
