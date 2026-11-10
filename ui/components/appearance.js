"use strict";

(() => {
  const key = "umbranet-wifi.appearance.v1";
  const defaults = { transparency: 32, accent: "#a578ff", glow: true, motion: true };
  const root = document.documentElement;
  const app = document.querySelector(".app");
  const slider = document.querySelector("#background-transparency");
  const valueLabel = document.querySelector("#transparency-value");
  const colorInput = document.querySelector("#accent-color");
  const swatches = document.querySelectorAll("[data-accent]");
  let state = { ...defaults };

  try {
    const stored = JSON.parse(localStorage.getItem(key) || "null");
    if (stored && typeof stored === "object") {
      if (typeof stored.transparency === "number" && Number.isFinite(stored.transparency)) state.transparency = Math.max(0, Math.min(100, stored.transparency));
      if (typeof stored.accent === "string" && /^#[0-9a-f]{6}$/i.test(stored.accent)) state.accent = stored.accent.toLowerCase();
      if (typeof stored.glow === "boolean") state.glow = stored.glow;
      if (typeof stored.motion === "boolean") state.motion = stored.motion;
    }
  } catch (_) { /* Use defaults when stored preferences cannot be read. */ }

  function save() {
    try { localStorage.setItem(key, JSON.stringify(state)); }
    catch (_) { /* Controls keep working for this session. */ }
  }

  function foreground(hex) {
    const rgb = [1, 3, 5].map(i => {
      const x = parseInt(hex.slice(i, i + 2), 16) / 255;
      return x <= 0.04045 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4;
    });
    return 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2] > 0.179 ? "#171024" : "#ffffff";
  }

  function render() {
    slider.value = String(state.transparency);
    valueLabel.textContent = `${state.transparency}%`;
    root.style.setProperty("--background-opacity", String((100 - state.transparency) / 100));
    root.style.setProperty("--purple", state.accent);
    root.style.setProperty("--accent-foreground", foreground(state.accent));
    colorInput.value = state.accent;
    for (const swatch of swatches) swatch.setAttribute("aria-pressed", String(swatch.dataset.accent === state.accent));
    for (const [id, prop, className] of [["glow-toggle", "glow", "no-glow"], ["motion-toggle", "motion", "no-motion"]]) {
      const button = document.getElementById(id);
      button.classList.toggle("active", state[prop]);
      button.setAttribute("aria-pressed", String(state[prop]));
      app.classList.toggle(className, !state[prop]);
    }
  }

  slider.addEventListener("input", () => { state.transparency = Number(slider.value); render(); save(); });
  for (const swatch of swatches) swatch.addEventListener("click", () => { state.accent = swatch.dataset.accent; render(); save(); });
  colorInput.addEventListener("input", () => { state.accent = colorInput.value; render(); save(); });
  for (const [id, prop] of [["glow-toggle", "glow"], ["motion-toggle", "motion"]]) {
    document.getElementById(id).addEventListener("click", () => { state[prop] = !state[prop]; render(); save(); });
  }
  document.getElementById("reset-appearance").addEventListener("click", () => { state = { ...defaults }; render(); save(); });
  render();
})();
