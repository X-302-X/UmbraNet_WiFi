"use strict";

(() => {
  const key = "umbranet-wifi.appearance.v1";
  const defaults = {
    transparency: 32, panelTransparency: 0, buttonTransparency: 0, fieldTransparency: 0,
    accent: "#8b6dff", glow: true, colorSync: true, neonTop: "#8b6dff", neonBottom: "#8b6dff",
    neonBrightness: 52, neonSize: 42, elementGlow: 100, backgroundAnimation: "particles",
    backgroundSpeed: 100, particleCount: 8, motion: true, shake: true, shakeStrength: 35,
    shakeSpeed: 100, uiSpeed: 100, textSize: 100, cornerRadius: 100, density: 100, sidebarWidth: 190,
  };
  const ranges = {
    "background-transparency": ["transparency", 0, 100, "%"],
    "panel-transparency": ["panelTransparency", 0, 100, "%"],
    "button-transparency": ["buttonTransparency", 0, 100, "%"],
    "field-transparency": ["fieldTransparency", 0, 100, "%"],
    "neon-brightness": ["neonBrightness", 0, 100, "%"],
    "neon-size": ["neonSize", 20, 80, "%"],
    "element-glow": ["elementGlow", 0, 200, "%"],
    "background-speed": ["backgroundSpeed", 25, 200, "%"],
    "particle-count": ["particleCount", 1, 8, ""],
    "shake-strength": ["shakeStrength", 0, 100, "%"],
    "shake-speed": ["shakeSpeed", 25, 200, "%"],
    "ui-speed": ["uiSpeed", 25, 200, "%"],
    "text-size": ["textSize", 90, 120, "%"],
    "corner-radius": ["cornerRadius", 0, 200, "%"],
    "density": ["density", 80, 120, "%"],
    "sidebar-width": ["sidebarWidth", 175, 230, " px"],
  };
  const groups = {
    transparency: ["transparency", "panelTransparency", "buttonTransparency", "fieldTransparency"],
    colors: ["accent", "glow", "colorSync", "neonTop", "neonBottom", "neonBrightness", "neonSize", "elementGlow"],
    background: ["backgroundAnimation", "backgroundSpeed", "particleCount"],
    motion: ["motion", "shake", "shakeStrength", "shakeSpeed", "uiSpeed"],
    layout: ["textSize", "cornerRadius", "density", "sidebarWidth"],
  };
  const root = document.documentElement;
  const app = document.querySelector(".app");
  const colorFields = { "accent-color": "accent", "neon-top": "neonTop", "neon-bottom": "neonBottom" };
  const toggles = { "glow-toggle": "glow", "motion-toggle": "motion", "shake-toggle": "shake" };
  const animations = ["particles", "waves", "fireflies", "stars", "orbits", "off"];
  let state = { ...defaults };

  try {
    const stored = JSON.parse(localStorage.getItem(key) || "null");
    if (stored && typeof stored === "object") {
      for (const [property, min, max] of Object.values(ranges)) {
        const v = stored[property];
        if (typeof v === "number" && Number.isFinite(v)) state[property] = Math.round(Math.max(min, Math.min(max, v)));
      }
      for (const property of Object.values(colorFields)) {
        if (typeof stored[property] === "string" && /^#[0-9a-f]{6}$/i.test(stored[property])) state[property] = stored[property].toLowerCase();
      }
      for (const property of [...Object.values(toggles), "colorSync"]) {
        if (typeof stored[property] === "boolean") state[property] = stored[property];
      }
      if (animations.includes(stored.backgroundAnimation)) state.backgroundAnimation = stored.backgroundAnimation;
    }
  } catch (_) { /* Use defaults when stored preferences cannot be read. */ }

  function save() {
    try { localStorage.setItem(key, JSON.stringify(state)); }
    catch (_) { /* Controls still work for the current session. */ }
  }
  function foreground(hex) {
    const rgb = [1, 3, 5].map(i => {
      const x = parseInt(hex.slice(i, i + 2), 16) / 255;
      return x <= 0.04045 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4;
    });
    return 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2] > 0.179 ? "#171024" : "#ffffff";
  }
  function render() {
    for (const [id, [prop, , , unit]] of Object.entries(ranges)) {
      document.getElementById(id).value = String(state[prop]);
      document.getElementById(id === "background-transparency" ? "transparency-value" : `${id}-value`).textContent = `${state[prop]}${unit}`;
    }
    for (const [id, prop] of Object.entries(colorFields)) document.getElementById(id).value = state[prop];
    document.querySelector("#neon-bottom").value = state.colorSync ? state.neonTop : state.neonBottom;
    document.querySelector("#neon-bottom").disabled = state.colorSync;
    document.querySelector("#color-sync").checked = state.colorSync;
    document.querySelector("#background-animation").value = state.backgroundAnimation;
    for (const swatch of document.querySelectorAll("[data-accent]")) swatch.setAttribute("aria-pressed", String(swatch.dataset.accent === state.accent));
    for (const [id, prop] of Object.entries(toggles)) {
      const button = document.getElementById(id);
      button.classList.toggle("active", state[prop]);
      button.setAttribute("aria-pressed", String(state[prop]));
    }
    app.classList.toggle("no-glow", !state.glow);
    app.classList.toggle("no-motion", !state.motion);
    app.classList.toggle("no-shake", !state.shake || state.shakeStrength === 0);
    app.dataset.backgroundAnimation = state.backgroundAnimation;
    const props = {
      "--background-opacity": (100 - state.transparency) / 100,
      "--panel-opacity": (100 - state.panelTransparency) / 100,
      "--button-opacity": (100 - state.buttonTransparency) / 100,
      "--field-opacity": (100 - state.fieldTransparency) / 100,
      "--purple": state.accent, "--accent-foreground": foreground(state.accent),
      "--neon-top": state.neonTop, "--neon-bottom": state.colorSync ? state.neonTop : state.neonBottom,
      "--neon-brightness": state.neonBrightness / 100, "--neon-size": `${state.neonSize}%`,
      "--element-glow": state.elementGlow / 100, "--ambient-duration": `${500 / state.backgroundSpeed}s`,
      "--shake-duration": `${35 / state.shakeSpeed}s`, "--shake-distance": `${state.shakeStrength / 100 * 1.5}px`,
      "--shake-angle": `${state.shakeStrength / 100 * 1.5}deg`,
      "--ui-duration": `${16 / state.uiSpeed}s`, "--ui-factor": 100 / state.uiSpeed,
      "--font-scale": state.textSize / 100, "--radius-scale": state.cornerRadius / 100,
      "--density": state.density / 100, "--sidebar-width": `${state.sidebarWidth}px`,
    };
    for (const [name, value] of Object.entries(props)) root.style.setProperty(name, String(value));
    [...document.querySelectorAll(".particle")].forEach((particle, index) => { particle.hidden = index >= state.particleCount; });
    document.getElementById("background-speed").disabled = state.backgroundAnimation === "off";
    document.getElementById("particle-count").disabled = state.backgroundAnimation === "off";
  }
  function update() { render(); save(); }
  for (const [id, [prop]] of Object.entries(ranges)) document.getElementById(id).addEventListener("input", event => { state[prop] = Number(event.target.value); update(); });
  for (const [id, prop] of Object.entries(colorFields)) document.getElementById(id).addEventListener("input", event => { state[prop] = event.target.value.toLowerCase(); update(); });
  for (const swatch of document.querySelectorAll("[data-accent]")) swatch.addEventListener("click", () => { state.accent = swatch.dataset.accent; update(); });
  for (const [id, prop] of Object.entries(toggles)) document.getElementById(id).addEventListener("click", () => { state[prop] = !state[prop]; update(); });
  document.getElementById("color-sync").addEventListener("change", event => { state.colorSync = event.target.checked; update(); });
  document.getElementById("background-animation").addEventListener("change", event => { if (animations.includes(event.target.value)) state.backgroundAnimation = event.target.value; update(); });
  for (const button of document.querySelectorAll("[data-reset-group]")) button.addEventListener("click", () => {
    for (const prop of groups[button.dataset.resetGroup]) state[prop] = defaults[prop];
    update();
  });
  document.getElementById("reset-appearance").addEventListener("click", () => { state = { ...defaults }; update(); });
  render();
})();
