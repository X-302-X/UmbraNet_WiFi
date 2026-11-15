"use strict";

(() => {
  const key = "umbranet-wifi.appearance.v1";
  const defaults = {
    style: "normal", classicBackup: null,
    transparency: 0, panelTransparency: 100, buttonTransparency: 0, fieldTransparency: 100,
    accent: "#8b6dff", borderColor: "#302b46",
    vpnColor: "#8b6dff", comboColor: "#8b6dff", dpiColor: "#8b6dff",
    restartColor: "#171325", startColor: "#8b6dff", stopColor: "#ed5969",
    glow: true, colorSync: true, neonTop: "#8b6dff", neonBottom: "#8b6dff",
    neonBrightness: 52, neonSize: 42, elementGlow: 100, backgroundAnimation: "particles",
    backgroundSpeed: 100, particleCount: 8, motion: true, shake: true, shakeStrength: 35,
    shakeSpeed: 100, uiSpeed: 100, textSize: 100, cornerRadius: 100, density: 100, sidebarWidth: 190,
  };
  const watcherPreset = {
    transparency: 0, panelTransparency: 100, buttonTransparency: 0, fieldTransparency: 100,
    accent: "#dc2636", borderColor: "#6e171f", vpnColor: "#9f1724", comboColor: "#9f1724",
    dpiColor: "#9f1724", restartColor: "#26080d", startColor: "#a91826", stopColor: "#d22838",
    glow: false, colorSync: true, neonTop: "#dc2636", neonBottom: "#dc2636",
    neonBrightness: 52, neonSize: 42, elementGlow: 85, backgroundAnimation: "watcher",
    backgroundSpeed: 100, particleCount: 8,
  };
  const presetProperties = Object.keys(watcherPreset);
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
    controls: ["buttonTransparency", "fieldTransparency", "vpnColor", "comboColor", "dpiColor", "restartColor", "startColor", "stopColor"],
    background: ["transparency", "backgroundAnimation", "backgroundSpeed", "particleCount"],
    panels: ["panelTransparency"],
    colors: ["accent", "borderColor", "glow", "colorSync", "neonTop", "neonBottom", "neonBrightness", "neonSize", "elementGlow"],
    navigation: ["sidebarWidth", "shake", "shakeStrength", "shakeSpeed"],
    general: ["motion", "uiSpeed", "textSize", "cornerRadius", "density"],
  };
  const root = document.documentElement;
  const app = document.querySelector(".app");
  const colorFields = {
    "accent-color": "accent", "border-color": "borderColor", "neon-top": "neonTop", "neon-bottom": "neonBottom",
    "color-vpn": "vpnColor", "color-combo": "comboColor", "color-dpi": "dpiColor",
    "color-restart": "restartColor", "color-start": "startColor", "color-stop": "stopColor",
  };
  const toggles = { "glow-toggle": "glow", "motion-toggle": "motion", "shake-toggle": "shake" };
  const animations = ["particles", "waves", "fireflies", "stars", "orbits", "watcher", "off"];
  const animationSelect = document.querySelector("#animation-select");
  const animationTrigger = document.querySelector("#background-animation");
  const animationCurrent = document.querySelector("#animation-current");
  const animationList = document.querySelector("#animation-options");
  const animationOptions = [...animationList.querySelectorAll("[role=option]")];
  let state = { ...defaults };

  function applyValues(stored, target) {
    if (!stored || typeof stored !== "object" || Array.isArray(stored)) return false;
    for (const [property, min, max] of Object.values(ranges)) {
      const v = stored[property];
      if (typeof v === "number" && Number.isFinite(v)) target[property] = Math.round(Math.max(min, Math.min(max, v)));
    }
    for (const property of Object.values(colorFields)) {
      if (typeof stored[property] === "string" && /^#[0-9a-f]{6}$/i.test(stored[property])) target[property] = stored[property].toLowerCase();
    }
    for (const property of [...Object.values(toggles), "colorSync"]) {
      if (typeof stored[property] === "boolean") target[property] = stored[property];
    }
    if (animations.includes(stored.backgroundAnimation)) target.backgroundAnimation = stored.backgroundAnimation;
    return true;
  }
  function applyStored(stored) {
    if (!applyValues(stored, state)) return false;
    state.style = stored.style === "watcher" ? "watcher" : "normal";
    if (stored.classicBackup && typeof stored.classicBackup === "object" && !Array.isArray(stored.classicBackup)) {
      const backup = { ...defaults };
      applyValues(stored.classicBackup, backup);
      state.classicBackup = Object.fromEntries(presetProperties.map(prop => [prop, backup[prop]]));
    }
    if (state.style !== "watcher" && state.backgroundAnimation === "watcher") state.backgroundAnimation = defaults.backgroundAnimation;
    return true;
  }

  let localSettings = null;
  try {
    localSettings = JSON.parse(localStorage.getItem(key) || "null");
    applyStored(localSettings);
  } catch (_) { /* Keep defaults if the WebView cache cannot be read. */ }

  const invoke = window.__TAURI_INTERNALS__?.invoke;
  const section = document.getElementById("appearance");
  const saveStatus = document.getElementById("appearance-save-status");
  let durableReady = false, durableAllowed = true, pendingSave = null, saveRunning = false;
  function persistenceWarning(message) {
    saveStatus.textContent = message;
    saveStatus.hidden = !message;
  }
  async function flushSaves() {
    if (!durableReady || !durableAllowed || saveRunning || typeof invoke !== "function") return;
    saveRunning = true;
    try {
      while (pendingSave !== null) {
        const value = pendingSave;
        pendingSave = null;
        try {
          await invoke("appearance_save", { value });
          persistenceWarning("");
        } catch (error) {
          persistenceWarning(`Не удалось сохранить настройки оформления: ${String(error)}`);
          break;
        }
      }
    } finally { saveRunning = false; }
  }
  function save() {
    const value = JSON.stringify(state);
    try { localStorage.setItem(key, value); }
    catch (_) { persistenceWarning("Не удалось сохранить настройки в хранилище окна."); }
    pendingSave = value;
    flushSaves();
  }
  async function loadDurableSettings() {
    if (typeof invoke !== "function") return;
    section.inert = true;
    section.setAttribute("aria-busy", "true");
    try {
      const value = await invoke("appearance_load");
      if (value !== null) {
        if (typeof value !== "string") throw new Error("Получен неверный формат настроек.");
        const stored = JSON.parse(value);
        if (!stored || typeof stored !== "object" || Array.isArray(stored)) throw new Error("Получен неверный формат настроек.");
        state = { ...defaults };
        applyStored(stored);
        try { localStorage.setItem(key, JSON.stringify(state)); } catch (_) { /* Persistent file remains authoritative. */ }
      } else if (localSettings && typeof localSettings === "object" && !Array.isArray(localSettings)) {
        // One-time migration from the existing WebView profile; never replace an existing file.
        const migrated = await invoke("appearance_migrate", { value: JSON.stringify(state) });
        if (migrated === false) {
          const current = await invoke("appearance_load");
          if (typeof current !== "string") throw new Error("Не удалось прочитать существующие настройки.");
          const stored = JSON.parse(current);
          if (!stored || typeof stored !== "object" || Array.isArray(stored)) throw new Error("Получен неверный формат настроек.");
          state = { ...defaults };
          applyStored(stored);
          try { localStorage.setItem(key, JSON.stringify(state)); } catch (_) { /* The file remains authoritative. */ }
        } else if (migrated !== true) {
          throw new Error("Не удалось проверить перенос настроек.");
        }
      }
      persistenceWarning("");
    } catch (error) {
      durableAllowed = false;
      persistenceWarning(`Не удалось загрузить или сохранить настройки оформления: ${String(error)}`);
    } finally {
      durableReady = true;
      render();
      section.inert = false;
      section.removeAttribute("aria-busy");
      flushSaves();
    }
  }
  function foreground(hex) {
    const rgb = [1, 3, 5].map(i => {
      const x = parseInt(hex.slice(i, i + 2), 16) / 255;
      return x <= 0.04045 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4;
    });
    const luminance = 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2];
    const dark = [23, 16, 36].map(value => {
      const x = value / 255;
      return x <= 0.04045 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4;
    });
    const darkLuminance = 0.2126 * dark[0] + 0.7152 * dark[1] + 0.0722 * dark[2];
    return (luminance + 0.05) / (darkLuminance + 0.05) > 1.05 / (luminance + 0.05) ? "#171024" : "#ffffff";
  }
  function buttonForeground(hex, background = [6, 6, 12]) {
    const opacity = (100 - state.buttonTransparency) / 100;
    const rgb = background.map((base, index) => Math.round(base * (1 - opacity) + parseInt(hex.slice(1 + index * 2, 3 + index * 2), 16) * opacity));
    return foreground(`#${rgb.map(value => value.toString(16).padStart(2, "0")).join("")}`);
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
    const selected = animationOptions.find(option => option.dataset.animation === state.backgroundAnimation);
    animationCurrent.textContent = selected.textContent;
    for (const option of animationOptions) option.setAttribute("aria-selected", String(option === selected));
    for (const swatch of document.querySelectorAll("[data-accent]")) swatch.setAttribute("aria-pressed", String(swatch.dataset.accent === state.accent));
    for (const swatch of document.querySelectorAll("[data-border]")) swatch.setAttribute("aria-pressed", String(swatch.dataset.border === state.borderColor));
    for (const [id, prop] of Object.entries(toggles)) {
      const button = document.getElementById(id);
      button.classList.toggle("active", state[prop]);
      button.setAttribute("aria-pressed", String(state[prop]));
    }
    const watcher = state.style === "watcher";
    const modified = watcher && presetProperties.some(prop => state[prop] !== watcherPreset[prop]);
    document.getElementById("preset-current").textContent = watcher ? (modified ? "Свой вариант · 👁 Do you see me?" : "👁 Do you see me?") : "Обычное оформление";
    for (const option of document.querySelectorAll("[data-preset]")) option.setAttribute("aria-selected", String(option.dataset.preset === state.style && !modified));
    document.querySelector('[data-animation="watcher"]').hidden = !watcher;
    app.dataset.style = state.style;
    app.classList.toggle("no-glow", !state.glow);
    app.classList.toggle("no-motion", !state.motion);
    app.classList.toggle("no-shake", !state.shake || state.shakeStrength === 0);
    app.dataset.backgroundAnimation = state.backgroundAnimation;
    app.dataset.watcherSpeed = String(state.backgroundSpeed);
    const props = {
      "--background-opacity": (100 - state.transparency) / 100,
      "--panel-opacity": (100 - state.panelTransparency) / 100,
      "--button-opacity": (100 - state.buttonTransparency) / 100,
      "--field-opacity": (100 - state.fieldTransparency) / 100,
      "--purple": state.accent, "--accent-foreground": foreground(state.accent), "--border": state.borderColor,
      "--vpn-color": state.vpnColor, "--combo-color": state.comboColor, "--dpi-color": state.dpiColor,
      "--restart-color": state.restartColor, "--start-color": state.startColor, "--stop-color": state.stopColor,
      "--vpn-foreground": buttonForeground(state.vpnColor, [25, 25, 37]), "--combo-foreground": buttonForeground(state.comboColor, [25, 25, 37]),
      "--dpi-foreground": buttonForeground(state.dpiColor, [25, 25, 37]), "--restart-foreground": buttonForeground(state.restartColor),
      "--start-foreground": buttonForeground(state.startColor), "--stop-foreground": buttonForeground(state.stopColor),
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
    document.getElementById("particle-count").disabled = state.backgroundAnimation === "off" || state.backgroundAnimation === "watcher";
    window.dispatchEvent(new CustomEvent("umbra-appearance", { detail: { style: state.style, animation: state.backgroundAnimation, motion: state.motion, speed: state.backgroundSpeed } }));
  }
  function update() { render(); save(); }
  for (const [id, [prop]] of Object.entries(ranges)) document.getElementById(id).addEventListener("input", event => { state[prop] = Number(event.target.value); update(); });
  for (const [id, prop] of Object.entries(colorFields)) document.getElementById(id).addEventListener("input", event => { state[prop] = event.target.value.toLowerCase(); update(); });
  for (const swatch of document.querySelectorAll("[data-accent]")) swatch.addEventListener("click", () => { state.accent = swatch.dataset.accent; update(); });
  for (const swatch of document.querySelectorAll("[data-border]")) swatch.addEventListener("click", () => { state.borderColor = swatch.dataset.border; update(); });
  for (const [id, prop] of Object.entries(toggles)) document.getElementById(id).addEventListener("click", () => { state[prop] = !state[prop]; update(); });
  document.getElementById("color-sync").addEventListener("change", event => { state.colorSync = event.target.checked; update(); });
  const presetSelect = document.getElementById("preset-select");
  const presetTrigger = document.getElementById("preset-trigger");
  const presetList = document.getElementById("preset-options");
  const presetOptions = [...presetList.querySelectorAll("[data-preset]")];
  function closePresetList(restoreFocus = false) {
    presetList.hidden = true;
    presetTrigger.setAttribute("aria-expanded", "false");
    if (restoreFocus) presetTrigger.focus();
  }
  function openPresetList() {
    presetList.hidden = false;
    presetTrigger.setAttribute("aria-expanded", "true");
    presetOptions.find(option => option.dataset.preset === state.style).focus({ preventScroll: true });
  }
  presetTrigger.addEventListener("click", () => presetList.hidden ? openPresetList() : closePresetList());
  presetTrigger.addEventListener("keydown", event => {
    if (["ArrowDown", "ArrowUp"].includes(event.key)) { event.preventDefault(); openPresetList(); }
  });
  presetList.addEventListener("click", event => {
    const option = event.target.closest("[data-preset]");
    if (!option) return;
    if (option.dataset.preset === "watcher") {
      if (state.style !== "watcher") state.classicBackup = Object.fromEntries(presetProperties.map(prop => [prop, state[prop]]));
      Object.assign(state, watcherPreset, { style: "watcher" });
    } else if (state.style === "watcher") {
      Object.assign(state, state.classicBackup || Object.fromEntries(presetProperties.map(prop => [prop, defaults[prop]])));
      state.style = "normal";
      if (state.backgroundAnimation === "watcher") state.backgroundAnimation = defaults.backgroundAnimation;
      state.classicBackup = null;
    }
    update();
    closePresetList(true);
  });
  presetList.addEventListener("keydown", event => {
    if (event.key === "Escape") { event.preventDefault(); closePresetList(true); return; }
    const index = presetOptions.indexOf(document.activeElement);
    let next;
    if (event.key === "ArrowDown") next = (index + 1) % presetOptions.length;
    else if (event.key === "ArrowUp") next = (index - 1 + presetOptions.length) % presetOptions.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = presetOptions.length - 1;
    else return;
    event.preventDefault();
    presetOptions[next].focus();
  });
  document.addEventListener("pointerdown", event => { if (!presetSelect.contains(event.target)) closePresetList(); });
  presetSelect.addEventListener("focusout", event => { if (!presetSelect.contains(event.relatedTarget)) closePresetList(); });

  function closeAnimationList(restoreFocus = false) {
    animationList.hidden = true;
    animationTrigger.setAttribute("aria-expanded", "false");
    if (restoreFocus) animationTrigger.focus();
  }
  function openAnimationList() {
    animationList.hidden = false;
    animationTrigger.setAttribute("aria-expanded", "true");
    const selected = animationOptions.find(option => option.dataset.animation === state.backgroundAnimation);
    selected.focus({ preventScroll: true });
    selected.scrollIntoView({ block: "nearest" });
  }
  animationTrigger.addEventListener("click", () => {
    if (animationList.hidden) openAnimationList();
    else closeAnimationList();
  });
  animationTrigger.addEventListener("keydown", event => {
    if (["ArrowDown", "ArrowUp"].includes(event.key)) {
      event.preventDefault();
      openAnimationList();
    }
  });
  animationList.addEventListener("click", event => {
    const option = event.target.closest("[data-animation]");
    if (!option || option.hidden || !animations.includes(option.dataset.animation)) return;
    state.backgroundAnimation = option.dataset.animation;
    update();
    closeAnimationList(true);
  });
  animationList.addEventListener("keydown", event => {
    if (event.key === "Escape") { event.preventDefault(); closeAnimationList(true); return; }
    const visibleOptions = animationOptions.filter(option => !option.hidden);
    const index = visibleOptions.indexOf(document.activeElement);
    let next;
    if (event.key === "ArrowDown") next = (index + 1) % visibleOptions.length;
    else if (event.key === "ArrowUp") next = (index - 1 + visibleOptions.length) % visibleOptions.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = visibleOptions.length - 1;
    else return;
    event.preventDefault();
    visibleOptions[next].focus();
  });
  document.addEventListener("pointerdown", event => {
    if (!animationSelect.contains(event.target)) closeAnimationList();
  });
  animationSelect.addEventListener("focusout", event => {
    if (!animationSelect.contains(event.relatedTarget)) closeAnimationList();
  });
  animationSelect.closest("details").addEventListener("toggle", event => {
    if (!event.target.open) closeAnimationList();
  });
  for (const button of document.querySelectorAll("[data-reset-group]")) button.addEventListener("click", () => {
    for (const prop of groups[button.dataset.resetGroup]) state[prop] = defaults[prop];
    update();
  });
  document.getElementById("reset-appearance").addEventListener("click", () => { state = { ...defaults }; update(); });
  render();
  loadDurableSettings();
})();
