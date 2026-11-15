"use strict";

(() => {
  const app = document.querySelector(".app");
  const scene = document.getElementById("watcher-scene");
  const message = document.getElementById("watcher-message");
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  const icons = [
    ["[data-page='routing'] .nav-emoji", "☠️"], ["[data-page='vpn'] .nav-emoji", "👁️"],
    ["[data-page='ai'] .nav-emoji", "💉"], ["[data-page='logs'] .nav-emoji", "🩸"],
    ["[data-page='settings'] .nav-emoji", "🔪"], ["[data-page='about'] .nav-emoji", "💀"],
    ["[data-mode='vpn'] .mode-emoji", "👁️"], ["[data-mode='combo'] .mode-emoji", "🪓"],
    ["[data-mode='dpi'] .mode-emoji", "☠️"],
  ].map(([selector, themed]) => {
    const element = document.querySelector(selector);
    return { element, original: element.textContent, themed };
  });
  const messages = ["He sees!", "Do you remember me?"];
  let timer = null;
  let enabled = false;
  let previousKind = "";
  let speed = 100;

  function stop() {
    clearTimeout(timer);
    timer = null;
    scene.classList.remove("visible");
    scene.dataset.kind = "";
  }
  function schedule(delay) {
    clearTimeout(timer);
    timer = setTimeout(showScene, delay);
  }
  function placeScene(kind) {
    const width = app.clientWidth;
    const height = app.clientHeight;
    const sceneWidth = kind === "eyes" ? Math.max(190, Math.min(width * .26, 330)) : 250;
    const sceneHeight = kind === "eyes" ? sceneWidth * .38 : 34;
    const obstacles = [];
    for (const element of app.querySelectorAll("button, input, textarea, select")) {
      const rect = element.getBoundingClientRect();
      if (rect.width && rect.height) obstacles.push(rect);
    }
    const walker = document.createTreeWalker(app, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      const node = walker.currentNode;
      if (!node.textContent.trim() || node.parentElement.closest('[aria-hidden="true"], script, style')) continue;
      const range = document.createRange();
      range.selectNodeContents(node);
      for (const rect of range.getClientRects()) if (rect.width && rect.height) obstacles.push(rect);
    }
    let best = null;
    for (let i = 0; i < 64; i++) {
      const x = width * (.29 + Math.random() * .55);
      const y = height * (.17 + Math.random() * .69);
      const left = x - sceneWidth / 2, top = y - sceneHeight / 2;
      let overlap = 0;
      for (const rect of obstacles) {
        overlap += Math.max(0, Math.min(left + sceneWidth, rect.right) - Math.max(left, rect.left)) *
          Math.max(0, Math.min(top + sceneHeight, rect.bottom) - Math.max(top, rect.top));
      }
      if (!best || overlap < best.overlap) best = { x, y, overlap };
      if (overlap === 0) break;
    }
    scene.style.setProperty("--scene-x", `${best.x / width * 100}%`);
    scene.style.setProperty("--scene-y", `${best.y / height * 100}%`);
  }
  function showScene() {
    if (!enabled) return;
    const kind = previousKind === "eyes" ? "message" : "eyes";
    previousKind = kind;
    scene.classList.remove("visible");
    scene.dataset.kind = kind;
    placeScene(kind);
    if (kind === "message") message.textContent = `> ${messages[Math.floor(Math.random() * messages.length)]}`;
    void scene.offsetWidth;
    scene.classList.add("visible");
    timer = setTimeout(() => {
      scene.classList.remove("visible");
      if (enabled) schedule((8500 + Math.random() * 11000) * 100 / speed);
    }, 6800);
  }
  function refresh() {
    speed = Math.max(25, Math.min(200, Number(app.dataset.watcherSpeed) || 100));
    const watching = app.dataset.style === "watcher";
    for (const icon of icons) icon.element.textContent = watching ? icon.themed : icon.original;
    const nextEnabled = watching && app.dataset.backgroundAnimation === "watcher" &&
      !app.classList.contains("no-motion") && !reducedMotion.matches && !document.hidden;
    if (nextEnabled === enabled) return;
    enabled = nextEnabled;
    stop();
    if (enabled) schedule(2300);
  }
  window.addEventListener("umbra-appearance", event => {
    speed = Math.max(25, Math.min(200, event.detail.speed || 100));
    refresh();
  });
  document.addEventListener("visibilitychange", refresh);
  reducedMotion.addEventListener("change", refresh);
  refresh();
})();
