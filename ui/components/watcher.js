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
  const messages = [
    "He sees!", "Do you remember me?", "I can see you.", "Don't look away.",
    "Still here?", "Behind the screen.", "You are not alone.", "I never left.",
    "I am watching.", "Look again.", "We remember you.", "There you are.",
  ];
  let timer = null;
  let enabled = false;
  let eyesUntilMessage = 2 + Math.floor(Math.random() * 3);
  let previousMessage = -1;
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
    const angle = (Math.random() < .5 ? -1 : 1) * (7 + Math.random() * 16);
    const baseWidth = kind === "eyes" ? Math.max(150, Math.min(width * .20, 250)) : 250;
    const baseHeight = kind === "eyes" ? baseWidth * .56 : 34;
    const radians = Math.abs(angle) * Math.PI / 180;
    const sceneWidth = baseWidth * Math.cos(radians) + baseHeight * Math.sin(radians);
    const sceneHeight = baseWidth * Math.sin(radians) + baseHeight * Math.cos(radians);
    scene.style.setProperty("--scene-angle", `${angle.toFixed(1)}deg`);
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
    const kind = eyesUntilMessage > 0 ? "eyes" : "message";
    if (kind === "eyes") eyesUntilMessage--;
    else eyesUntilMessage = 2 + Math.floor(Math.random() * 3);
    scene.classList.remove("visible");
    scene.dataset.kind = kind;
    placeScene(kind);
    if (kind === "message") {
      let index = Math.floor(Math.random() * messages.length);
      if (index === previousMessage) index = (index + 1) % messages.length;
      previousMessage = index;
      message.textContent = `> ${messages[index]}`;
    }
    const duration = Math.max(2500, Math.min(12000, (kind === "eyes" ? 4600 : 4200) * 100 / speed));
    scene.style.setProperty("--scene-duration", `${duration}ms`);
    scene.style.setProperty("--typing-duration", `${Math.round(duration * .45)}ms`);
    void scene.offsetWidth;
    scene.classList.add("visible");
    timer = setTimeout(() => {
      scene.classList.remove("visible");
      if (enabled) schedule((1200 + Math.random() * 1800) * 100 / speed);
    }, duration);
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
    if (enabled) schedule(900);
  }
  window.addEventListener("umbra-appearance", event => {
    speed = Math.max(25, Math.min(200, event.detail.speed || 100));
    refresh();
  });
  document.addEventListener("visibilitychange", refresh);
  reducedMotion.addEventListener("change", refresh);
  refresh();
})();
