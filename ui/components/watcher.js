"use strict";

(() => {
  const app = document.querySelector(".app");
  const field = document.getElementById("watcher-eye-field");
  const template = document.getElementById("watcher-eye-template");
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
  const timers = new Set();
  let enabled = false;
  let questionsBeforePhrase = 2;
  let previousMessage = -1;
  let speed = 100;
  let obstacleCache = null;
  let obstacleCacheTime = 0;
  let lastGlitch = -1;

  function later(callback, delay) {
    const timer = setTimeout(() => { timers.delete(timer); callback(); }, delay);
    timers.add(timer);
  }
  function stop() {
    for (const timer of timers) clearTimeout(timer);
    timers.clear();
    field.replaceChildren();
    obstacleCache = null;
    scene.classList.remove("visible");
    scene.dataset.kind = "";
  }
  function scaled(milliseconds, minimum) {
    return Math.max(minimum, milliseconds * 100 / speed);
  }
  function obstacles() {
    const boxes = [];
    const root = app.getBoundingClientRect();
    function add(rect) {
      if (rect.width && rect.height && rect.right > root.left && rect.left < root.right && rect.bottom > root.top && rect.top < root.bottom) {
        boxes.push({ left: rect.left - root.left, right: rect.right - root.left, top: rect.top - root.top, bottom: rect.bottom - root.top });
      }
    }
    for (const element of app.querySelectorAll("button, input, textarea, select")) add(element.getBoundingClientRect());
    const walker = document.createTreeWalker(app, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      const node = walker.currentNode;
      if (!node.textContent.trim() || node.parentElement.closest('[aria-hidden="true"], script, style')) continue;
      const range = document.createRange();
      range.selectNodeContents(node);
      for (const rect of range.getClientRects()) add(rect);
    }
    return boxes;
  }
  function position(width, height, angle, boxes, region = null) {
    const radians = Math.abs(angle) * Math.PI / 180;
    const w = width * Math.cos(radians) + height * Math.sin(radians);
    const h = width * Math.sin(radians) + height * Math.cos(radians);
    const availableWidth = app.clientWidth, availableHeight = app.clientHeight;
    const left = Math.max(w / 2, region ? region.column * availableWidth / 4 : 0);
    const right = Math.min(availableWidth - w / 2, region ? (region.column + 1) * availableWidth / 4 : availableWidth);
    const top = Math.max(h / 2, region ? region.row * availableHeight / 3 : 0);
    const bottom = Math.min(availableHeight - h / 2, region ? (region.row + 1) * availableHeight / 3 : availableHeight);
    let best;
    for (let i = 0; i < 28; i++) {
      const x = left + Math.random() * Math.max(0, right - left);
      const y = top + Math.random() * Math.max(0, bottom - top);
      const candidate = { left: x - w / 2, right: x + w / 2, top: y - h / 2, bottom: y + h / 2, x, y };
      let overlap = 0;
      for (const rect of boxes) {
        overlap += Math.max(0, Math.min(candidate.right, rect.right) - Math.max(candidate.left, rect.left)) *
          Math.max(0, Math.min(candidate.bottom, rect.bottom) - Math.max(candidate.top, rect.top));
      }
      if (!best || overlap < best.overlap) best = { ...candidate, overlap };
      if (overlap === 0) break;
    }
    return best;
  }
  function randomAngle() {
    return (Math.random() < .5 ? -1 : 1) * (7 + Math.random() * 28);
  }
  function cachedObstacles() {
    const now = performance.now();
    if (!obstacleCache || now - obstacleCacheTime > 700) {
      obstacleCache = obstacles();
      obstacleCacheTime = now;
    }
    return obstacleCache.slice();
  }
  function showEye() {
    if (!enabled) return;
    const boxes = cachedObstacles();
    const root = app.getBoundingClientRect();
    // Balance the background's regions without fixing the precise position.
    const occupancy = Array(12).fill(0);
    for (const other of field.children) {
      const rect = other.getBoundingClientRect();
      boxes.push({ left: rect.left - root.left, right: rect.right - root.left, top: rect.top - root.top, bottom: rect.bottom - root.top });
      const x = Number.parseFloat(other.style.getPropertyValue("--eye-x"));
      const y = Number.parseFloat(other.style.getPropertyValue("--eye-y"));
      if (Number.isFinite(x) && Number.isFinite(y)) {
        const column = Math.min(3, Math.max(0, Math.floor(x / 25)));
        const row = Math.min(2, Math.max(0, Math.floor(y / (100 / 3))));
        occupancy[row * 4 + column]++;
      }
    }
    const least = Math.min(...occupancy);
    const choices = occupancy.map((value, index) => value === least ? index : -1).filter(index => index >= 0);
    const chosen = choices[Math.floor(Math.random() * choices.length)];
    const region = { column: chosen % 4, row: Math.floor(chosen / 4) };
    const eye = template.content.firstElementChild.cloneNode(true);
    const size = 48 + Math.random() * 52;
    const angle = randomAngle();
    const box = position(size, size * .47, angle, boxes, region);
    // Each eye holds independently; the brief exit has its own duration.
    const hold = scaled(900 + Math.random() * 3400, 600);
    const glitchDuration = scaled(220 + Math.random() * 160, 150);
    // Avoid two successive eyes using the same exit, while retaining randomness.
    let glitch = Math.floor(Math.random() * 4);
    if (glitch === lastGlitch) glitch = (glitch + 1 + Math.floor(Math.random() * 3)) % 4;
    lastGlitch = glitch;
    eye.dataset.glitch = ["shift", "slices", "echo", "tear"][glitch];
    eye.style.setProperty("--eye-x", `${box.x / app.clientWidth * 100}%`);
    eye.style.setProperty("--eye-y", `${box.y / app.clientHeight * 100}%`);
    eye.style.setProperty("--eye-size", `${size.toFixed(1)}px`);
    eye.style.setProperty("--eye-angle", `${angle.toFixed(1)}deg`);
    eye.style.setProperty("--eye-duration", `${hold}ms`);
    eye.style.setProperty("--glitch-duration", `${glitchDuration}ms`);
    field.append(eye);
    later(() => {
      eye.classList.add("glitching");
      later(() => {
        eye.remove();
        if (enabled) {
          const gap = field.childElementCount < 8 ? 0 : scaled(60 + Math.random() * 750, 40);
          later(showEye, gap);
        }
      }, glitchDuration);
    }, hold);
  }
  function showMessage() {
    if (!enabled) return;
    const question = questionsBeforePhrase > 0;
    if (question) {
      questionsBeforePhrase--;
      message.textContent = Math.random() < .5 ? "?" : "???";
    } else {
      questionsBeforePhrase = 2 + Math.floor(Math.random() * 3);
      let index = Math.floor(Math.random() * messages.length);
      if (index === previousMessage) index = (index + 1) % messages.length;
      previousMessage = index;
      message.textContent = `> ${messages[index]}`;
    }
    scene.classList.remove("visible");
    scene.dataset.kind = question ? "question" : "message";
    const angle = randomAngle();
    const box = position(question ? (message.textContent.length * 19) : 250, 34, angle, obstacles());
    scene.style.setProperty("--scene-x", `${box.x / app.clientWidth * 100}%`);
    scene.style.setProperty("--scene-y", `${box.y / app.clientHeight * 100}%`);
    scene.style.setProperty("--scene-angle", `${angle.toFixed(1)}deg`);
    const duration = scaled(question ? 1800 : 2700, 1200);
    scene.style.setProperty("--scene-duration", `${duration}ms`);
    scene.style.setProperty("--typing-duration", `${Math.round(duration * .42)}ms`);
    void scene.offsetWidth;
    scene.classList.add("visible");
    later(() => {
      scene.classList.remove("visible");
      if (enabled) later(showMessage, scaled(1200 + Math.random() * 1500, 500));
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
    if (enabled) {
      questionsBeforePhrase = 2;
      const count = 12 + Math.floor(Math.random() * 5);
      // Spread the initial arrivals irregularly as well as the later lifetimes.
      const arrivals = Array.from({ length: count }, () => 70 + Math.random() * 1050).sort((a, b) => a - b);
      let lastArrival = 0;
      for (const candidate of arrivals) {
        const arrival = Math.max(candidate, lastArrival + 65 + Math.random() * 75);
        later(showEye, arrival);
        lastArrival = arrival;
      }
      later(showMessage, 1200);
    }
  }
  window.addEventListener("umbra-appearance", refresh);
  document.addEventListener("visibilitychange", refresh);
  reducedMotion.addEventListener("change", refresh);
  refresh();
})();
