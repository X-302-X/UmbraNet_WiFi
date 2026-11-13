"use strict";
(() => {
  const invoke = window.__TAURI_INTERNALS__?.invoke;
  const stages = ["welcome", "settings", "installing", "complete"];
  const labels = ["Начало установки", "Параметры установки", "Ход установки", "Завершение"];
  const notes = ["Несколько простых шагов — и всё готово.", "Для переустановки сначала закройте UmbraNet.", "Дождитесь завершения установки.", "Можно запустить приложение или открыть его папку."];
  let index = 0, ready = false, busy = false;
  const next = document.querySelector("#next"), back = document.querySelector("#back"), path = document.querySelector("#install-path"), error = document.querySelector("#general-error"), openFolder = document.querySelector("#open-folder");
  const showError = text => { error.textContent = text || ""; error.hidden = !text; };
  const render = () => {
    document.querySelectorAll("[data-stage]").forEach(el => { el.hidden = el.dataset.stage !== stages[index]; });
    document.querySelectorAll("[data-step]").forEach(el => { const n = Number(el.dataset.step); el.classList.toggle("active", n === Math.min(index, 2) && index !== 3); el.classList.toggle("done", n < Math.min(index, 2) || index === 3); });
    document.querySelector("#section-label").textContent = labels[index];
    document.querySelector("#bottom-note").textContent = notes[index];
    document.querySelector("#status").textContent = index === 2 ? "Установка выполняется" : index === 3 ? "Установка завершена" : "Установщик UmbraNet";
    back.hidden = index !== 1; back.disabled = busy;
    openFolder.hidden = index !== 3; openFolder.disabled = busy;
    document.querySelector("#close").disabled = busy;
    next.disabled = !ready || busy;
    next.innerHTML = index === 0 ? 'Продолжить <span class="arrow">→</span>' : index === 1 ? 'Установить <span class="arrow">→</span>' : index === 2 ? 'Подождите…' : 'Запустить UmbraNet <span class="arrow">→</span>';
  };
  async function initialize() {
    if (typeof invoke !== "function") { showError("Это окно работает только в установщике Windows."); return; }
    try { path.value = await invoke("setup_suggested_path"); ready = true; }
    catch (e) { showError(String(e)); }
    render();
  }
  next.addEventListener("click", async () => {
    if(!ready || busy) return;
    showError("");
    if(index === 0) { index = 1; render(); return; }
    if(index === 1) {
      if(!path.value.trim()) { document.querySelector("#path-error").hidden = false; path.focus(); return; }
      document.querySelector("#path-error").hidden = true;
      busy = true; index = 2; render();
      try {
        const installed = await invoke("setup_install", { path: path.value, shortcuts: document.querySelector("#shortcut").checked });
        path.value = installed;
        document.querySelector("#summary-path").textContent = installed;
        index = 3;
      } catch (e) { index = 1; showError(String(e)); }
      finally { busy = false; render(); }
      return;
    }
    if(index === 3) {
      try { await invoke("setup_open", { application: true }); await invoke("setup_close"); }
      catch(e) { showError(String(e)); }
    }
  });
  back.addEventListener("click", () => { if(!busy) { showError(""); index = 0; render(); } });
  document.querySelector("#browse").addEventListener("click", async () => {
    if(busy) return;
    try { const selected = await invoke("setup_choose_folder"); if(selected) { path.value = selected; document.querySelector("#path-error").hidden = true; } }
    catch(e) { showError(String(e)); }
  });
  openFolder.addEventListener("click", async () => { try { await invoke("setup_open", { application: false }); } catch(e) { showError(String(e)); } });
  document.querySelector("#minimize").addEventListener("click", async () => { try { await invoke("setup_minimize"); } catch(e) { showError(String(e)); } });
  document.querySelector("#close").addEventListener("click", async () => { if(!busy) { try { await invoke("setup_close"); } catch(e) { showError(String(e)); } } });
  initialize();
})();
