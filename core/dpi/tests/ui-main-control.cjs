// Проверка главной кнопки без Windows/драйвера: node core/dpi/tests/ui-main-control.cjs
const fs = require('fs');
const vm = require('vm');
const assert = require('assert');
const path = require('path');
const source = fs.readFileSync(path.join(__dirname, '../../../ui/components/pages.js'), 'utf8');
class Element {
  constructor(dataset = {}) {
    this.dataset = dataset; this.listeners = {}; this.disabled = false; this.hidden = false;
    this.textContent = ''; this.firstChild = {textContent: ''}; this.child = new ElementText();
    this.classList = {toggle() {}};
  }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  querySelector(selector) { if (selector === 'span') return this.child; return null; }
  setAttribute() {}
  async click() { if (!this.disabled && this.listeners.click) await this.listeners.click(); }
}
class ElementText { constructor() { this.textContent = ''; } }
function make() {
  const ids = {};
  for (const name of ['#catalog-search','#catalog-empty','#action-notice','.action-start','.action-restart','#combo-tabs','#route-vpn','#route-dpi']) ids[name] = new Element();
  const modes = ['vpn','combo','dpi'].map(mode => new Element({mode}));
  const calls = [], entries = [];
  let running = false, failQuery = false, successfulStop = false, stopStarted = false, stopFailsAfterClose = false;
  const invoke = async (name) => {
    calls.push(name);
    if (name === 'dpi_control_status') {
      if (stopStarted) return stopFailsAfterClose
        ? {phase: 'failed', owned_closed: true, message: 'ошибка службы', service_status: null}
        : {phase: 'complete', owned_closed: true, message: null, service_status: 'stopped'};
      return {phase: 'idle', owned_closed: false, message: null, service_status: null};
    }
    if (name === 'dpi_strategy_list') {
      if (failQuery) throw new Error('ошибка состояния');
      return JSON.stringify({running});
    }
    if (name === 'dpi_engine_start') throw new Error('активный DPI временно отключён');
    if (name === 'dpi_engine_stop') {
      if (!successfulStop) throw new Error('ошибка остановки');
      stopStarted = true;
      return {phase: 'stopping', owned_closed: false, message: null, service_status: null};
    }
    throw new Error('неожиданный вызов');
  };
  const document = {
    querySelector: selector => ids[selector],
    querySelectorAll: selector => selector === '[data-mode]' ? modes : [],
    getElementById: () => new Element(),
  };
  const window = { __TAURI_INTERNALS__: {invoke}, umbraJournal: {add: (...x) => entries.push(x), addRequired: (...x) => entries.push(x), stopAfterDpi: () => entries.push(["paused"])} };
  vm.runInNewContext(source, {document, window, setTimeout: (fn, ms) => { if (ms === 600) queueMicrotask(fn); return 1; }, clearTimeout() {}});
  return {ids, modes, calls, entries, setRunning(v) {running = v;}, fail(v) {failQuery = v;}, allowStop() {successfulStop = true;}, failAfterClose() {successfulStop = true; stopFailsAfterClose = true;}};
}
(async () => {
  const t = make();
  await t.ids['.action-start'].click();
  assert.equal(t.calls.length, 0, 'VPN не отправляет команду DPI');
  await t.modes[2].click();
  assert.deepEqual(t.calls, ['dpi_control_status','dpi_strategy_list']);
  assert.equal(t.ids['.action-start'].child.textContent, 'Старт');
  await t.ids['.action-start'].click();
  assert.deepEqual(t.calls, ['dpi_control_status','dpi_strategy_list','dpi_strategy_list','dpi_engine_start','dpi_strategy_list']);
  assert(t.ids['#action-notice'].textContent.includes('временно отключён'));
  assert.equal(t.ids['.action-start'].dataset.state, 'start');
  assert(t.entries.some(([k]) => k === 'error'));

  // Состояние изменилось между отрисовкой и нажатием: команда не должна
  // превращаться из видимого «Старт» в неожиданную остановку.
  t.setRunning(true);
  await t.ids['.action-start'].click();
  assert.equal(t.calls.filter(c => c === 'dpi_engine_stop').length, 0);
  assert.equal(t.ids['.action-start'].child.textContent, 'Стоп');
  assert.equal(t.modes[0].disabled, true);
  await t.ids['.action-start'].click();
  assert.equal(t.calls.filter(c => c === 'dpi_engine_stop').length, 1);
  assert(t.ids['#action-notice'].textContent.includes('ошибка остановки'));
  assert.equal(t.ids['.action-start'].disabled, true, 'неподтверждённая остановка блокирует команды');
  assert.equal(t.modes[0].disabled, true);

  const u = make();
  u.fail(true);
  await u.modes[2].click();
  assert.equal(u.ids['.action-start'].child.textContent, 'Проверить состояние');
  await u.ids['.action-start'].click();
  assert(!u.calls.includes('dpi_engine_start'), 'ошибка статуса не запускает DPI');
  u.fail(false);
  await u.ids['.action-start'].click();
  assert(!u.calls.includes('dpi_engine_start'), 'проверка не является нажатием Старт');
  assert.equal(u.ids['.action-start'].child.textContent, 'Старт');
  const failedCheck = make(); failedCheck.setRunning(true);
  await failedCheck.modes[2].click();
  failedCheck.fail(true);
  await failedCheck.ids['.action-start'].click();
  assert(!failedCheck.calls.includes('dpi_engine_stop'));
  assert(failedCheck.entries.some(([type, text]) => type === 'system' && text.includes('нажал «Стоп»')));
  assert(failedCheck.entries.some(([type, text]) => type === 'error' && text.includes('ошибка состояния')));

  const ok = make(); ok.setRunning(true); ok.allowStop();
  await ok.modes[2].click();
  assert.equal(ok.ids['.action-start'].child.textContent, 'Стоп');
  await ok.ids['.action-start'].click();
  assert.equal(ok.ids['.action-start'].child.textContent, 'Старт');
  assert(ok.entries.some(([type]) => type === 'paused'));
  assert(ok.ids['#action-notice'].textContent.includes('не доказывает выгрузку'));

  const err = make(); err.setRunning(true); err.failAfterClose();
  await err.modes[2].click();
  await err.ids['.action-start'].click();
  assert(err.entries.some(([type,text]) => type === 'error' && text.includes('ошибка службы')));
  assert(err.entries.some(([type]) => type === 'paused'));
  assert.equal(err.ids['.action-start'].disabled, true);

  console.log('Основная кнопка: старт, ожидание Stop, ошибки и журнал — OK');
})().catch(error => { console.error(error); process.exitCode = 1; });
