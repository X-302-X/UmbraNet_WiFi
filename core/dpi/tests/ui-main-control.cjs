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
  let running = false, failQuery = false, successfulStop = false, stopStarted = false, stopFailsAfterClose = false, workerFault = false, autoFault = false, recovering = false, watchCallback = null;
  const invoke = async (name) => {
    calls.push(name);
    if (name === 'dpi_control_status') {
      if (workerFault && !stopStarted) return {phase:'failed', owned_closed:true, auto_fault:autoFault, message:'неожиданное завершение; общий WinDivert не остановлен', service_status:null};
      if (recovering && !stopStarted) return {phase:'recovering', owned_closed:false, message:'Рабочий поток завершился; закрываем канал', service_status:null};
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
  vm.runInNewContext(source, {document, window, setTimeout: (fn, ms) => { if (ms === 600) queueMicrotask(fn); if (ms === 1500) watchCallback = fn; return 1; }, clearTimeout() {}});
  return {ids, modes, calls, entries, setRunning(v) {running = v;}, fail(v) {failQuery = v;}, allowStop() {successfulStop = true;}, failAfterClose() {successfulStop = true; stopFailsAfterClose = true;}, setWorkerFault() {workerFault = true;}, setAutoFault() {workerFault = true; autoFault = true;}, setRecovering() {recovering = true;}, async tickWatch() {assert(watchCallback); const cb=watchCallback; watchCallback=null; await cb();}};
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

  const recovery = make(); recovery.setRunning(true); recovery.allowStop();
  await recovery.modes[2].click(); recovery.setRecovering(); await recovery.tickWatch();
  assert(recovery.entries.some(([type,text]) => type === 'error' && text.includes('закрываем канал')));
  assert.equal(recovery.ids['.action-start'].child.textContent, 'Стоп');
  await recovery.ids['.action-start'].click();
  assert(recovery.calls.includes('dpi_engine_stop'), 'Stop доступен при автоочистке');

  const delayed = make(); delayed.setRunning(true);
  await delayed.modes[2].click(); await delayed.ids['.action-start'].click();
  assert.equal(delayed.ids['.action-start'].disabled, true);
  delayed.setAutoFault(); await delayed.tickWatch();
  assert.equal(delayed.ids['.action-start'].disabled, false, 'после автоочистки Stop снова доступен');
  delayed.allowStop(); await delayed.ids['.action-start'].click();
  assert.equal(delayed.calls.filter(c => c === 'dpi_engine_stop').length, 2);

  const auto = make(); auto.setRunning(true); auto.allowStop();
  await auto.modes[2].click(); auto.setAutoFault(); await auto.tickWatch();
  assert(auto.entries.some(([type,text]) => type === 'error' && text.includes('Нажмите «Стоп»')));
  assert.equal(auto.ids['.action-start'].child.textContent, 'Стоп');
  assert.equal(auto.ids['.action-start'].disabled, false);
  auto.setRunning(false); await auto.ids['.action-start'].click();
  assert(auto.calls.includes('dpi_engine_stop'), 'аварийное закрытие не отменяет последующий Stop общего драйвера');
  assert(auto.entries.some(([type]) => type === 'paused'));

  const race = make(); race.setRunning(true); race.allowStop();
  await race.modes[2].click(); race.setAutoFault(); race.setRunning(false);
  await race.ids['.action-start'].click();
  assert(!race.calls.includes('dpi_engine_start'), 'при падении нельзя случайно запустить DPI');
  assert(!race.calls.includes('dpi_engine_stop'), 'сначала уточнить аварийное состояние');
  assert.equal(race.ids['.action-start'].child.textContent, 'Стоп');
  await race.ids['.action-start'].click();
  assert(race.calls.includes('dpi_engine_stop'));

  const fault = make(); fault.setRunning(true);
  await fault.modes[2].click();
  fault.setWorkerFault(); await fault.tickWatch();
  assert(fault.ids['#action-notice'].textContent.includes('неожиданное завершение'));
  assert(fault.entries.some(([type,text]) => type === 'error' && text.includes('общий WinDivert не остановлен')));
  assert(fault.entries.some(([type]) => type === 'paused'));
  assert.equal(fault.ids['.action-start'].disabled, true);
  console.log('Основная кнопка: старт, ожидание Stop, автоошибка и журнал — OK');
})().catch(error => { console.error(error); process.exitCode = 1; });
