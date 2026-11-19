// Логика журнала без WebView/Windows: node core/dpi/tests/ui-journal.cjs
const fs = require('fs'), vm = require('vm'), assert = require('assert'), path = require('path');
class Element {
  constructor(fragment = false) {
    this.fragment = fragment; this.children = []; this.listeners = {}; this.value = ''; this.textContent = '';
    this.disabled = false; this.hidden = false; this.className = ''; this.title = '';
    this.classList = {toggle() {}};
  }
  addEventListener(name, callback) { this.listeners[name] = callback; }
  append(...nodes) { for (const node of nodes) this.children.push(...(node.fragment ? node.children : [node])); }
  replaceChildren(...nodes) { this.children = []; this.append(...nodes); }
  focus() { this.focused = true; } select() { this.selected = true; }
  async fire(name) { return await this.listeners[name]?.(); }
}
const ids = {};
for (const id of ['journal-list','journal-search','journal-filter','journal-count','journal-state','journal-pause','journal-report','journal-export-mode','journal-copy','journal-copy-status','journal-clear','journal-prepare','journal-more','journal-total','journal-flows','journal-system','journal-errors']) ids[id] = new Element();
ids['journal-filter'].value = 'all'; ids['journal-export-mode'].value = 'redacted';
const document = {querySelector: s => ids[s.slice(1)], createElement: () => new Element(), createDocumentFragment: () => new Element(true)};
let copied = '';
const window = {};
const ctx = {document, window, navigator:{clipboard:{writeText: async s => {copied = s;}}}, requestAnimationFrame: fn => fn(), Date, console};
vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../../../ui/components/logs.js'),'utf8'), ctx);
const flatten = element => element.textContent + element.children.map(flatten).join('');
const all = element => [element, ...element.children.flatMap(all)];
(async () => {
  const j = window.umbraJournal;
  j.addFlowView({session_id:1, events:[{sequence:1, observed_ms:12345, established:true, pid:42, process:'discord.exe', selected_process:true, protocol:'UDP', local_ip:'192.0.2.1',local_port:123,remote_ip:'2001:db8::1',remote_port:443}]});
  j.add('error','Ошибка для 192.0.2.99 и 2001:db8::9');
  let rows = ids['journal-list'].children;
  assert(rows[0].className.includes('is-error')); assert(flatten(rows[0]).includes('ОШИБКА'));
  let marked = all(rows[0]).filter(e => e.className === 'journal-sensitive').map(flatten);
  assert(marked.includes('192.0.2.99')); assert(marked.includes('2001:db8::9'));
  assert(flatten(rows[1]).includes('Новое соединение'));
  marked = all(rows[1]).filter(e => e.className === 'journal-sensitive').map(flatten);
  assert(marked.some(s => s.includes('discord.exe'))); assert(marked.some(s => s.includes('PID 42')));
  assert(marked.some(s => s.includes('192.0.2.1') && s.includes('2001:db8::1')));
  assert.equal(ids['journal-total'].textContent,'3'); assert.equal(ids['journal-flows'].textContent,'1'); assert.equal(ids['journal-errors'].textContent,'1');
  j.addFlowView({session_id:1, events:[{sequence:2, observed_ms:12346, established:true, pid:43, process:null, protocol:'TCP', local_ip:null, local_port:null, remote_ip:'203.0.113.84',remote_port:443}]});
  assert(all(ids['journal-list'].children[0]).some(e => e.className === 'journal-sensitive' && flatten(e).includes('203.0.113.84')));
  j.add('system','Файл C:\\Users\\Alice\\profile.json, email alice@example.com, адрес 203.0.113.42');
  assert(all(ids['journal-list'].children[0]).some(e => e.className === 'journal-sensitive' && flatten(e).includes('C:\\Users\\Alice')));
  await ids['journal-prepare'].fire('click');
  let report = ids['journal-report'].value;
  assert(report.includes('discord.exe'));
  for (const secret of ['192.0.2.1','2001:db8::1','192.0.2.99','2001:db8::9','Alice','alice@example.com','203.0.113.42','203.0.113.84']) assert(!report.includes(secret), secret);
  await ids['journal-copy'].fire('click'); assert.equal(copied,report);
  ctx.navigator.clipboard = null; await ids['journal-copy'].fire('click');
  assert(ids['journal-report'].selected); assert(ids['journal-copy-status'].textContent.includes('Ctrl+C'));
  ids['journal-export-mode'].value='full'; await ids['journal-export-mode'].fire('change'); assert.equal(ids['journal-report'].value,'');
  await ids['journal-prepare'].fire('click'); report=ids['journal-report'].value;
  for (const secret of ['192.0.2.1','2001:db8::1','192.0.2.99','Alice','alice@example.com']) assert(report.includes(secret), secret);
  ids['journal-filter'].value='error'; await ids['journal-filter'].fire('change'); assert.equal(ids['journal-list'].children.length,1); assert(ids['journal-list'].children[0].className.includes('is-error'));
  ids['journal-search'].value='нет такого'; await ids['journal-search'].fire('input'); assert(flatten(ids['journal-list']).includes('Ничего не найдено'));
  ids['journal-filter'].value='all'; ids['journal-search'].value=''; await ids['journal-filter'].fire('change');
  await ids['journal-pause'].fire('click'); j.add('system','not recorded');
  j.addRequired('system','Нажат Стоп DPI'); j.addRequired('error','Сбой остановки DPI'); j.stopAfterDpi(); j.add('system','после подтверждённого стоп');
  await ids['journal-prepare'].fire('click'); report=ids['journal-report'].value;
  assert(!report.includes('not recorded')); assert(report.includes('Нажат Стоп DPI')); assert(report.includes('Сбой остановки DPI')); assert(!report.includes('после подтверждённого стоп')); assert(report.includes('Запись журнала остановлена'));
  assert(ids['journal-state'].textContent.includes('паузе'));
  await ids['journal-clear'].fire('click'); assert.equal(ids['journal-report'].value,''); assert.equal(ids['journal-total'].textContent,'0'); assert(ids['journal-copy'].disabled);
  await ids['journal-pause'].fire('click');
  for(let i=0;i<550;i++) j.add('system',`message-${i}`);
  assert.equal(ids['journal-total'].textContent,'551'); assert.equal(ids['journal-list'].children.length,200); assert(!ids['journal-more'].hidden);
  assert(flatten(ids['journal-list'].children[0]).includes('message-549'));
  await ids['journal-more'].fire('click'); assert.equal(ids['journal-list'].children.length,400);
  await ids['journal-prepare'].fire('click'); report=ids['journal-report'].value; assert(report.includes('message-0')); assert(report.includes('message-549'));
  console.log('Journal layout, colours, search, two exports, pause/stop and retention passed (mock DOM)');
})().catch(e => {console.error(e);process.exit(1)});
