// Список стратегии: старый профиль явно помечен как не подключённый.
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('assert');
class Element {
  constructor() { this.children = []; this.dataset = {}; this.listeners = {}; this.classList = {toggle(){}}; }
  append(...children) { this.children.push(...children); }
  replaceChildren() { this.children = []; }
  setAttribute(name, value) { this[name] = value; }
  addEventListener(event, fn) { this.listeners[event] = fn; }
}
const selectors = ['#strategy-list','#strategy-count','#strategy-message','#engine-state','#auto-list','#auto-count','#auto-clear'];
const elements = Object.fromEntries(selectors.map(s => [s, new Element()]));
const calls = [];
const document = {querySelector: s => elements[s], createElement: () => new Element()};
const view = {strategies:[{id:'uz1',name:'Uz1',file:'uz1.json',implementation_pending:true}, {id:'pass-through',name:'Pass',file:'pass-through.json',implementation_pending:false}], selected:'pass-through', running:false, auto_domains:[]};
const window = {__TAURI_INTERNALS__:{invoke: async (name, args) => {calls.push([name,args]); if(name==='dpi_strategy_select') view.selected=args.id; return JSON.stringify(view);}}};
vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../../../ui/components/dpi-strategies.js'),'utf8'), {document, window, setInterval, clearInterval});
setImmediate(async () => {
  const rows = elements['#strategy-list'].children;
  assert.equal(rows.length, 2);
  assert.equal(rows[0].children[0].textContent, 'Uz1');
  assert.equal(rows[0].children[2].textContent, 'подключение не завершено');
  assert.equal(rows[1].children.length, 2);
  await rows[0].listeners.click();
  await new Promise(resolve => setImmediate(resolve));
  assert(calls.some(([name,args]) => name === 'dpi_strategy_select' && args.id === 'uz1'));
  assert.equal(elements['#strategy-count'].textContent, 'Выбрано: uz1');
  console.log('UI strategies: OK');
});
