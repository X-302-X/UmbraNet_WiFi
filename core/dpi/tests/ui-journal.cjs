// node core/dpi/tests/ui-journal.cjs — без Windows и драйвера
const fs = require('fs'), vm = require('vm'), assert = require('assert'), path = require('path');
class Element {
  constructor(fragment = false) { this.fragment=fragment; this.children=[]; this.listeners={}; this.value=''; this.textContent=''; this.hidden=false; this.className=''; this.style={}; this.scrollTop=0; this.open=false; this.attributes={}; }
  get scrollHeight() { return this.children.length * 40; }
  addEventListener(name, cb) { this.listeners[name]=cb; }
  append(...nodes) { for(const node of nodes) this.children.push(...(node.fragment ? node.children : [node])); }
  replaceChildren(...nodes) { this.children=[]; this.append(...nodes); }
  focus() { this.focused=true; } select() { this.selected=true; }
  showModal() { this.open=true; } close() { this.open=false; }
  contains(node) { return node===this || this.children.includes(node); }
  setAttribute(name,value) { this.attributes[name]=value; }
  getBoundingClientRect() { return {left:10,top:120,width:210,height:90}; }
  async fire(name,event={}) { return await this.listeners[name]?.(event); }
}
const ids={}; for(const id of ['journal-list','journal-search','journal-filter','journal-menu','journal-export-button','journal-action-status','journal-export-dialog','journal-export-title','journal-report','journal-copy','journal-copy-status','journal-export-redacted','journal-export-full','journal-export-close']) ids[id]=new Element();
ids['journal-filter'].value='all'; ids['journal-menu'].hidden=true;
const document={querySelector:s=>ids[s.slice(1)],createElement:()=>new Element(),createDocumentFragment:()=>new Element(true),addEventListener(){}};
let copied=''; const window={innerWidth:1024,innerHeight:768};
const ctx={document,window,navigator:{clipboard:{writeText:async s=>{copied=s;}}},requestAnimationFrame:fn=>fn(),setTimeout:()=>1,clearTimeout:()=>{},Date,console};
vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../../../ui/components/logs.js'),'utf8'),ctx);
const flatten=e=>e.textContent+e.children.map(flatten).join(''); const all=e=>[e,...e.children.flatMap(all)];
(async()=>{
 const j=window.umbraJournal;
 j.addFlowView({session_id:1,events:[{sequence:1,observed_ms:12345,established:true,pid:42,process:'discord.exe',selected_process:true,protocol:'UDP',local_ip:'192.0.2.1',local_port:123,remote_ip:'2001:db8::1',remote_port:443}]});
 j.add('error','Ошибка для 192.0.2.99 и 2001:db8::9');
 let rows=ids['journal-list'].children;
 assert(rows[0].className.includes('is-error')); assert(flatten(rows[0]).includes('Ошибка'));
 let marked=all(rows[0]).filter(e=>e.className==='journal-sensitive').map(flatten);
 assert(marked.includes('192.0.2.99')); assert(marked.includes('2001:db8::9'));
 assert(flatten(rows[1]).includes('Новое соединение'));
 marked=all(rows[1]).filter(e=>e.className==='journal-sensitive').map(flatten);
 assert(marked.some(s=>s.includes('discord.exe'))); assert(marked.some(s=>s.includes('PID 42'))); assert(marked.some(s=>s.includes('192.0.2.1')&&s.includes('2001:db8::1')));
 j.addFlowView({session_id:1,events:[{sequence:2,observed_ms:12346,established:true,pid:43,process:null,protocol:'TCP',local_ip:null,remote_ip:'203.0.113.84',remote_port:443}]});
 assert(all(ids['journal-list'].children[0]).some(e=>e.className==='journal-sensitive'&&flatten(e).includes('203.0.113.84')));
 j.add('system','Файл C:\\Users\\Alice\\profile.json, email alice@example.com, адрес 203.0.113.42');
 assert(all(ids['journal-list'].children[0]).some(e=>e.className==='journal-sensitive'&&flatten(e).includes('C:\\Users\\Alice')));
 ids['journal-search'].value='discord.exe'; await ids['journal-search'].fire('input'); assert.equal(ids['journal-list'].children.length,1); assert(flatten(ids['journal-list']).includes('discord.exe'));
 ids['journal-search'].value=''; ids['journal-filter'].value='error'; await ids['journal-filter'].fire('change'); assert.equal(ids['journal-list'].children.length,1); assert(ids['journal-list'].children[0].className.includes('is-error'));
 ids['journal-search'].value='нет такого'; await ids['journal-search'].fire('input'); assert(flatten(ids['journal-list']).includes('Ничего не найдено'));
 ids['journal-search'].value=''; ids['journal-filter'].value='all'; await ids['journal-filter'].fire('change');
 await ids['journal-export-button'].fire('click'); assert(!ids['journal-menu'].hidden); assert.equal(ids['journal-export-button'].attributes['aria-expanded'],'true');
 await ids['journal-export-redacted'].fire('click'); let report=ids['journal-report'].value; assert.equal(copied,report); assert(ids['journal-menu'].hidden); assert.equal(ids['journal-action-status'].textContent,'Скопировано'); assert(!ids['journal-export-dialog'].open);
 for(const secret of ['discord.exe','PID 42','192.0.2.1','2001:db8::1','192.0.2.99','2001:db8::9','Alice','alice@example.com','203.0.113.42','203.0.113.84']) assert(!report.includes(secret),secret);
 assert(report.includes('анонимность не гарантируется'));
 let prevented=false; await ids['journal-list'].fire('contextmenu',{clientX:30,clientY:40,preventDefault(){prevented=true;}}); assert(prevented); assert(!ids['journal-menu'].hidden);
 ctx.navigator.clipboard=null; await ids['journal-export-full'].fire('click'); assert(ids['journal-export-dialog'].open); assert(ids['journal-report'].selected); assert(ids['journal-copy-status'].textContent.includes('Ctrl+C')); report=ids['journal-report'].value;
 for(const secret of ['192.0.2.1','2001:db8::1','192.0.2.99','Alice','alice@example.com']) assert(report.includes(secret),secret);
 await ids['journal-copy'].fire('click'); assert(ids['journal-copy-status'].textContent.includes('Ctrl+C'));
 await ids['journal-export-close'].fire('click'); assert(!ids['journal-export-dialog'].open);
 let keyPrevented=false; await ids['journal-list'].fire('keydown',{key:'F10',shiftKey:true,preventDefault(){keyPrevented=true;}}); assert(keyPrevented); assert(ids['journal-export-redacted'].focused);
 j.addRequired('system','Нажат Стоп DPI'); j.addRequired('error','Сбой остановки DPI'); j.stopAfterDpi(); j.add('system','после подтверждённого стоп');
 await ids['journal-export-close'].fire('click'); await ids['journal-export-full'].fire('click'); report=ids['journal-report'].value; assert(report.includes('Нажат Стоп DPI')); assert(report.includes('Сбой остановки DPI')); assert(report.includes('Запись журнала остановлена')); assert(!report.includes('после подтверждённого стоп'));
 j.startForDpi(); for(let i=0;i<550;i++) j.add('system',`message-${i}`); assert(ids['journal-list'].children.length>550); assert(flatten(ids['journal-list'].children[0]).includes('message-549')); await ids['journal-export-close'].fire('click'); await ids['journal-export-full'].fire('click'); report=ids['journal-report'].value; assert(report.includes('message-0')); assert(report.includes('message-549'));
 ids['journal-list'].scrollTop=100; const old=ids['journal-list'].scrollHeight; j.add('system','new'); assert.equal(ids['journal-list'].scrollTop,100+ids['journal-list'].scrollHeight-old);
 console.log('Journal search, colours, context-copy, stop retention and scrolling passed (mock DOM)');
})().catch(e=>{console.error(e);process.exit(1)});
