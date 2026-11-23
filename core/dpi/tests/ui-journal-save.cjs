// Проверка очереди записи и закрытия без Tauri/Windows: node core/dpi/tests/ui-journal-save.cjs
const fs = require('fs'), vm = require('vm'), assert = require('assert'), path = require('path');
class Element {
  constructor(fragment=false){ this.fragment=fragment; this.children=[]; this.listeners={}; this.value=''; this.textContent=''; this.hidden=false; this.style={}; this.scrollTop=0; this.open=false; }
  get scrollHeight(){return this.children.length*40;}
  addEventListener(k,cb){this.listeners[k]=cb;}
  append(...nodes){for(const n of nodes)this.children.push(...(n.fragment?n.children:[n]));}
  replaceChildren(...nodes){this.children=[];this.append(...nodes);}
  contains(n){return n===this||this.children.includes(n);} setAttribute(){} focus(){} select(){}
  getBoundingClientRect(){return {left:0,top:100,width:210,height:80};} showModal(){this.open=true;} close(){this.open=false;}
}
const ids={}; for(const id of ['journal-list','journal-search','journal-filter','journal-menu','journal-export-button','journal-action-status','journal-save-status','journal-export-dialog','journal-export-title','journal-report','journal-copy','journal-copy-status','journal-export-redacted','journal-export-full','journal-export-close']) ids[id]=new Element();
ids['journal-filter'].value='all';
const document={querySelector:s=>ids[s.slice(1)],createElement:()=>new Element(),createDocumentFragment:()=>new Element(true),addEventListener(){}};
let fail=false, cleanupFail=false, closed=0, confirms=0, allowDiscard=false, saved=[], calls=[], writing=false;
const handlers={};
const window={innerWidth:1000,innerHeight:700,addEventListener:(name,cb)=>{handlers[name]=cb;},confirm:()=>{confirms++;return allowDiscard;},__TAURI_INTERNALS__:{invoke:async(name,args)=>{
 calls.push([name,args]);
 if(name==='journal_ready')return 7;
 if(name==='journal_cleanup'){if(cleanupFail)throw Error('старый файл занят');return;}
 if(name==='journal_finish_close'){closed++;return;}
 if(name==='journal_write'){
   assert(!writing,'одновременные партии недопустимы'); writing=true;
   await new Promise(r=>setTimeout(r,8)); writing=false;
   if(fail)throw Error('нет доступа');
   saved.push(...args.records.map(s=>JSON.parse(s)));return;
 }
 throw Error('unexpected command');
}}};
let slowTimer=null;
const timer=(fn,ms)=>{if(ms>=5000){slowTimer=fn;return -1;}return setTimeout(fn,ms);};
const ctx={document,window,navigator:{},requestAnimationFrame:fn=>fn(),TextEncoder,setTimeout:timer,clearTimeout:id=>{if(id===-1)slowTimer=null;else clearTimeout(id)},Date,console};
vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../../../ui/components/logs.js'),'utf8'),ctx);
const delay=ms=>new Promise(r=>setTimeout(r,ms));
(async()=>{
 const j=window.umbraJournal;
 j.add('error','Ошибка 203.0.113.42');
 j.addFlowView({session_id:1,events:[{sequence:1,observed_ms:12345,established:true,pid:42,process:'discord.exe',protocol:'TCP',remote_ip:'203.0.113.42',remote_port:443}]});
 for(let i=0;i<130;i++)j.add('system',`событие-${i}`);
 fail=true; await delay(20);
 assert(!ids['journal-save-status'].hidden); assert(ids['journal-save-status'].textContent.includes('нет доступа'));
 await handlers['umbra-journal-close-request']();
 assert.equal(confirms,1); assert.equal(closed,0); assert.equal(saved.length,0);
 fail=false; cleanupFail=true;
 assert(slowTimer); const retry=slowTimer; slowTimer=null; retry(); await delay(50);
 assert.equal(saved.length,133); assert(ids['journal-save-status'].textContent.includes('прошлого сеанса'));
 // Отказ удаления не должен останавливать сохранение новых записей.
 j.add('system','после ошибки очистки'); await delay(30);
 assert.equal(saved.length,134); assert(ids['journal-save-status'].textContent.includes('прошлого сеанса'));
 cleanupFail=false; assert(slowTimer); const retry3=slowTimer; slowTimer=null; retry3(); await delay(20);
 assert(ids['journal-save-status'].hidden);
 await handlers['umbra-journal-close-request']();
 assert.equal(closed,1); assert.equal(saved.length,134); assert(saved.some(e=>e.событие.includes('discord.exe'))); assert(saved.some(e=>e.событие.includes('203.0.113.42')));
 assert.deepEqual(calls.filter(c=>c[0]==='journal_write').map(c=>c[1].batch),[1,1,1,2,3,4]);
 assert(ids['journal-save-status'].hidden); assert(!ids['journal-save-status'].textContent);
 console.log('Журнал: партии, ошибка, повтор и ожидание записи при закрытии — OK');
})().catch(e=>{console.error(e);process.exitCode=1;});
