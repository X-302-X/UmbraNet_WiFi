// UI-модель: явное согласие, независимый процесс и блокировка на ошибке.
const fs=require('fs'),vm=require('vm'),assert=require('assert'),path=require('path');
class El { constructor(){this.disabled=false;this.hidden=false;this.textContent='';this.value='';this.listeners={};this.classList={toggle(){}};this.open=false;} addEventListener(n,f){this.listeners[n]=f;} fire(n){return this.listeners[n]?.();} showModal(){this.open=true} close(){this.open=false} }
const ids={}; for(const id of ['diagnostic-loopback-start','diagnostic-start','diagnostic-tcp-start','diagnostic-tcp-open','diagnostic-tcp-dialog','diagnostic-tcp-close','diagnostic-tcp-report','diagnostic-result-title','diagnostic-stop','diagnostic-state','diagnostic-message'])ids[id]=new El();
let probe={phase:'idle',blocked:false}, confirm=false, calls=[], logs=[], timerId=0, timers=new Map();
const invoke=async n=>{calls.push(n); if(n==='dpi_diagnostic_status')return {phase:'idle',busy:false,session_id:0,events:[]}; if(n==='dpi_loopback_status')return probe; if(n==='dpi_loopback_start'){probe={phase:'running',blocked:false};return probe;} throw Error(n);};
const window={__TAURI_INTERNALS__:{invoke},confirm:()=>confirm,dispatchEvent(){},umbraJournal:{add:(...x)=>logs.push(x),addFlowView(){}}};
const ctx={window,document:{querySelector:s=>ids[s.slice(1)]},Event:class{},setTimeout:f=>{timers.set(++timerId,f);return timerId},clearTimeout:id=>timers.delete(id),console};
vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../../../ui/components/diagnostics.js'),'utf8'),ctx);
const tick=()=>new Promise(r=>setImmediate(r));
async function runTimers(){const list=[...timers.values()];timers.clear(); for(const f of list)f(); await tick();}
(async()=>{
 await tick(); assert(!ids['diagnostic-loopback-start'].disabled);
 await ids['diagnostic-loopback-start'].fire('click'); assert(!calls.includes('dpi_loopback_start'));
 confirm=true; await ids['diagnostic-loopback-start'].fire('click');
 assert(calls.includes('dpi_loopback_start')); assert(ids['diagnostic-start'].disabled); assert(ids['diagnostic-loopback-start'].disabled); assert(window.umbraDiagnosticBusy());
 probe={phase:'finished',blocked:false,message:'Обмен и возврат подтверждены'}; await runTimers();
 assert(!window.umbraDiagnosticBusy()); assert(!ids['diagnostic-loopback-start'].disabled); assert(logs.some(x=>x[1].includes('Обмен и возврат')));
 await ids['diagnostic-loopback-start'].fire('click'); probe={phase:'error',blocked:true,message:'Закрытие не подтверждено'}; await runTimers();
 assert(window.umbraDiagnosticBusy()); assert(ids['diagnostic-start'].disabled); assert(ids['diagnostic-loopback-start'].disabled); assert(logs.some(x=>x[0]==='error' && x[1].includes('не подтверждено')));
 console.log('Loopback UI consent, completion and fail-closed status: OK');
})().catch(e=>{console.error(e);process.exit(1)});
