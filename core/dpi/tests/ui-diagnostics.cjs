const fs=require('fs'),vm=require('vm'),assert=require('assert'),path=require('path');
class Element {
  constructor(){this.disabled=false;this.hidden=false;this.textContent='';this.value='';this.listeners={};this.classList={toggle(){}};this.open=false;}
  addEventListener(name,cb){this.listeners[name]=cb;} fire(name){return this.listeners[name]?.();}
  showModal(){this.open=true;} close(){this.open=false;}
}
const ids={}; for(const id of ['diagnostic-loopback-start','diagnostic-start','diagnostic-tcp-start','diagnostic-tcp-open','diagnostic-tcp-dialog','diagnostic-tcp-close','diagnostic-tcp-report','diagnostic-result-title','diagnostic-stop','diagnostic-state','diagnostic-message'])ids[id]=new Element();
const matrix={flag_set_valid:1,flag_set_invalid:2,flag_unset_valid:3,flag_unset_invalid:4};
const direction={total:10,ipv4:7,ipv6:3,over_1500_bytes:2,unsupported:0,tcp_checksum:matrix,ipv4_checksum:matrix,ipv4_mismatch:{zero_field:3,nonzero_field:1,helper_same:1,helper_different:2,helper_unavailable:1}};
const base={kind:'flow',phase:'idle',busy:false,session_id:0,events:[],duration_seconds:30};
const tcp={kind:'tcp_metadata',phase:'running',busy:true,session_id:1,events:[],duration_seconds:30,tcp_stats:{outbound:direction,inbound:direction}};
let confirm=false,calls=[],entries=[],active=tcp,probe={phase:'idle',blocked:false};
const flow={...base,phase:'running',busy:true,session_id:2,established:7,identified:4,unresolved:3,events_dropped:2};
const invoke=async name=>{calls.push(name);if(name==='dpi_diagnostic_status')return base;if(name==='dpi_loopback_status')return probe;if(name==='dpi_loopback_start'){probe={phase:'running',blocked:false};return probe;}if(name==='dpi_tcp_diagnostic_start'){active=tcp;return tcp;}if(name==='dpi_diagnostic_start'){active=flow;return flow;}if(name==='dpi_diagnostic_stop')return {...active,phase:'finished',busy:false};throw Error(name);};
const window={__TAURI_INTERNALS__:{invoke},confirm:()=>confirm,dispatchEvent(){},umbraJournal:{add:(...v)=>entries.push(v),addFlowView(){}}};
const context={window,document:{querySelector:s=>ids[s.slice(1)]},Event:class{},setTimeout:()=>0,clearTimeout(){},console};
vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../../../ui/components/diagnostics.js'),'utf8'),context);
const tick=()=>new Promise(r=>setImmediate(r));
(async()=>{
 await tick(); assert.equal(ids['diagnostic-tcp-start'].disabled,false);
 ids['diagnostic-start'].fire('click'); ids['diagnostic-tcp-start'].fire('click'); await tick(); assert(!calls.includes('dpi_tcp_diagnostic_start')); assert(!calls.includes('dpi_diagnostic_start'));
 confirm=true; ids['diagnostic-tcp-start'].fire('click'); await tick(); assert(calls.includes('dpi_tcp_diagnostic_start')); assert(ids['diagnostic-start'].disabled); assert(ids['diagnostic-tcp-start'].disabled); assert(!ids['diagnostic-stop'].disabled); assert(ids['diagnostic-tcp-open'].hidden);
 ids['diagnostic-stop'].fire('click'); await tick(); assert(calls.includes('dpi_diagnostic_stop')); assert.equal(ids['diagnostic-tcp-start'].disabled,false); assert(!ids['diagnostic-tcp-open'].hidden);
 let report=ids['diagnostic-tcp-report'].value; assert(report.includes('все приложения')); assert(report.includes('флаг=1/сумма неверна 2')); assert(report.includes('Поле checksum нулевое: 3; ненулевое: 1')); assert(report.includes('совпала с исходной 1; отличается 2; сравнить не удалось 1')); assert(report.includes('до 128 пакетов')); assert(report.includes('не доказывают')); assert(!report.includes('192.0.2.1')); assert(report.includes('Завершена'));
 ids['diagnostic-tcp-open'].fire('click'); assert(ids['diagnostic-tcp-dialog'].open); ids['diagnostic-tcp-close'].fire('click'); assert(!ids['diagnostic-tcp-dialog'].open);
 assert(entries.some(e=>e[1].includes('TCP-проверку'))); assert(entries.some(e=>e[1].includes('исходящих пакетов 10')));
 ids['diagnostic-start'].fire('click'); await tick(); assert(calls.includes('dpi_diagnostic_start')); ids['diagnostic-stop'].fire('click'); await tick();
 assert(!ids['diagnostic-tcp-open'].hidden); assert(ids['diagnostic-result-title'].textContent.includes('соединений')); assert(ids['diagnostic-tcp-report'].value.includes('Новых соединений: 7')); assert(ids['diagnostic-tcp-report'].value.includes('Удалено событий из очереди: 2'));
 assert(entries.some(e=>e[1].includes('новых 7')));
 ids['diagnostic-loopback-start'].fire('click'); await tick(); assert(calls.includes('dpi_loopback_start'));
 assert(ids['diagnostic-start'].disabled); assert(ids['diagnostic-loopback-start'].disabled); assert(window.umbraDiagnosticBusy());
 assert(entries.some(e=>e[1].includes('локальную проверку')));
 console.log('Diagnostic consent, status, FLOW/TCP reports and shared stop passed (mock DOM)');
})().catch(e=>{console.error(e);process.exit(1)});
