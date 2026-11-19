const fs = require('fs'), vm = require('vm'), assert = require('assert'), path = require('path');
class Element {
  constructor() { this.disabled = false; this.hidden = false; this.textContent = ''; this.value = ''; this.listeners = {}; this.classList = {toggle(){}}; }
  addEventListener(name, cb) { this.listeners[name] = cb; }
  fire(name) { return this.listeners[name]?.(); }
}
const ids = {};
for (const id of ['diagnostic-start','diagnostic-tcp-start','diagnostic-flow-stats','diagnostic-tcp-results','diagnostic-tcp-report','diagnostic-stop','diagnostic-state','diagnostic-message','diagnostic-established','diagnostic-identified','diagnostic-selected','diagnostic-unresolved']) ids[id] = new Element();
const matrix = {flag_set_valid:1,flag_set_invalid:2,flag_unset_valid:3,flag_unset_invalid:4};
const direction = {total:10,ipv4:7,ipv6:3,over_1500_bytes:2,unsupported:0,tcp_checksum:matrix,ipv4_checksum:matrix};
const base = {kind:'flow',phase:'idle',busy:false,session_id:0,events:[],duration_seconds:30};
const tcp = {kind:'tcp_metadata',phase:'running',busy:true,session_id:1,events:[],duration_seconds:30,tcp_stats:{outbound:direction,inbound:direction}};
let confirm = false, calls = [], entries=[];
const invoke = async name => { calls.push(name); if(name==='dpi_diagnostic_status') return base; if(name==='dpi_tcp_diagnostic_start') return tcp; if(name==='dpi_diagnostic_stop') return {...tcp,phase:'finished',busy:false}; throw Error(name); };
const window = {__TAURI_INTERNALS__:{invoke},confirm:()=>confirm,dispatchEvent(){},umbraJournal:{add:(...v)=>entries.push(v),addFlowView(){}}};
const context={window,document:{querySelector:s=>ids[s.slice(1)]},Event:class{},setTimeout:()=>0,clearTimeout(){},console};
vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../../../ui/components/diagnostics.js'),'utf8'),context);
const tick=()=>new Promise(r=>setImmediate(r));
(async()=>{
 await tick(); assert.equal(ids['diagnostic-tcp-start'].disabled,false);
 ids['diagnostic-tcp-start'].fire('click'); await tick(); assert(!calls.includes('dpi_tcp_diagnostic_start'));
 confirm=true; ids['diagnostic-tcp-start'].fire('click'); await tick();
 assert(calls.includes('dpi_tcp_diagnostic_start')); assert(ids['diagnostic-start'].disabled); assert(ids['diagnostic-tcp-start'].disabled); assert(!ids['diagnostic-stop'].disabled);
 assert(ids['diagnostic-flow-stats'].hidden); assert(!ids['diagnostic-tcp-results'].hidden);
 let report=ids['diagnostic-tcp-report'].value; assert(report.includes('все приложения')); assert(report.includes('флаг=1/сумма неверна 2')); assert(report.includes('не доказывают')); assert(!report.includes('192.0.2.1'));
 ids['diagnostic-stop'].fire('click'); await tick(); assert(calls.includes('dpi_diagnostic_stop')); assert.equal(ids['diagnostic-tcp-start'].disabled,false); assert(ids['diagnostic-tcp-report'].value.includes('Завершена'));
 assert(entries.some(e=>e[1].includes('TCP-проверку')));
 console.log('TCP diagnostic UI consent, status, aggregate report and shared stop passed (mock DOM)');
})().catch(e=>{console.error(e);process.exit(1)});
