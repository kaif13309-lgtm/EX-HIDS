// EX-HIDS UI: event stream, counters, explanation panel
const sevOf=s=>s>=.75?["High","hi"]:s>=.45?["Medium","md"]:["Low","lo"];
let N=0,A=0,S=0,M=0,run=true,list=[],sel=null,id=0;
function add(f,label){
const r=analyse(f);const e={id:++id,t:new Date(),f,r,src:ip(),dst:ip(),label};
N++;if(r.fused>=.45){A++;if(r.sig>0)S++;if(r.ano>=.45)M++;}
list.unshift(e);if(list.length>80)list.pop();draw();}
function draw(){
sN.textContent=N;sA.textContent=A;sS.textContent=S;sM.textContent=M;
feed.innerHTML=list.map(e=>{const[sv,c]=sevOf(e.r.fused);const alert=e.r.fused>=.45;
const nm=e.r.hit.length?e.r.hit[0].name:(alert?"Anomalous behaviour":"Normal traffic");
return`<div class="row ${sel&&sel.id===e.id?"sel":""}" tabindex="0" data-id="${e.id}"><span class="t">${e.t.toTimeString().slice(0,8)}</span><span>${nm}<br><span class="mu small">${e.src} → ${e.dst}</span></span><span class="pill ${alert?c:"mu"}">${alert?sv+" "+(e.r.fused*100|0):"OK"}</span></div>`}).join("");}
feed.addEventListener("click",ev=>{const r=ev.target.closest(".row");if(r)show(+r.dataset.id)});
feed.addEventListener("keydown",ev=>{if(ev.key==="Enter"){const r=ev.target.closest(".row");if(r)show(+r.dataset.id)}});
function show(i){sel=list.find(e=>e.id===i);if(!sel)return;draw();const{r,f}=sel;const[sv,c]=sevOf(r.fused);const alert=r.fused>=.45;
const top=r.contrib.filter(x=>x.c>.05).slice(0,3);
let nl;
if(!alert)nl="No rule matched and every feature sits near its learned baseline, so the event is treated as normal.";
else{const a=[];
if(r.hit.length)a.push(`<b style="color:var(--sig)">Signature:</b> rule ${r.hit.map(h=>h.id+" ("+h.name+")").join(", ")} fired because ${r.hit[0].why(f)}.`);
else a.push(`<b style="color:var(--sig)">Signature:</b> no known rule matched.`);
if(r.ano>=.3&&top.length)a.push(`<b style="color:var(--ano)">Anomaly:</b> behaviour is unusual mainly because of ${top.map(x=>`${x.n.toLowerCase()} (${x.v}, baseline ${x.m}, ${Math.abs(x.z).toFixed(1)}σ ${x.z>0?"above":"below"})`).join("; ")}.`);
else a.push(`<b style="color:var(--ano)">Anomaly:</b> statistical deviation is low.`);
nl=a.join("<br>");}
detail.innerHTML=`<h2>Explanation for event #${sel.id} <span class="pill ${alert?c:"mu"}" style="margin-left:6px">${alert?sv+" threat":"Benign"}</span></h2>
<div class="small mu">${sel.src} → ${sel.dst}${sel.label?" · injected: "+sel.label:""}</div>
<div class="gl" style="margin-top:12px"><span>Signature score</span><div class="track"><i style="width:${r.sig*100}%;background:var(--sig)"></i></div><span>${(r.sig*100|0)}%</span></div>
<div class="gl"><span>Anomaly score</span><div class="track"><i style="width:${r.ano*100}%;background:var(--ano)"></i></div><span>${(r.ano*100|0)}%</span></div>
<div class="gl"><span><b>Fused risk</b></span><div class="track"><i style="width:${r.fused*100}%;background:var(--${c})"></i></div><span><b>${(r.fused*100|0)}%</b></span></div>
<div class="nl">${nl}</div>
<h2 style="margin-top:14px">Feature contributions to anomaly score</h2>
${r.contrib.map(x=>`<div class="gl"><span>${x.n}</span><div class="track"><i style="width:${x.c*100}%;background:var(--ano)"></i></div><span>${(x.c*100|0)}%</span></div>`).join("")}
<h2 style="margin-top:14px">Raw features</h2>
<table>${F.map(x=>`<tr><td>${x.n}</td><td>${f[x.k]}</td></tr>`).join("")}</table>`;}
atk.innerHTML=Object.keys(ATK).map(k=>`<button class="atk" data-k="${k}">${k}</button>`).join("");
atk.addEventListener("click",ev=>{const k=ev.target.dataset.k;if(k){add(ATK[k](),k);show(list[0].id)}});
run_=document.getElementById("run");
run_.onclick=()=>{run=!run;run_.textContent=run?"Pause stream":"Resume stream"};
theme.onclick=()=>{const d=document.documentElement;const dark=getComputedStyle(d).colorScheme==="dark";d.dataset.theme=dark?"light":"dark"};
for(let i=0;i<8;i++)add(normal());
setInterval(()=>{if(run)add(normal())},1300);
