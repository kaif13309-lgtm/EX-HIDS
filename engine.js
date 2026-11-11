// EX-HIDS detection engine: features, signature rules, anomaly model, fusion, attack simulators
const F=[
{k:"pkt_rate",n:"Packet rate (pkt/s)",m:40,s:15,w:1},
{k:"src_bytes",n:"Bytes sent (KB)",m:12,s:6,w:1},
{k:"dst_bytes",n:"Bytes received (KB)",m:30,s:12,w:.8},
{k:"distinct_ports",n:"Distinct ports hit",m:2,s:1.2,w:1.2},
{k:"failed_logins",n:"Failed logins",m:.3,s:.6,w:1.3},
{k:"syn_ratio",n:"SYN-only ratio",m:.08,s:.06,w:1.1},
{k:"proc_spawn",n:"Processes spawned",m:2,s:1.5,w:.9},
{k:"priv_change",n:"Privilege changes",m:0,s:.3,w:1.4}];
const RULES=[
{id:"R101",name:"Port scan",sev:.85,test:e=>e.distinct_ports>=40&&e.syn_ratio>.6,why:e=>`${e.distinct_ports} distinct ports probed with ${(e.syn_ratio*100|0)}% SYN-only packets, a classic scan pattern`},
{id:"R102",name:"SSH brute force",sev:.9,test:e=>e.failed_logins>=8,why:e=>`${e.failed_logins} failed logins in one window exceeds the limit of 8`},
{id:"R103",name:"SYN flood / DoS",sev:.95,test:e=>e.pkt_rate>=500&&e.syn_ratio>.7,why:e=>`${e.pkt_rate} pkt/s with ${(e.syn_ratio*100|0)}% SYN-only packets indicates a flood`},
{id:"R104",name:"Data exfiltration",sev:.8,test:e=>e.src_bytes>=400&&e.dst_bytes<20,why:e=>`${e.src_bytes} KB sent out against ${e.dst_bytes} KB received is a one-sided transfer`},
{id:"R105",name:"Privilege escalation",sev:.9,test:e=>e.priv_change>=2&&e.proc_spawn>=10,why:e=>`${e.priv_change} privilege changes and ${e.proc_spawn} spawned processes in one session`}];
const rnd=(m,s)=>Math.max(0,m+s*(Math.random()+Math.random()+Math.random()-1.5)*1.6);
const ip=()=>`10.0.${Math.floor(Math.random()*8)}.${Math.floor(Math.random()*250)+2}`;
function normal(){return{pkt_rate:rnd(40,15)|0,src_bytes:rnd(12,6)|0,dst_bytes:rnd(30,12)|0,distinct_ports:rnd(2,1.2)|0,failed_logins:Math.random()<.08?1:0,syn_ratio:+rnd(.08,.05).toFixed(2),proc_spawn:rnd(2,1.5)|0,priv_change:0}}
const ATK={
"Port scan":()=>({...normal(),distinct_ports:60+(Math.random()*80|0),syn_ratio:.9,pkt_rate:180}),
"SSH brute force":()=>({...normal(),failed_logins:14+(Math.random()*20|0),pkt_rate:90}),
"SYN flood":()=>({...normal(),pkt_rate:900+(Math.random()*900|0),syn_ratio:.95,src_bytes:60}),
"Data exfiltration":()=>({...normal(),src_bytes:600+(Math.random()*600|0),dst_bytes:6,pkt_rate:120}),
"Privilege escalation":()=>({...normal(),priv_change:3,proc_spawn:14+(Math.random()*8|0)}),
"Zero-day (unknown)":()=>({...normal(),pkt_rate:260,dst_bytes:95,proc_spawn:7,syn_ratio:.3,distinct_ports:6})};
function analyse(f){
const hit=RULES.filter(r=>r.test(f));
const sig=hit.length?Math.max(...hit.map(r=>r.sev)):0;
const z=F.map(x=>({...x,v:f[x.k],z:(f[x.k]-x.m)/x.s}));
const raw=z.map(x=>x.w*Math.max(0,Math.abs(x.z)-1)**1);
const tot=raw.reduce((a,b)=>a+b,0);
const ano=1-Math.exp(-tot/8);
const fused=1-(1-sig)*(1-ano);
const contrib=z.map((x,i)=>({...x,c:tot?raw[i]/tot:0})).sort((a,b)=>b.c-a.c);
return{hit,sig,ano,fused,contrib,tot};}
