
const defaults = [
  "https://www.hdfilmcehennemi.nl/hot-spot-2026/",
  "https://jetfilmizle.now/film/bugun-guzel",
  "https://720izle.com/filmler11/nasil-katil-olunur-how-to-make-a-killing/",
  "https://fullhdfilmizle.now/film/intikam-vakti-2021",
   "https://www.diziyou.one/the-shards-1-sezon-9-bolum/",
  "https://filmmakinesi.to/film/hot-spot-2026/",
  "https://www.sinema.gg/parthenope/#!",
  "https://www.fullhdfilmizlesene.now/film/orumcek-adam-yepyeni-bir-gun-spider-man-brand-new-day/"
];

let sites = JSON.parse(localStorage.getItem("resolverSites") || "null") || [];
defaults.forEach(u=>{ if(!sites.includes(u)) sites.push(u); });
localStorage.setItem("resolverSites", JSON.stringify(sites));
let allLogs = [];

function saveSites(){ localStorage.setItem("resolverSites", JSON.stringify(sites)); }
function renderSites(){
  const box = document.getElementById("siteList");
  box.innerHTML = "";
  sites.forEach((u,i)=>{
    const d = document.createElement("div");
    d.className="site";
    d.innerHTML=`<input class="pick" type="checkbox" data-i="${i}" checked>
      <span>${escapeHtml(u)}</span>
      <button class="secondary" style="flex:0" onclick="removeUrl(${i})">×</button>`;
    box.appendChild(d);
  });
}
function escapeHtml(s){return s.replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m]));}
function addUrl(){
  const el=document.getElementById("newUrl"); const u=el.value.trim();
  if(!/^https?:\/\//i.test(u)) return alert("http/https URL gir abi.");
  if(!sites.includes(u)) sites.push(u);
  saveSites(); renderSites(); el.value="";
}
function removeUrl(i){sites.splice(i,1);saveSites();renderSites();}
function selectAll(){document.querySelectorAll(".pick").forEach(x=>x.checked=true);}
function selectedUrls(){return [...document.querySelectorAll(".pick:checked")].map(x=>sites[Number(x.dataset.i)]);}

async function runRepoSingle(){
  const u=document.getElementById("newUrl").value.trim();
  if(!/^https?:\/\//i.test(u)) return alert("Önce URL gir abi.");
  setStatus("Repo bilgileri analiz ediliyor...","warn");
  const box=document.createElement("div"); box.className="result";
  box.innerHTML=`<h3>${escapeHtml(u)} — REPO ANALİZİ</h3><div class="meta"><span class="badge warn">Çalışıyor</span></div><pre>CloudStream repo bilgileri çıkarılıyor...</pre>`;
  document.getElementById("results").prepend(box);
  try{
    const r=await fetch("/api/repo-analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url:u})});
    const data=await r.json(); if(data.error) throw new Error(data.error);
    const ready=data.cloudstream_ready||{}, cat=data.catalog||{}, ser=data.series||{};
    box.querySelector(".meta").innerHTML=
      `<span class="badge ${data.status==="VERIFIED"?"ok":"warn"}">${escapeHtml(data.status||"UNKNOWN")}</span>`+
      `<span class="badge">İçerik ${cat.count||0}</span><span class="badge">Poster ${cat.poster_count||0}</span>`+
      `<span class="badge">Kategori ${(data.categories||[]).length}</span><span class="badge">Arama ${(data.search||[]).length}</span>`+
      `<span class="badge">Sayfalama ${(data.pagination||[]).length}</span><span class="badge">Bölüm ${(ser.episodes||[]).length}</span>`;
    const report={
      cloudstream_ready:ready, runtime:data.runtime||{}, catalog:cat, categories:data.categories||[], search:data.search||[],
      pagination:data.pagination||[], series:ser, requests:data.requests||0
    };
    box.querySelector("pre").textContent=(data.logs||[]).join("\n")+"\n\n===== CLOUDSTREAM REPO RAPORU =====\n"+JSON.stringify(report,null,2);
    allLogs.push("===== "+u+" — REPO ANALİZİ =====\n"+box.querySelector("pre").textContent);
    setStatus("Repo analizi bitti","ok");
  }catch(e){box.querySelector(".meta").innerHTML=`<span class="badge bad">HATA</span>`;box.querySelector("pre").textContent=String(e);setStatus("Hata","bad");}
}

async function runSingle(){
  const u=document.getElementById("newUrl").value.trim();
  if(!/^https?:\/\//i.test(u)) return alert("Önce URL gir abi.");
  await runUrls([u]);
}
async function runSelected(){const arr=selectedUrls(); if(!arr.length)return alert("Site seç."); await runUrls(arr);}
function setStatus(t,kind=""){const e=document.getElementById("status");e.textContent=t;e.className="badge "+kind;}
function clearResults(){document.getElementById("results").innerHTML="";allLogs=[];}
async function runUrls(urls){
  setStatus("Taranıyor...","warn");
  for(const url of urls){
    const box=document.createElement("div"); box.className="result";
    box.innerHTML=`<h3>${escapeHtml(url)}</h3><div class="meta"><span class="badge warn">Çalışıyor</span></div><pre>İstek gönderiliyor...</pre>`;
    document.getElementById("results").prepend(box);
    try{
      const r=await fetch("/api/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url})});
      const data=await r.json();
      const kind=data.final_verified?"ok":(data.blocked||data.runtime_needed?"warn":"");
      box.querySelector(".meta").innerHTML=
        `<span class="badge ${kind}">${escapeHtml(data.detect||"UNKNOWN")}</span>
         <span class="badge">HTTP ${data.http_status||0}</span>
         <span class="badge">İstek ${data.requests||0}</span>
         <span class="badge">Derinlik ${data.max_depth||0}</span>
         <span class="badge">${data.confidence||0}%</span>
         <span class="badge">Aile: ${escapeHtml(data.resolver_family||"UNKNOWN")}</span>
         <span class="badge">Motor: ${escapeHtml(data.suggested_engine||"MANUAL_INSPECTION")}</span>
         <span class="badge">Medya: ${escapeHtml(data.media_transport||"UNKNOWN")}</span>
         <span class="badge ${data.site_compatibility===100?"ok":""}">Uyum ${data.site_compatibility||0}%</span>
         <span class="badge ${data.browser_runtime_used?"ok":""}">Browser ${data.browser_runtime_used?"KULLANILDI":(data.browser_runtime_available?"HAZIR":"STATİK")}</span>`;
      box.querySelector("pre").textContent=(data.logs||[]).join("\n");
      allLogs.push("===== "+url+" =====\n"+(data.logs||[]).join("\n"));
    }catch(e){
      box.querySelector(".meta").innerHTML=`<span class="badge bad">HATA</span>`;
      box.querySelector("pre").textContent=String(e);
    }
  }
  setStatus("Bitti","ok");
}
async function copyAll(){
  await navigator.clipboard.writeText(allLogs.join("\n\n"));
  setStatus("Log kopyalandı","ok");
}
renderSites();

let manualSessionId='';
let manualPoll=null;
async function startManualListen(){
  const u=document.getElementById('singleUrl').value.trim(); if(!u){alert('URL gir abi');return;}
  const r=await fetch('/api/manual-start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:u})});
  const d=await r.json(); if(!r.ok){alert(d.error||'Başlatılamadı');return;}
  manualSessionId=d.session_id;
  if(d.status==='error'){ alert('Chrome açılamadı: '+(d.error||'bilinmeyen hata')); manualSessionId=''; return; }
  if(d.status==='listening') alert('Chrome açıldı — DİNLİYORUM. Siteyi sen gez; program hiçbir yere kendi tıklamayacak.');
  else alert('Chrome başlatılıyor. Durum ekranda takip edilecek.');
  clearInterval(manualPoll); manualPoll=setInterval(async()=>{try{const rr=await fetch('/api/manual-status',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:u,session_id:manualSessionId})}); const x=await rr.json(); console.log('MANUAL_LISTENER',x.status,x.request_count,x.snapshot_count); if(x.status==='error'){clearInterval(manualPoll); alert('Dinleyici hatası: '+(x.error||'bilinmeyen hata')); manualSessionId='';}}catch(e){}},1000);
}
async function stopManualListen(){
  const u=document.getElementById('singleUrl').value.trim(); if(!manualSessionId){alert('Önce Siteyi Aç ve Dinle');return;}
  clearInterval(manualPoll);
  setStatus('Dinleyici durduruluyor; final rapor hazırlanıyor...','warn');
  let r=await fetch('/api/manual-stop',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:u,session_id:manualSessionId})});
  let d=await r.json(); if(!r.ok){alert(d.error||'Bitirilemedi');return;}
  // V77: never download a stopping placeholder. Poll until the background
  // listener has built the complete capture result.
  const deadline=Date.now()+90000;
  while(d && (d.status==='stopping' || d.status==='starting' || d.status==='listening' || d.finalizing===true)){
    if(Date.now()>deadline){
      setStatus('Final rapor zaman aşımı — oturum korunuyor','bad');
      alert('Final rapor 90 saniyede tamamlanmadı. TXT indirilmedi; eksik stopping raporu oluşturulmadı.');
      return;
    }
    await new Promise(resolve=>setTimeout(resolve,750));
    const rr=await fetch('/api/manual-status',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:u,session_id:manualSessionId})});
    d=await rr.json(); if(!rr.ok){alert(d.error||'Final durum alınamadı');return;}
    setStatus('Final rapor hazırlanıyor... request: '+(d.request_count||0)+' | snapshot: '+(d.snapshot_count||0),'warn');
  }
  if(d.status==='error'){setStatus('Dinleyici hatası','bad'); alert(d.error||'Dinleyici hatası'); return;}
  if(d.status!=='CAPTURED' && !d.CLOUDSTREAM_REPO_DATA){
    setStatus('Final veri oluşmadı','bad'); alert('Final veri oluşmadı; eksik TXT indirilmedi.'); return;
  }
  localStorage.setItem('resolverLabV77LastCapture',JSON.stringify(d));
  const txt='===== '+u+' — V7.7 REPO + PLAYER ANALİZİ =====\n'+JSON.stringify(d,null,2);
  const blob=new Blob([txt],{type:'text/plain;charset=utf-8'}), a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='repo-player-manual-listen-v77.txt'; a.click(); URL.revokeObjectURL(a.href);
  setStatus('Final rapor hazır — TXT oluşturuldu','ok');
  manualSessionId='';
}

