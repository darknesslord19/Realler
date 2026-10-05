from html.parser import HTMLParser
from urllib.parse import urljoin,urlparse,urlencode,parse_qsl,urlunparse
import urllib.request,re,html as htmllib,json,os,subprocess,time
from collections import Counter,defaultdict
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/153 Safari/537.36'
NOISE=('login','register','iletisim','contact','privacy','gizlilik','dmca','facebook','instagram','twitter','telegram','reklam','account','hesap','javascript:','#')
TAX_HINT=('genre','category','kategori','tur','type','dil','language','ulke','country','collection','tag')
MEDIA_EXT=('.m3u8','.mpd','.mp4','.mkv','.webm','.vtt','.srt','.ass')

def clean(s): return re.sub(r'\s+',' ',htmllib.unescape(str(s or ''))).strip()
def same(a,b): return urlparse(a).netloc.lower().removeprefix('www.')==urlparse(b).netloc.lower().removeprefix('www.')
def uniq(xs,key=lambda x:x):
 out=[]; seen=set()
 for x in xs:
  k=key(x)
  if k and k not in seen: seen.add(k); out.append(x)
 return out

def path_shape(u):
 p=urlparse(u).path.strip('/')
 if not p:return '/'
 parts=[]
 for x in p.split('/'):
  if re.fullmatch(r'\d+',x): parts.append('{n}')
  elif len(x)>3 and ('-' in x or re.search(r'[a-zA-Z]',x)): parts.append('{slug}')
  else: parts.append(x.lower())
 return '/'.join(parts)

class StructuralDOM(HTMLParser):
 def __init__(self):
  super().__init__(convert_charrefs=True); self.stack=[]; self.nodes=[]; self.links=[]; self.images=[]; self.forms=[]; self.scripts=[]; self._script=None
 def handle_starttag(self,t,attrs):
  a=dict(attrs); t=t.lower(); parent=self.stack[-1] if self.stack else None
  node={'tag':t,'attrs':a,'parent':parent,'text':'','links':[],'images':[],'depth':len(self.stack)}; self.nodes.append(node)
  if parent is not None:
   parent.setdefault('children',[]).append(node)
  if t=='a':
   x={'href':a.get('href',''),'text':'','attrs':a,'node':node}; self.links.append(x)
   for anc in self.stack[-5:]: anc['links'].append(x)
  if t in ('img','source'):
   x={'attrs':a,'node':node}; self.images.append(x)
   for anc in self.stack[-5:]: anc['images'].append(x)
  if t=='form':
   f={'action':a.get('action',''),'method':a.get('method','GET').upper(),'inputs':[],'node':node}; self.forms.append(f); node['form']=f
  if t in ('input','button','select','textarea'):
   for anc in reversed(self.stack):
    if 'form' in anc: anc['form']['inputs'].append({'tag':t,**a}); break
  if t=='script': self._script=[]
  if t not in ('meta','link','img','input','br','hr','source','area','base','embed','param','track','wbr'): self.stack.append(node)
 def handle_startendtag(self,t,attrs): self.handle_starttag(t,attrs); self.handle_endtag(t)
 def handle_endtag(self,t):
  t=t.lower()
  if t=='script' and self._script is not None: self.scripts.append(''.join(self._script)); self._script=None
  for i in range(len(self.stack)-1,-1,-1):
   if self.stack[i]['tag']==t: del self.stack[i:]; break
 def handle_data(self,d):
  if self._script is not None:self._script.append(d)
  for n in self.stack[-5:]: n['text']+=d
  active=next((n for n in reversed(self.stack) if n['tag']=='a'),None)
  if active is not None:
   for x in reversed(self.links):
    if x['node'] is active: x['text']+=d; break

def img_url(attrs,base):
 for k in ('data-src','data-lazy-src','data-original','data-image','data-srcset','srcset','src'):
  v=attrs.get(k)
  if v and not str(v).startswith('data:'): return urljoin(base,str(v).split(',')[0].strip().split(' ')[0])
 return ''

class RepoAnalyzer:
 def __init__(self,max_requests=24): self.max_requests=max_requests; self.requests=0; self.logs=[]; self.cache={}
 def log(self,s): self.logs.append('[REPO_ANALYZER] '+s)
 def fetch(self,url,referer=''):
  if url in self.cache:return self.cache[url]
  if self.requests>=self.max_requests:return (0,'','')
  self.requests+=1; h={'User-Agent':UA,'Accept':'text/html,application/xhtml+xml,*/*;q=0.8','Accept-Language':'tr-TR,tr;q=0.9'}
  if referer:h['Referer']=referer
  try:
   with urllib.request.urlopen(urllib.request.Request(url,headers=h),timeout=12) as r:
    x=(r.status,r.read(3000000).decode('utf-8','replace'),r.geturl()); self.cache[url]=x; return x
  except Exception as e:self.log(f'FETCH_FAIL {url} {type(e).__name__}'); self.cache[url]=(0,'',''); return self.cache[url]
 def dom(self,b):
  d=StructuralDOM()
  try:d.feed(b)
  except Exception:pass
  return d
 def root(self,u):p=urlparse(u); return f'{p.scheme}://{p.netloc}/'

 def _link_records(self,d,base):
  out=[]
  for a in d.links:
   href=urljoin(base,a['href']); title=clean(a['text']); p=urlparse(href)
   if not href.startswith('http') or not same(href,base) or p.path.lower().endswith(MEDIA_EXT):continue
   out.append((a,href,title))
  return out

 def catalog(self,b,base,limit=120):
  d=self.dom(b); records=self._link_records(d,base); shape_counts=Counter(path_shape(h) for _,h,t in records if t)
  candidates=[]
  for a,href,title in records:
   low=(href+' '+title).lower(); path=urlparse(href).path.lower()
   if not title or any(n in low for n in NOISE):continue
   # taxonomy/navigation routes are not content cards
   segs=[x for x in path.strip('/').split('/') if x]
   if any(x in TAX_HINT for x in segs[:-1]):continue
   n=a['node']; ancestors=[n]; q=n.get('parent')
   while q is not None and len(ancestors)<5: ancestors.append(q); q=q.get('parent')
   poster=''; structural=0
   # Associate an image only with the smallest card-like DOM scope.  A shared
   # row/grid ancestor containing several content links must never donate its
   # first image to every card.
   for anc in ancestors:
    imgs=anc.get('images',[]); links=anc.get('links',[])
    distinct=[]
    for lk in links:
     hu=urljoin(base,lk.get('href',''))
     if hu.startswith('http') and same(hu,base) and hu not in distinct: distinct.append(hu)
    owns_this=(href in distinct)
    if imgs and owns_this and len(distinct)==1:
     for im in imgs:
      poster=img_url(im['attrs'],base)
      if poster:break
     if poster: structural=max(structural,4); break
   # Image nested directly inside the anchor is always strong evidence.
   if not poster:
    for im in n.get('images',[]):
     poster=img_url(im['attrs'],base)
     if poster: structural=max(structural,4); break
   attrs=' '.join([str(a['attrs'])]+[str(x.get('attrs',{})) for x in ancestors[:3]]).lower()
   if any(k in attrs for k in ('poster','movie','film','series','dizi','card','item','content')): structural+=1
   repeated=shape_counts[path_shape(href)]>=3
   # Generic content evidence = repeated detail-like route plus visual card structure.
   depth=len(segs); score=structural+(2 if poster else 0)+(2 if repeated else 0)+(1 if depth>=1 else 0)
   if score<5:continue
   kind='series' if re.search(r'/(?:dizi|series|tv|anime)(?:/|$)',path,re.I) else 'movie_or_unknown'
   candidates.append({'title':title[:180],'url':href,'poster':poster,'kind':kind,'evidence_score':score,'route_shape':path_shape(href)})
  # Keep dominant repeated content shapes; this removes header/nav links without domain rules.
  if candidates:
   cc=Counter(x['route_shape'] for x in candidates); dominant={s for s,n in cc.items() if n>=2}
   if dominant:candidates=[x for x in candidates if x['route_shape'] in dominant or x['evidence_score']>=7]
  for x in candidates:x.pop('route_shape',None)
  return uniq(candidates,lambda x:x['url'])[:limit]

 def categories(self,b,base,cards):
  d=self.dom(b); content_urls={x['url'] for x in cards}; records=self._link_records(d,base); shapes=Counter(path_shape(h) for _,h,t in records if t)
  out=[]
  for a,href,title in records:
   if not title or href in content_urls:continue
   low=(href+' '+title).lower(); p=urlparse(href); segs=[x.lower() for x in p.path.strip('/').split('/') if x]
   if any(n in low for n in NOISE):continue
   tax=any(x in TAX_HINT for x in segs[:-1])
   text_hint=bool(re.search(r'\b(tümünü gör|tumunu gor|filmler|diziler|anime|aksiyon|komedi|dram|korku|macera|belgesel|altyaz|dublaj)\b',title,re.I))
   # Category evidence is taxonomy route or a non-content collection link; never a dominant content-card shape.
   if tax or (text_hint and shapes[path_shape(href)]<3): out.append({'name':title[:100],'url':href,'evidence':'taxonomy_route' if tax else 'collection_link'})
  return uniq(out,lambda x:x['url'])[:120]

 def search_info(self,b,base,cards):
  d=self.dom(b); out=[]; sample=(cards[0]['title'] if cards else 'test').split(' - ')[0].strip()
  for f in d.forms:
   blob=(str(f)+' '+clean(f['node'].get('text'))).lower(); fields=[i.get('name') for i in f['inputs'] if i.get('name')]
   qfield=next((i.get('name') for i in f['inputs'] if i.get('name') and (i.get('type','').lower()=='search' or re.search(r'(q|query|search|s|ara)',i.get('name',''),re.I))),None)
   if qfield or 'search' in blob or 'arama' in blob:
    ep=urljoin(base,f['action'] or base); item={'method':f['method'],'endpoint':ep,'parameters':fields,'query_parameter':qfield,'verified':False,'source':'form'}
    if f['method']=='GET' and qfield and sample:
     pu=urlparse(ep); qs=dict(parse_qsl(pu.query)); qs[qfield]=sample; test=urlunparse((pu.scheme,pu.netloc,pu.path,pu.params,urlencode(qs),pu.fragment)); st,bb,fu=self.fetch(test,base)
     if st==200:
      hits=self.catalog(bb,fu or test); norm=re.sub(r'\W+','',sample.lower())
      item.update(test_url=test,http_status=st,result_count=len(hits),verified=any(norm and norm in re.sub(r'\W+','',x['title'].lower()) for x in hits))
    out.append(item)
  # Generic JS/network declarations; discovery only unless behavior can be verified statically.
  js='\n'.join(d.scripts).replace('\\/','/')
  for rx,method in ((r'fetch\s*\(\s*["\']([^"\']+)', 'FETCH'),(r'(?:url|endpoint)\s*[:=]\s*["\']([^"\']+)', 'JS')):
   for m in re.finditer(rx,js,re.I):
    raw=m.group(1)
    if re.search(r'(search|arama|query|ajax)',raw,re.I):out.append({'method':method,'endpoint':urljoin(base,raw),'parameters':[],'verified':False,'source':'javascript'})
  # Input-only is a signal, not a ready search mechanism.
  if not out and re.search(r'<input[^>]+(?:type=["\']search|placeholder=["\'][^"\']*(?:ara|search))',b,re.I):out.append({'method':'UI_EVENT','endpoint':'','parameters':[],'verified':False,'source':'search_input_requires_runtime'})
  return uniq(out,lambda x:(x['method'],x.get('endpoint'),tuple(x.get('parameters',[]))))[:20]

 def _pagination_candidates(self,b,base):
  d=self.dom(b); out=[]
  for a,href,title in self._link_records(d,base):
   txt=title.lower(); rel=str(a['attrs'].get('rel','')).lower()
   if 'next' in rel or txt in ('next','sonraki','ileri','›','»','daha fazla','load more') or re.search(r'[?&](?:page|paged|sayfa)=\d+',href,re.I) or re.search(r'/(?:page|sayfa)/\d+/?',href,re.I):out.append({'type':'link','url':href,'verified':False,'new_items':0,'source_text':title})
  return uniq(out,lambda x:(x['type'],x['url']))[:20]

 def pagination(self,b,base,cards,categories):
  # Search home AND collection/category pages; many sites paginate only after "Tümünü Gör".
  probes=[('home',base,b,cards)]
  for c in categories[:4]:
   st,bb,fu=self.fetch(c['url'],base)
   if st==200:probes.append((c['name'],fu or c['url'],bb,self.catalog(bb,fu or c['url'])))
  out=[]
  for label,pbase,pbody,pcards in probes:
   originals={x['url'] for x in pcards}
   for x in self._pagination_candidates(pbody,pbase):
    x['context']=label
    if x['type']=='link':
     st,bb,fu=self.fetch(x['url'],pbase)
     if st==200:
      nxt=self.catalog(bb,fu or x['url']); new=len({z['url'] for z in nxt}-originals); x.update(http_status=st,new_items=new,verified=new>=1)
    out.append(x)
   # Do not invent page-2 URLs. If the site exposes no explicit pagination
   # evidence here, runtime interaction/network discovery decides the mechanism.
  return uniq(out,lambda x:(x['context'],x['type'],x['url']))[:30]

 def series(self,b,base):
  d=self.dom(b); eps=[]; seasons=set(); season_links=[]
  for a,href,title in self._link_records(d,base):
   path=urlparse(href).path
   # URL/attributes are strongest evidence and are parsed before visible text/date noise.
   url_patterns=[r'(?:sezon|season)[-_/ ]*(\d+).*?(?:bolum|bölüm|episode|ep)[-_/ ]*(\d+)',r'[?&](?:season|sezon)=(\d+).*?[?&](?:episode|ep|bolum)=(\d+)']
   m=next((m for rx in url_patterns if (m:=re.search(rx,href,re.I))),None)
   if not m:
    attrs=' '.join(f'{k}={v}' for k,v in a['attrs'].items())
    m=re.search(r'(?:season|sezon)\D{0,4}(\d+).*?(?:episode|ep|bolum|bölüm)\D{0,4}(\d+)',attrs,re.I)
   if not m:
    # Text fallback requires explicit labels on both numbers; dates are ignored.
    m=re.search(r'(\d+)\s*\.?\s*(?:sezon|season)\s+(\d+)\s*\.?\s*(?:b[oö]l[uü]m|episode|ep)\b',title,re.I)
   if m:
    s,e=int(m.group(1)),int(m.group(2));
    if 0<s<100 and 0<e<1000: seasons.add(s); eps.append({'season':s,'episode':e,'title':title[:180],'url':href,'evidence':'url_or_explicit_label'})
    continue
   sm=re.search(r'(?:sezon|season)[-_/ ]*(\d+)',href,re.I) or re.search(r'(\d+)\s*\.?\s*(?:sezon|season)\b',title,re.I)
   if sm:
    s=int(sm.group(1)); seasons.add(s); season_links.append(href)
  return {'detected':bool(seasons or eps),'seasons':sorted(seasons),'episodes':uniq(eps,lambda x:x['url'])[:300],'season_links':uniq(season_links)[:50]}

 def _request_signature(self,req):
  try:
   return (req.method,req.url,req.post_data or '')
  except Exception:return ('','','')

 def _request_record(self,req,kind='runtime'):
  try:
   pu=urlparse(req.url); params=dict(parse_qsl(pu.query,keep_blank_values=True)); post=req.post_data or ''
   ctype=(req.headers or {}).get('content-type','')
   return {'method':req.method,'url':req.url,'endpoint':urlunparse((pu.scheme,pu.netloc,pu.path,pu.params,'',pu.fragment)),'query_parameters':params,'post_data':post[:2000],'content_type':ctype,'resource_type':req.resource_type,'source':kind}
  except Exception:return {}

 def _chrome_candidates(self):
  out=[]
  if os.name=='nt':
   for env in ('PROGRAMFILES','PROGRAMFILES(X86)','LOCALAPPDATA'):
    root=os.environ.get(env,'')
    if root:out.append(os.path.join(root,'Google','Chrome','Application','chrome.exe'))
  else:
   out += ['/usr/bin/google-chrome','/usr/bin/google-chrome-stable','/usr/bin/chromium','/usr/bin/chromium-browser']
  return [x for x in out if os.path.isfile(x)]

 def _runtime_connect(self,pw):
  # 1) Reuse an already running real Chrome when possible.
  try:
   b=pw.chromium.connect_over_cdp('http://127.0.0.1:9222',timeout=2200)
   self.log('RUNTIME_CHROME mode=EXISTING_CDP PASS')
   return {'browser':b,'context':(b.contexts[0] if b.contexts else None),'mode':'EXISTING_CDP','owned_context':False}
  except Exception as e:
   self.log('RUNTIME_CHROME mode=EXISTING_CDP FAIL '+type(e).__name__)
  chrome=next(iter(self._chrome_candidates()),None)
  # 2) Reliable fallback: Playwright controls installed Chrome directly.
  # This does not depend on port 9222 and avoids profile/remote-debug attach races.
  prof=os.path.join(os.path.dirname(__file__),'chrome_repo_runtime_profile')
  os.makedirs(prof,exist_ok=True)
  try:
   kwargs={}
   if chrome:kwargs['executable_path']=chrome
   # On Windows keep it visible; headless is only for non-GUI test environments.
   use_headless=(os.name!='nt' and not os.environ.get('DISPLAY'))
   ctx=pw.chromium.launch_persistent_context(
    prof, headless=use_headless,
    args=['--no-first-run','--no-default-browser-check','--disable-popup-blocking'] + (['--no-sandbox'] if os.name!='nt' else []),
    viewport=None, timeout=15000, **kwargs
   )
   mode='DIRECT_CHROME' if chrome else 'PLAYWRIGHT_CHROMIUM'
   self.log('RUNTIME_CHROME mode='+mode+' PASS exe='+(chrome or 'playwright-bundled'))
   return {'browser':None,'context':ctx,'mode':mode,'owned_context':True}
  except Exception as e:
   self.log('RUNTIME_CHROME mode=DIRECT_PERSISTENT FAIL '+type(e).__name__+': '+str(e)[:180])
  return None

 def _search_inputs(self,page,try_open=True):
  # Score DOM controls by search semantics. Do not assume one input name.
  js="""() => Array.from(document.querySelectorAll('input,textarea,[contenteditable=true]')).map((e,i)=>({i,tag:e.tagName.toLowerCase(),type:(e.type||''),name:(e.name||''),id:(e.id||''),placeholder:(e.placeholder||''),aria:(e.getAttribute('aria-label')||''),cls:(e.className||'').toString(),formAction:(e.form&&e.form.action)||'',visible:!!(e.offsetWidth||e.offsetHeight||e.getClientRects().length)}))"""
  def scored():
   arr=page.evaluate(js); out=[]
   for x in arr:
    blob=' '.join(str(x.get(k,'')) for k in ('type','name','id','placeholder','aria','cls','formAction')).lower()
    score=0
    if x.get('type','').lower()=='search':score+=10
    if re.search(r'(^|[^a-z])(search|arama|ara|query)([^a-z]|$)',blob):score+=7
    if re.search(r'(^|[^a-z])(q|s)([^a-z]|$)',blob):score+=3
    if x.get('visible'):score+=2
    if score>=5:out.append((score,x))
   return [x for _,x in sorted(out,key=lambda z:-z[0])]
  found=scored()
  if found or not try_open:return found
  # Search toggles may be icon-only. Inspect semantic attrs + innerHTML (magnifier/search SVG names).
  try:
   cand=page.locator('button,a,[role=button]')
   for i in range(min(cand.count(),120)):
    e=cand.nth(i)
    try:
     if not e.is_visible():continue
     blob=((e.get_attribute('aria-label') or '')+' '+(e.get_attribute('title') or '')+' '+(e.get_attribute('id') or '')+' '+(e.get_attribute('class') or '')+' '+(e.inner_html() or '')).lower()
     if re.search(r'search|arama|\bara\b|magnif|icon-search|fa-search|bi-search',blob):
      e.click(timeout=1200); page.wait_for_timeout(300); found=scored()
      if found:return found
    except Exception:pass
  except Exception:pass
  return []

 def _submit_search_control(self,page,meta,query):
  # Set value + native events even for custom JS search widgets, then prefer
  # the control's own form. This handles visible, overlay and JS-bound inputs.
  idx=int(meta['i'])
  return page.evaluate("""([idx,q])=>{const es=Array.from(document.querySelectorAll('input,textarea,[contenteditable=true]')); const e=es[idx]; if(!e)return 'missing'; e.focus(); if(e.isContentEditable)e.textContent=q; else {const p=Object.getPrototypeOf(e); const d=Object.getOwnPropertyDescriptor(p,'value'); if(d&&d.set)d.set.call(e,q); else e.value=q;} for(const n of ['input','change','keyup'])e.dispatchEvent(new Event(n,{bubbles:true})); e.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',code:'Enter',keyCode:13,which:13,bubbles:true})); e.dispatchEvent(new KeyboardEvent('keypress',{key:'Enter',code:'Enter',keyCode:13,which:13,bubbles:true})); e.dispatchEvent(new KeyboardEvent('keyup',{key:'Enter',code:'Enter',keyCode:13,which:13,bubbles:true})); if(e.form){ if(e.form.requestSubmit){e.form.requestSubmit(); return 'requestSubmit'} e.form.submit(); return 'submit'} return 'events';}""",[idx,query])

 def _title_query(self,cards):
  # Prefer a human title fragment, stripping year/rating/CSS noise generically.
  for c in cards[:8]:
   t=re.sub(r'\.fa-[^ ]+\{[^}]*\}',' ',c.get('title',''))
   t=re.sub(r'^\s*(?:19|20)\d{2}\s+','',t)
   t=re.sub(r'^\s*\d+(?:\.\d+)?\s+','',t)
   words=[w for w in re.findall(r'[A-Za-zÀ-ž0-9]+',t) if len(w)>=4 and not w.isdigit()]
   if words:return ' '.join(words[:2])[:50]
  return 'test'

 def _runtime_gate(self,page,stage='page'):
  # Be polite to protected sites: wait for the page to settle and never try to
  # bypass a challenge. If a verification page is visible, give the user time
  # to complete it in the same persistent Chrome session.
  try:
   page.wait_for_load_state('domcontentloaded',timeout=12000)
  except Exception:pass
  page.wait_for_timeout(1800)
  def state():
   try:
    return page.evaluate("""() => { const t=((document.title||'')+' '+(document.body?document.body.innerText.slice(0,5000):'')).toLowerCase(); return {challenge:/cloudflare|checking your browser|verify you are human|just a moment|attention required|security verification|doğrulama/.test(t), title:document.title||''}; }""")
   except Exception:return {'challenge':False,'title':''}
  st=state()
  if st.get('challenge'):
   self.log('RUNTIME_GATE CHALLENGE stage='+stage+' title='+str(st.get('title',''))[:80])
   # Visible Windows Chrome: user may solve the verification normally.
   for _ in range(30):
    page.wait_for_timeout(2000)
    st=state()
    if not st.get('challenge'):
     self.log('RUNTIME_GATE CHALLENGE_CLEARED stage='+stage); return 'cleared'
   self.log('RUNTIME_GATE BLOCKED_OR_CHALLENGED stage='+stage); return 'blocked'
  return 'ok'

 def _runtime_pause(self,page,ms=1800):
  # Fixed courtesy delay; this is rate limiting, not challenge evasion.
  try:page.wait_for_timeout(ms)
  except Exception:pass

 def runtime_discovery(self,base,cards,categories):
  result={'available':False,'mode':'NONE','error':'','search':[],'pagination':[],'logs':[]}
  try:from playwright.sync_api import sync_playwright
  except Exception:
   self.log('RUNTIME unavailable playwright_missing'); result['error']='playwright_missing'; return result
  query=self._title_query(cards)
  try:
   with sync_playwright() as pw:
    conn=self._runtime_connect(pw)
    if not conn:self.log('RUNTIME unavailable chrome_launch'); result['error']='chrome_launch_failed'; return result
    result['available']=True; result['mode']=conn.get('mode','UNKNOWN'); ctx=conn.get('context')
    if ctx is None:
     b=conn.get('browser'); ctx=b.contexts[0] if b and b.contexts else (b.new_context() if b else None)
    if ctx is None:result['error']='no_context'; return result
    page=ctx.new_page(); net=[]
    page.on('request',lambda r: net.append(self._request_record(r)))
    try:
     page.goto(base,wait_until='domcontentloaded',timeout=18000)
     if self._runtime_gate(page,'home')=='blocked': result['error']='BLOCKED_OR_CHALLENGED'
    except Exception as e:self.log('RUNTIME goto_fail '+type(e).__name__)

    # SEARCH: reveal controls when needed, submit, then correlate request/navigation
    # with a changed result DOM.  Verification accepts matching title text OR a
    # changed content-card set containing results; it does not depend on one site's selectors.
    try:
     inputs=self._search_inputs(page,True)
     if inputs:
      old_cards={x['url'] for x in self.catalog(page.content(),page.url)}; n0=len(net); u0=page.url
      meta=inputs[0]; self.log('RUNTIME_SEARCH control '+str({k:meta.get(k) for k in ('tag','type','name','id','placeholder','formAction','visible')}))
      self._runtime_pause(page,1600)
      action=self._submit_search_control(page,meta,query); self.log('RUNTIME_SEARCH submit='+str(action))
      gate=self._runtime_gate(page,'search')
      if gate=='blocked': result['error']='BLOCKED_OR_CHALLENGED'
      html=page.content(); hits=self.catalog(html,page.url); new_cards={x['url'] for x in hits}-old_cards
      qt=[x.lower() for x in re.findall(r'[A-Za-zÀ-ž0-9]+',query) if len(x)>=3]
      text=clean(re.sub(r'<[^>]+>',' ',html)).lower()
      matched=bool(qt and all(t in text for t in qt[:2]))
      reqs=[x for x in net[n0:] if x and x.get('resource_type') in ('document','xhr','fetch')]
      qcompact=re.sub(r'\s+','',query.lower())
      evidence=[]
      for x in reqs:
       blob=(x.get('url','')+' '+x.get('post_data','')).lower()
       decoded=blob.replace('+',' ').replace('%20',' ')
       if query.lower() in decoded or qcompact in re.sub(r'\s+','',decoded):evidence.append(x)
      if not evidence and page.url!=u0:
       pu=urlparse(page.url); evidence=[{'method':'GET','url':page.url,'endpoint':urlunparse((pu.scheme,pu.netloc,pu.path,pu.params,'',pu.fragment)),'query_parameters':dict(parse_qsl(pu.query)),'post_data':'','resource_type':'document','source':'runtime_navigation'}]
      verified=bool(evidence and (matched or new_cards or page.url!=u0))
      if evidence:
       ev=dict(evidence[-1]); ev.update({'verified':verified,'result_count':len(hits),'new_items':len(new_cards),'query':query,'result_url':page.url,'proof':'runtime_request_plus_result_change' if verified else 'runtime_request_without_result_change'}); result['search'].append(ev)
       self.log('RUNTIME_SEARCH '+('VERIFIED' if verified else 'DISCOVERED')+' '+ev.get('method','')+' '+ev.get('url','')[:160])
     else:self.log('RUNTIME_SEARCH no_semantic_control')
    except Exception as e:self.log('RUNTIME search_fail '+type(e).__name__+': '+str(e)[:120])

    # PAGINATION: probe collection pages. Click explicit next/load-more first;
    # then scroll several viewport heights. A mechanism is VERIFIED only when
    # the content-card URL set grows/changes and a navigation/request is observed.
    ranked=sorted(categories,key=lambda c:(0 if re.search(r'tümünü|tumunu|daha|all|filmler|diziler',c.get('name',''),re.I) else 1))
    targets=[('home',base)]+[(c.get('name','category'),c['url']) for c in ranked[:4]]
    for label,target in targets:
     try:
      page.goto(target,wait_until='domcontentloaded',timeout=16000)
      if self._runtime_gate(page,'pagination:'+label)=='blocked': result['error']='BLOCKED_OR_CHALLENGED'; break
      first=self.catalog(page.content(),page.url); old={x['url'] for x in first}
      if len(old)<2:continue
      n0=len(net); u0=page.url; action=''; acted=False
      self._runtime_pause(page,1500)
      sels=['a[rel="next"]','button:has-text("Daha Fazla")','a:has-text("Daha Fazla")','button:has-text("Load More")','a:has-text("Load More")','a:has-text("Sonraki")','button:has-text("Sonraki")','a:has-text("Next")','button:has-text("Next")','.load-more','[data-page]','[data-next]']
      for sel in sels:
       try:
        loc=page.locator(sel).first
        if loc.count() and loc.is_visible():loc.click(timeout=2500); action='click:'+sel; acted=True; break
       except Exception:pass
      if not acted:
       action='scroll'
       for _ in range(4):
        page.evaluate('window.scrollBy(0, Math.max(window.innerHeight, 900))'); page.wait_for_timeout(900)
      gate=self._runtime_gate(page,'pagination_action:'+label)
      if gate=='blocked': result['error']='BLOCKED_OR_CHALLENGED'; break
      second=self.catalog(page.content(),page.url); newurls={x['url'] for x in second}-old
      reqs=[x for x in net[n0:] if x and x.get('resource_type') in ('document','xhr','fetch')]
      relevant=[x for x in reqs if same(x.get('url',''),target)] or reqs
      if newurls and (relevant or page.url!=u0):
       if relevant:ev=dict(relevant[-1])
       else:
        pu=urlparse(page.url); ev={'method':'GET','url':page.url,'endpoint':urlunparse((pu.scheme,pu.netloc,pu.path,pu.params,'',pu.fragment)),'query_parameters':dict(parse_qsl(pu.query)),'post_data':'','resource_type':'document','source':'runtime_navigation'}
       ev.update({'type':'runtime_interaction','context':label,'source_url':target,'action':action,'verified':True,'new_items':len(newurls),'sample_new_urls':list(newurls)[:5],'result_url':page.url,'proof':'runtime_interaction_plus_new_cards'}); result['pagination'].append(ev)
       self.log('RUNTIME_PAGINATION VERIFIED '+label+' '+action+' new='+str(len(newurls))); break
     except Exception as e:self.log('RUNTIME pagination_probe_fail '+type(e).__name__+': '+str(e)[:100])
    try:page.close()
    except Exception:pass
    if conn.get('owned_context'):
     try:ctx.close()
     except Exception:pass
  except Exception as e:self.log('RUNTIME fatal '+type(e).__name__+': '+str(e)[:160]); result['error']=type(e).__name__
  return result

 def recover_posters(self,cards):
  for c in [x for x in cards if not x['poster']][:4]:
   st,b,fu=self.fetch(c['url'])
   if st!=200:continue
   m=re.search(r'<meta[^>]+(?:property|name)=["\'](?:og:image|twitter:image)["\'][^>]+content=["\']([^"\']+)',b,re.I) or re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+(?:property|name)=["\'](?:og:image|twitter:image)["\']',b,re.I)
   if m:c['poster']=urljoin(fu or c['url'],htmllib.unescape(m.group(1)))

 def analyze(self,url):
  root=self.root(url); self.log('START '+url); self.log('MODE GENERIC_STRUCTURAL_DISCOVERY + RUNTIME_NETWORK_VERIFY NO_SITE_HARDCODE')
  st,home,final=self.fetch(root)
  if st!=200:st,home,final=self.fetch(url)
  base=final or root; cards=self.catalog(home,base); self.recover_posters(cards); cats=self.categories(home,base,cards); searches=self.search_info(home,base,cards); pages=self.pagination(home,base,cards,cats); runtime=self.runtime_discovery(base,cards,cats); searches=uniq([x for x in searches if x.get('verified')]+runtime.get('search',[])+[x for x in searches if not x.get('verified')],lambda x:(x.get('method'),x.get('endpoint'),x.get('url'),tuple(sorted((x.get('query_parameters') or {}).keys())))); pages=uniq([x for x in pages if x.get('verified')]+runtime.get('pagination',[])+[x for x in pages if not x.get('verified')],lambda x:(x.get('context'),x.get('type'),x.get('url'),x.get('endpoint')))
  candidates=[]
  if url.rstrip('/')!=root.rstrip('/'):candidates.append(url)
  candidates += [x['url'] for x in cards if x['kind']=='series'][:12]
  # If type unknown, probe a few detail cards too; series detection is evidence based.
  candidates += [x['url'] for x in cards][:4]
  series={'detected':False,'seasons':[],'episodes':[],'season_links':[]}
  for u in uniq(candidates):
   ds,db,df=self.fetch(u,base)
   if ds!=200:continue
   got=self.series(db,df or u)
   if got['detected']:
    # Follow season pages generically if detail only exposes season selectors.
    if not got['episodes']:
     for su in got.get('season_links',[])[:4]:
      ss,sb,sf=self.fetch(su,df or u)
      if ss==200:
       sub=self.series(sb,sf or su); got['episodes']+=sub['episodes']; got['seasons']=sorted(set(got['seasons'])|set(sub['seasons']))
    series=got; series['detail_url']=u; break
  verified_search=sum(bool(x.get('verified')) for x in searches); verified_page=sum(bool(x.get('verified')) for x in pages)
  self.log(f'CATALOG count={len(cards)} posters={sum(bool(x["poster"]) for x in cards)}'); self.log(f'CATEGORIES count={len(cats)}'); self.log(f'SEARCH candidates={len(searches)} verified={verified_search}'); self.log(f'PAGINATION candidates={len(pages)} verified={verified_page}'); self.log(f'SERIES detected={series["detected"]} seasons={len(series["seasons"])} episodes={len(series["episodes"])}')
  return {'status':'VERIFIED' if cards else ('DISCOVERED' if cats or searches or pages or series['detected'] else 'UNKNOWN'),'root_url':root,'http_status':st,'requests':self.requests,'runtime':{'available':runtime.get('available',False),'mode':runtime.get('mode','NONE'),'error':runtime.get('error',''),'search_verified':sum(bool(x.get('verified')) for x in runtime.get('search',[])),'pagination_verified':sum(bool(x.get('verified')) for x in runtime.get('pagination',[]))},'catalog':{'count':len(cards),'poster_count':sum(bool(x['poster']) for x in cards),'items':cards},'categories':cats,'search':searches,'pagination':pages,'series':series,'cloudstream_ready':{'main_page':len(cards)>=3,'posters':bool(cards and sum(bool(x['poster']) for x in cards)>=max(1,(len(cards)*2)//3)),'search_mechanism':any(x.get('verified') for x in searches),'pagination':any(x.get('verified') for x in pages),'series_episodes':bool(series['episodes'])},'logs':self.logs}
