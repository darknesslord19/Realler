import threading,time,uuid,re,json,os,shutil
from urllib.parse import urlparse,parse_qsl,urljoin
from repo_analyzer import RepoAnalyzer, same

SESSIONS={}
LOCK=threading.Lock()

class ManualSession:
    def __init__(self,url):
        self.id=uuid.uuid4().hex[:12]; self.url=url; self.status='starting'; self.error=''; self.started=time.time(); self.events=[]; self.net=[]; self.snapshots=[]; self.stop_evt=threading.Event(); self.done_evt=threading.Event(); self.result=None; self.observed_episodes=[]; self.series_ui=[]; self.player_ui=[]; self.frame_events=[]; self.playback_proofs=[]; self.subtitles=[]; self.last_html=''; self.last_url=self.url
        self.thread=threading.Thread(target=self._run,daemon=True); self.thread.start()
    def add(self,typ,**kw):
        self.events.append({'t':round(time.time()-self.started,2),'type':typ,**kw})
        self.events=self.events[-1200:]
    def _req(self,r):
        try:return {'t':round(time.time()-self.started,2),'method':r.method,'url':r.url,'resource_type':r.resource_type,'post_data':r.post_data or ''}
        except Exception:return None
    def _run(self):
        """V80: installed Google Chrome + mitmproxy only. No Playwright/CDP."""
        import subprocess, socket, sys
        from pathlib import Path
        a=RepoAnalyzer(); mitm=None; chrome_proc=None
        cap=Path(__file__).with_name('manual_mitm_capture.jsonl')
        try:
            cap.write_text('',encoding='utf-8')
            sock=socket.socket(); sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]; sock.close()
            addon=Path(__file__).with_name('manual_mitm_capture.py')
            mitmdump=shutil.which('mitmdump') or shutil.which('mitmdump.exe')
            if mitmdump:
                mitm_cmd=[mitmdump]
            else:
                # Same Python that runs Resolver Lab. If mitmproxy is not installed here,
                # fail visibly instead of opening Chrome with a dead proxy.
                try:
                    __import__('mitmproxy.tools.dump')
                except Exception as ie:
                    raise RuntimeError('mitmproxy/mitmdump bulunamadı. Önce: pip install mitmproxy') from ie
                mitm_cmd=[sys.executable,'-m','mitmproxy.tools.dump']
            mitm_cmd += ['-q','--listen-host','127.0.0.1','--listen-port',str(port),'--ssl-insecure','--set','connection_strategy=lazy','--set',f'manual_capture={cap}','-s',str(addon)]
            log_path=Path(__file__).with_name(f'manual_mitm_{self.id}.log')
            # V81 CMD LIVE: addon printleri doğrudan Resolver Lab CMD penceresine akar.
            # Böylece kullanıcı Stop/TXT beklemeden tüm anlamlı trafiği kopyalayabilir.
            mitm=subprocess.Popen(mitm_cmd)

            # HARD GATE: Chrome must never start until the proxy socket is really accepting.
            ready=False; deadline=time.time()+10.0; last_err=''
            while time.time() < deadline:
                if mitm.poll() is not None:
                    break
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.20):
                        ready=True; break
                except OSError as se:
                    last_err=str(se); time.sleep(.10)
            if not ready:
                detail='MITM process proxy portunu açamadı'
                rc=mitm.poll()
                raise RuntimeError(f'MITM proxy hazır olmadı (port={port}, rc={rc}). {detail or last_err}')
            self.add('MITM_READY',proxy_port=port,log=str(log_path))

            chrome=next(iter(a._chrome_candidates()),None)
            if not chrome or not os.path.exists(chrome): raise RuntimeError('Kurulu Google Chrome bulunamadı')
            profile=os.path.join(os.path.dirname(__file__),'manual_listener_profiles',self.id); os.makedirs(profile,exist_ok=True)
            cmd=[chrome,f'--proxy-server=http://127.0.0.1:{port}','--proxy-bypass-list=<-loopback>','--disable-quic','--ignore-certificate-errors',f'--user-data-dir={profile}','--no-first-run','--no-default-browser-check','--disable-popup-blocking','--new-window',self.url]
            chrome_proc=subprocess.Popen(cmd,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            self.status='listening'; self.add('LISTENING',url=self.url,mode='NORMAL_CHROME_MITM_ONLY',proxy_port=port)
            pos=0; root_host=urlparse(self.url).netloc.lower()
            while not self.stop_evt.wait(.25):
                pos=self._consume_mitm(cap,pos,a,root_host)
            pos=self._consume_mitm(cap,pos,a,root_host)
            self.result=self._build_result(a,self.last_html or '',self.last_url or self.url)
            if isinstance(self.result,dict): self.result['subtitles']=self.subtitles
            self.status='done'; self.done_evt.set()
        except Exception as e:
            self.error=type(e).__name__+': '+str(e)
            if self.stop_evt.is_set():
                try:self.result=self._force_finalize_from_capture(); self.status='done'
                except Exception:self.status='error'
            else:self.status='error'
            self.done_evt.set()
        finally:
            if mitm is not None:
                try:mitm.terminate()
                except Exception:pass
            # Chrome açık kalabilir; bu sürümde amaç canlı CMD kaydıdır.

    def _consume_mitm(self,path,pos,a,root_host):
        try:
            with path.open('r',encoding='utf-8',errors='replace') as f:
                f.seek(pos)
                for line in f:
                    try:r=json.loads(line)
                    except Exception:continue
                    u=r.get('url',''); pu=urlparse(u); host=pu.netloc.lower(); ct=(r.get('content_type') or '').lower()
                    if r.get('kind')=='subtitle_track':
                        rec={'t':round(time.time()-self.started,2),'url':u,'language':r.get('language','unknown'),'type':r.get('subtitle_type','SUBTITLE'),'source':r.get('source','')}
                        if u and not any(x.get('url')==u for x in self.subtitles): self.subtitles.append(rec)
                        self.add('SUBTITLE_TRACK',**rec)
                        continue
                    if r.get('subtitle') and r.get('kind')=='response':
                        rec={'t':round(time.time()-self.started,2),'url':u,'language':'unknown','type':'NETWORK','content_type':ct,'status':r.get('status')}
                        if u and not any(x.get('url')==u for x in self.subtitles): self.subtitles.append(rec)
                        self.add('SUBTITLE_NETWORK',**rec)
                    if r.get('kind')=='request':
                        typ='document' if r.get('document') else ('xhr' if r.get('api_like') else 'fetch')
                        x={'t':round(time.time()-self.started,2),'method':r.get('method','GET'),'url':u,'resource_type':typ,'post_data':r.get('post_data','') or ''}
                        self.net.append(x); self.net=self.net[-2000:]; self.add('REQUEST',method=x['method'],url=u,resource_type=typ)
                    elif r.get('kind')=='response' and host==root_host:
                        body=r.get('text','') or ''
                        if body and ('html' in ct or r.get('document')):
                            self.last_html=body; self.last_url=u
                            cards=a.catalog(body,u); urls={x.get('url') for x in cards if x.get('url')}
                            self.snapshots.append({'t':round(time.time()-self.started,2),'url':u,'count':len(urls),'new_urls':list(urls)[:30],'cards':cards[:100]}); self.snapshots=self.snapshots[-400:]
                            self.add('NAVIGATION',url=u); self.add('DOM_CHANGE',url=u,count=len(urls),new_items=len(urls))
                            for m in re.finditer(r'href=["\']([^"\']*(?:sezon|season)[^"\']*(?:bolum|bölüm|episode|ep)[^"\']*)["\']',body,re.I):
                                eu=urljoin(u,m.group(1)); mm=re.search(r'(?:sezon|season)[-_ /]?(\d+).*?(?:bolum|bölüm|episode|ep)[-_ /]?(\d+)',eu,re.I)
                                if mm and not any(x['url']==eu for x in self.observed_episodes):self.observed_episodes.append({'season':int(mm.group(1)),'episode':int(mm.group(2)),'url':eu,'evidence':'mitm_html_response'})
                return f.tell()
        except FileNotFoundError:return pos
        except Exception:return pos
    def _on_frame_nav(self,pg,f):
        try:
            u=f.url or ''
            if f==pg.main_frame:
                self.add('NAVIGATION',url=u)
            elif u.startswith(('http://','https://')):
                rec={'t':round(time.time()-self.started,2),'page_url':pg.url,'url':u,'name':f.name or '','source':'frame_navigation'}
                self.frame_events.append(rec); self.frame_events=self.frame_events[-600:]
                self.add('PLAYER_FRAME_NAVIGATION',page_url=pg.url,url=u,name=f.name or '')
        except Exception: pass

    def _on_req(self,r):
        x=self._req(r)
        if not x:return
        # Keep documents/XHR/fetch; assets add noise and are not needed for repo discovery.
        if x['resource_type'] in ('document','xhr','fetch'):
            self.net.append(x); self.net=self.net[-1200:]; self.add('REQUEST',method=x['method'],url=x['url'],resource_type=x['resource_type'])
    def _build_result(self,a,html,final_url):
        # V6.5: PASSIVE ONLY. Learn from requests, navigations and DOM snapshots that
        # the user actually produced. No synthetic click/goto/scroll/search.
        noise_hosts=('google-analytics.com','googletagmanager.com','doubleclick.net')
        noise_paths=('/cdn-cgi/','/popover/','/favicon','/manifest','/api/ziyaretci')
        media_ext=re.compile(r'\.(?:m3u8|mpd|ts|m4s|mp4|webm|vtt|srt)(?:$|\?)',re.I)

        # Redirect-aware site identity. final_url is authoritative when the start URL
        # redirects (e.g. sinema.gg -> sinemacc.com).
        fp=urlparse(final_url or self.url)
        final_origin=f'{fp.scheme}://{fp.netloc}' if fp.scheme and fp.netloc else ''
        observed_hosts=[]
        for u in [final_url]+[e.get('url','') for e in self.events if e.get('type')=='NAVIGATION']:
            pu=urlparse(u or '')
            if pu.netloc and pu.netloc not in observed_hosts: observed_hosts.append(pu.netloc)
        allowed_hosts=set(observed_hosts)
        if fp.netloc: allowed_hosts.add(fp.netloc)

        def useful(n):
            pu=urlparse(n.get('url',''))
            host=pu.netloc.lower(); path=pu.path.lower()
            if not host or host not in allowed_hosts: return False
            if any(h in host for h in noise_hosts): return False
            if any(p in path for p in noise_paths): return False
            if media_ext.search(n.get('url','')): return False
            return True
        clean_net=[n for n in self.net if useful(n)]

        # SEARCH: query-bearing same-site requests only; exclude pagination/media/logging.
        search=[]; seen_search=set()
        for n in clean_net:
            u=n['url']; pu=urlparse(u); q=dict(parse_qsl(pu.query,keep_blank_values=True)); post=n.get('post_data','') or ''
            keys={k.lower() for k in q}; qkeys=keys & {'s','q','query','search','searchterm','keyword','term','ara'}
            post_search=bool(re.search(r'(^|[&{\" ])(s|q|query|search|searchterm|keyword|term|ara)[=\":]',post,re.I))
            if not qkeys and not post_search: continue
            if re.search(r'/(?:log-search|search-log|analytics)(?:/|$)',pu.path,re.I): continue
            endpoint=pu._replace(query='',fragment='').geturl()
            sig=(n['method'],endpoint,tuple(sorted(q.keys())))
            if sig in seen_search: continue
            seen_search.add(sig)
            search.append({**n,'endpoint':endpoint,'query_parameters':q,'verified':True,'source':'manual_user_action_network'})

        # Generic pagination parser. Supports AJAX routes and full document navigations:
        # /load/page/2/x/, /page/2/, /sayfa/2/, /sayfa-2, /filmler/sayfa-2, ?page=2.
        def pagination_shape(u):
            pu=urlparse(u or ''); q=dict(parse_qsl(pu.query,keep_blank_values=True)); path=pu.path
            m=re.search(r'/load/page/(\d+)/(categories|genres)/([^/]+)/?',path,re.I)
            if m: return int(m.group(1)),m.group(2).lower(),m.group(3),'ajax_load',q
            m=re.search(r'/load/page/(\d+)/([^/]+)/?',path,re.I)
            if m: return int(m.group(1)),m.group(2).lower(),m.group(2),'ajax_load',q
            for k in ('page','paged','p','currentPage','currentpage'):
                if str(q.get(k,'')).isdigit() and int(q[k]) >= 2: return int(q[k]),'query',k,'query',q
            m=re.search(r'/(page|sayfa)/(\d+)(?:/|$)',path,re.I)
            if m: return int(m.group(2)),'path',m.group(1).lower(),'path_segment',q
            m=re.search(r'/(sayfa|page)-(\d+)(?:/|$)',path,re.I)
            if m: return int(m.group(2)),'path',m.group(1).lower(),'path_dash',q
            # Collection routes with a bare trailing page number: /yeni-filmler/2,
            # /filmizle/aile-filmleri/2. Detail routes are deliberately excluded.
            m=re.search(r'/(\d+)(?:/|$)',path,re.I)
            if m and int(m.group(1)) >= 2:
                low=path.lower()
                if not re.search(r'/(?:film|dizi|series|tv)/[^/]+/\d+/?$',low,re.I):
                    parent=re.sub(r'/\d+/?$','',path).rstrip('/')
                    if parent and parent.count('/') >= 1: return int(m.group(1)),'numeric_tail',parent,'path_numeric_tail',q
            return None

        pagination=[]; seen_pag=set()
        evidence=[]
        for n in clean_net:
            evidence.append(('request',n.get('t',0),n.get('method','GET'),n.get('url',''),n.get('resource_type','')))
        for e in self.events:
            if e.get('type')=='NAVIGATION': evidence.append(('navigation',e.get('t',0),'GET',e.get('url',''),'document'))
        evidence.sort(key=lambda z:z[1])
        for source,t,method,u,rtype in evidence:
            sh=pagination_shape(u)
            if not sh: continue
            page_num,family,token,style,q=sh; pu=urlparse(u)
            # de-dupe the request+navigation pair for the same page.
            sig=(pu.scheme,pu.netloc,pu.path,tuple(sorted(q.items())),page_num)
            if sig in seen_pag: continue
            seen_pag.add(sig)
            after=[x for x in self.snapshots if t <= x['t'] <= t+4.0]
            snap=after[0] if after else None
            pagination.append({'t':t,'method':method,'url':u,'resource_type':rtype,'type':'manual_observed_pagination',
                'endpoint':pu._replace(query='',fragment='').geturl(),'query_parameters':q,'page':page_num,'family':family,
                'route_token':token,'style':style,'verified':True,'result_url':(snap or {}).get('url',''),
                'new_items':len((snap or {}).get('new_urls',[])),'sample_new_urls':(snap or {}).get('new_urls',[])[:5],
                'source':'manual_user_action_'+source})

        # Union catalog across the whole manual session instead of only the richest page.
        cardmap={}
        for snap in self.snapshots:
            for c in snap.get('cards',[]):
                u=c.get('url') or ''
                if u and u not in cardmap: cardmap[u]=dict(c)
        for c in a.catalog(html,final_url) if html else []:
            u=c.get('url') or ''
            if u and u not in cardmap: cardmap[u]=dict(c)
        cards=list(cardmap.values())[:500]

        # Aggregate categories from every captured page, not only whichever page was open at Stop.
        catmap={}
        for snap in self.snapshots:
            for c in snap.get('cards',[]):
                pass
        # RepoAnalyzer needs HTML for taxonomy extraction; final HTML is retained, while
        # navigation URLs add taxonomy routes that the user explicitly visited.
        cats=a.categories(html,final_url,cards) if html else []
        for c in cats: catmap[c.get('url','')]=c
        for e in self.events:
            if e.get('type')!='NAVIGATION': continue
            u=e.get('url',''); pu=urlparse(u)
            if pu.netloc not in allowed_hosts: continue
            if re.search(r'/(?:tur|genre|category|kategori|dil|ulke|kanal)/[^/]+/?$',pu.path,re.I):
                name=pu.path.strip('/').split('/')[-1].replace('-',' ').title()
                catmap.setdefault(u,{'name':name,'url':u,'evidence':'manual_navigation_taxonomy'})
        cats=list(catmap.values())

        # SERIES: collect episode-shaped URLs and group them by series root/slug.
        def episode_info(u):
            clean=(u or '').split('?')[0]
            pu=urlparse(clean); path=pu.path
            # WordPress-style episode permalink: /bolum/series-slug-4-sezon-8-bolum/
            # Map it back to the canonical series page instead of treating every episode as a separate root.
            wp=re.search(r'/(?:bolum|bölüm)/(.+?)-(\d+)-(?:sezon|season)-(\d+)-(?:bolum|bölüm|episode|ep)/?$',path,re.I)
            if wp:
                slug=wp.group(1).strip('/-'); season=int(wp.group(2)); episode=int(wp.group(3))
                root=f'{pu.scheme}://{pu.netloc}/dizi/{slug}/'
                return season,episode,root
            mm=re.search(r'(?:sezon|season)[-_ /]?(\d+).*?(?:bolum|bölüm|episode|ep)[-_ /]?(\d+)',clean,re.I)
            if not mm: return None
            season=int(mm.group(1)); episode=int(mm.group(2))
            root=re.split(r'/(?:sezon|season)[-_ /]?\d+',clean,1,flags=re.I)[0].rstrip('/')+'/'
            return season,episode,root
        epmap={}
        for x in self.observed_episodes:
            info=episode_info(x.get('url',''))
            if info:
                s,e,root=info; y=dict(x); y['series_root']=root; epmap[(root,s,e,y['url'])]=y
        candidates=[]
        for n in clean_net: candidates.append((n.get('url',''),'manual_request'))
        for e in self.events:
            if e.get('type')=='NAVIGATION': candidates.append((e.get('url',''),'manual_navigation'))
        for u,ev in candidates:
            info=episode_info(u)
            if not info: continue
            s,e,root=info; clean=u.split('?')[0]
            epmap[(root,s,e,clean)]={'season':s,'episode':e,'url':clean,'series_root':root,'evidence':ev}
        eps=sorted(epmap.values(),key=lambda x:(x.get('series_root',''),x['season'],x['episode'],x['url']))
        groups={}
        for x in eps:
            g=groups.setdefault(x['series_root'],{'series_root':x['series_root'],'seasons':{},'episode_count':0})
            g['seasons'].setdefault(str(x['season']),[]).append(x); g['episode_count']+=1
        series_groups=[]
        for root,g in groups.items():
            g['season_numbers']=sorted(int(k) for k in g['seasons']); series_groups.append(g)
        # V6.6 UI-driven series evidence. This handles sites such as JetFilm where
        # season/episode buttons change data/player state without changing the URL.
        def series_page_root(u):
            pu=urlparse(u or '')
            if re.search(r'/(?:dizi|series|tv)/[^/]+/?$',pu.path,re.I):
                return pu._replace(query='',fragment='').geturl().rstrip('/')+'/'
            return ''
        ui_groups={}
        current_root=''; active_season={}
        # First learn all visible controls per series page.
        for st in self.series_ui:
            root=series_page_root(st.get('url',''))
            if not root: continue
            g=ui_groups.setdefault(root,{'series_root':root,'available_seasons':set(),'available_episodes':{},'clicked_episodes':[],'click_mechanisms':[]})
            for c in st.get('controls',[]):
                txt=(c.get('text') or '').strip()
                m=re.match(r'^(?:sezon|season)\s*(\d+)$',txt,re.I)
                if m: g['available_seasons'].add(int(m.group(1))); continue
                m=re.match(r'^E\s*(\d+)$',txt,re.I) or re.match(r'^(?:bölüm|bolum|episode|ep)\s*(\d+)$',txt,re.I)
                if m:
                    ctx=str(c.get('season_context') or '').strip()
                    # DOM container evidence wins. Otherwise only visible episode controls
                    # are assigned to a single visible/known season; hidden duplicate tabs
                    # are not dumped into an 'unknown' bucket.
                    if ctx.isdigit(): g['available_episodes'].setdefault(ctx,set()).add(int(m.group(1)))
                    elif c.get('visible'): g['available_episodes'].setdefault('visible_unbound',set()).add(int(m.group(1)))
        # Then replay the user's actual actions in time order to bind E# to active season.
        for ev in sorted(self.events,key=lambda x:x.get('t',0)):
            if ev.get('type')=='NAVIGATION':
                rr=series_page_root(ev.get('url',''))
                if rr: current_root=rr
                continue
            if ev.get('type')!='SERIES_UI_CLICK': continue
            rr=series_page_root(ev.get('url','')) or current_root
            if not rr: continue
            current_root=rr; g=ui_groups.setdefault(rr,{'series_root':rr,'available_seasons':set(),'available_episodes':{},'clicked_episodes':[],'click_mechanisms':[]})
            txt=(ev.get('text') or '').strip()
            sm=re.match(r'^(?:sezon|season)\s*(\d+)$',txt,re.I)
            if sm:
                active_season[rr]=int(sm.group(1)); g['available_seasons'].add(active_season[rr]); continue
            em=re.match(r'^E\s*(\d+)$',txt,re.I) or re.match(r'^(?:bölüm|bolum|episode|ep)\s*(\d+)$',txt,re.I)
            if not em: continue
            epno=int(em.group(1)); sno=active_season.get(rr,1)
            # Correlate only same-site document/xhr/fetch immediately after the user's click.
            nearby=[]
            for n in clean_net:
                if ev.get('t',0) <= n.get('t',0) <= ev.get('t',0)+2.5:
                    nu=n.get('url','')
                    if not media_ext.search(nu): nearby.append({'method':n.get('method'),'url':nu,'resource_type':n.get('resource_type'),'post_data':n.get('post_data','')})
            rec={'t':ev.get('t',0),'season':sno,'episode':epno,'label':txt,'page_url':ev.get('url',''),'href':ev.get('href',''),'evidence':'manual_ui_click','network_after_click':nearby[:12]}
            if not any(x['season']==sno and x['episode']==epno for x in g['clicked_episodes']): g['clicked_episodes'].append(rec)
            g['available_episodes'].setdefault(str(sno),set()).add(epno)
        ui_series_groups=[]
        for root,g in ui_groups.items():
            avail={k:sorted(v) for k,v in g['available_episodes'].items()}
            # Bind visible-but-unlabelled controls to seasons actually established by
            # manual clicks. Never emit an 'unknown' season in V6.7.
            if 'visible_unbound' in avail:
                vis=avail.pop('visible_unbound')
                clicked_seasons=sorted(set(x['season'] for x in g['clicked_episodes']))
                targets=clicked_seasons or sorted(g['available_seasons'])
                if len(targets)==1:
                    k=str(targets[0]); avail[k]=sorted(set(avail.get(k,[])+vis))
                elif targets:
                    # The UI exposes the same E-control set per season tab; when multiple
                    # seasons were manually visited, retain the observed set for each visited season.
                    for sn in targets:
                        k=str(sn); avail[k]=sorted(set(avail.get(k,[])+vis))
            ui_series_groups.append({'series_root':root,'available_seasons':sorted(g['available_seasons']),'available_episodes':avail,
                                     'clicked_episodes':sorted(g['clicked_episodes'],key=lambda x:(x['season'],x['episode'])),
                                     'clicked_episode_count':len(g['clicked_episodes'])})
        # Merge URL-shaped episode groups and UI-driven groups without inventing clicks.
        ui_by_root={x['series_root']:x for x in ui_series_groups}
        for g in series_groups:
            if g['series_root'] in ui_by_root: g['ui']=ui_by_root[g['series_root']]
        detected=bool(eps or ui_series_groups)
        seasons=sorted(set([x['season'] for x in eps]+[s for g in ui_series_groups for s in g['available_seasons']]))
        series={'detected':detected,'seasons':seasons,'episodes':eps,'season_links':[],
                'groups':series_groups,'group_count':len(series_groups),'ui_groups':ui_series_groups,
                'ui_group_count':len(ui_series_groups),'manual_clicked_episode_count':sum(x['clicked_episode_count'] for x in ui_series_groups)}

        # Reusable Kotlin pagination templates, preserving the site's real style.
        templates=[]; seen_tpl=set()
        for x in pagination:
            pu=urlparse(x['url']); path=pu.path; q=dict(parse_qsl(pu.query,keep_blank_values=True))
            tpl=path
            tpl=re.sub(r'/load/page/\d+/', '/load/page/{page}/', tpl, count=1, flags=re.I)
            tpl=re.sub(r'/(page|sayfa)/\d+(?=/|$)', lambda m:'/'+m.group(1)+'/{page}', tpl, count=1, flags=re.I)
            tpl=re.sub(r'/(sayfa|page)-\d+(?=/|$)', lambda m:'/'+m.group(1)+'-{page}', tpl, count=1, flags=re.I)
            if x['style']=='path_numeric_tail': tpl=re.sub(r'/\d+/?$', '/{page}', tpl, count=1)
            if x['style']=='query':
                for k in ('page','paged','p','currentPage','currentpage'):
                    if k in q and str(q[k]).isdigit(): q[k]='{page}'; break
                from urllib.parse import urlencode
                qs=urlencode(q)
                tpl=path+('?' + qs if qs else '')
                tpl=tpl.replace('%7Bpage%7D','{page}')
            key=(x['family'],tpl)
            if key in seen_tpl: continue
            seen_tpl.add(key); templates.append({'family':x['family'],'style':x['style'],'template':tpl,'example':x['url'],'verified':True})

        # V6.8.3 bidirectional nearest consume-once correlated structural player/embed report.
        # Passive only: associate player evidence with the content/episode the user actually opened.
        player_records=[]; seen_player=set()
        player_noise_hosts=('youtube.com','youtu.be','google.com','gstatic.com','recaptcha.net','yandex.ru','yandex.com','mc.yandex.ru','wargamings.net','doubleclick.net','googletagmanager.com','google-analytics.com')
        def is_media_url(u): return bool(media_ext.search(u or ''))
        def is_player_noise(u):
            h=(urlparse(u or '').netloc or '').lower()
            return any(h==x or h.endswith('.'+x) or x in h for x in player_noise_hosts)
        def content_kind(u):
            p=urlparse(u or '').path.lower()
            if re.search(r'/(?:dizi|series|tv)/[^/]+/?$',p): return 'series'
            if re.search(r'/(?:bolum|bölüm)/[^/]+/?$',p) and episode_info(u): return 'series'
            if re.search(r'/(?:film|movie)/[^/]+/?$',p): return 'movie'
            return 'unknown'
        def canonical_content(u):
            info=episode_info(u)
            return info[2].rstrip('/') if info else (u or '').rstrip('/')
        def content_page(u): return content_kind(u)!='unknown'
        def player_shaped(u):
            pu=urlparse(u or ''); blob=(pu.path+'?'+pu.query).lower()
            return bool(re.search(r'(?:^|/)(?:embed|player|watch|video|jetplayer)(?:/|$)|(?:embed|player|jetplayer)',blob,re.I))
        def nearest_content(t,window=12.0):
            cand=[]
            for e in self.events:
                if e.get('type')=='NAVIGATION' and content_page(e.get('url','')) and e.get('t',0)<=t and t-e.get('t',0)<=window:
                    cand.append(e)
            return cand[-1].get('url','') if cand else ''
        # Manual episode clicks are the strongest series context.
        episode_clicks=[]
        for g in ui_series_groups:
            for x in g.get('clicked_episodes',[]):
                episode_clicks.append({'t':x.get('t',0),'series_root':g.get('series_root',''),'season':x.get('season'),'episode':x.get('episode'),'label':x.get('label',''),'consumed':False})
        episode_clicks.sort(key=lambda x:x.get('t',0))
        def nearest_episode(t,window=0.30,consume=False,series_root=''):
            # V6.8.3: browser/CDP can report the player fetch a few milliseconds BEFORE
            # the DOM click observer. Match bidirectionally in a deliberately narrow window.
            c=[]
            for x in episode_clicks:
                if consume and x.get('consumed'): continue
                if series_root and x.get('series_root','').rstrip('/') != series_root.rstrip('/'): continue
                dt=abs(float(x.get('t',0))-float(t or 0))
                if dt<=window: c.append((dt,x.get('t',0),x))
            if not c: return None
            c.sort(key=lambda z:(z[0],z[1]))
            hit=c[0][2]
            if consume: hit['consumed']=True
            return hit
        def add_player(content_url,embed_url,source,t=0,extra=None):
            if not embed_url or is_media_url(embed_url) or is_player_noise(embed_url): return
            ep=urlparse(embed_url); cp=urlparse(content_url or '')
            if not ep.scheme.startswith('http'): return
            # External visible frames are useful player evidence; same-site frames must look player-shaped.
            if ep.netloc==cp.netloc and not player_shaped(embed_url): return
            if not content_page(content_url): return
            original_content_url=content_url
            einfo=episode_info(original_content_url)
            content_url=canonical_content(content_url)
            key=(content_url,embed_url,source)
            if key in seen_player:return
            seen_player.add(key)
            rec={'t':t,'content_url':content_url,'content_kind':content_kind(content_url),'embed_url':embed_url,
                 'player_host':ep.netloc,'source':source,'verified':True}
            if einfo: rec['episode_context']={'season':einfo[0],'episode':einfo[1],'label':f'S{einfo[0]}E{einfo[1]}'}
            if extra: rec.update(extra)
            player_records.append(rec)
        for st in self.player_ui:
            cu=st.get('url','')
            if not content_page(cu): continue
            for fr in st.get('frames',[]):
                # Hidden stale iframes are not considered verified player evidence.
                if not fr.get('visible',False): continue
                add_player(cu,fr.get('url',''),'dom_iframe_embed',st.get('t',0),
                           {'tag':fr.get('tag',''),'visible':True,'title':fr.get('title','')})
        for fr in self.frame_events:
            t=fr.get('t',0); cu=fr.get('page_url','')
            # Reject stale frame navigations after the main page has already moved to a listing/taxonomy page.
            if not content_page(cu): cu=nearest_content(t,4.0)
            add_player(cu,fr.get('url',''),'frame_navigation',t,{'frame_name':fr.get('name','')})
        player_requests=[]; seen_pr=set()
        for n in clean_net:
            if is_media_url(n.get('url','')) or is_player_noise(n.get('url','')): continue
            if not player_shaped(n.get('url','')): continue
            # Player APIs are normally xhr/fetch/post. A generic document navigation is too noisy.
            if n.get('resource_type')=='document' and n.get('method','GET').upper()=='GET': continue
            sig=(n.get('method'),n.get('url'),n.get('post_data',''))
            if sig in seen_pr: continue
            seen_pr.add(sig)
            t=n.get('t',0); cu=nearest_content(t,12.0); epctx=None
            # First resolve the content page, then consume only a click from that same series.
            if content_kind(cu)=='series': epctx=nearest_episode(t,window=0.30,consume=True,series_root=cu)
            if epctx: cu=epctx.get('series_root','').rstrip('/')
            if not cu: continue
            rec={**n,'verified':True,'source':'manual_player_network','content_url':cu,'content_kind':content_kind(cu)}
            if epctx: rec['episode_context']={'season':epctx['season'],'episode':epctx['episode'],'label':epctx['label']}
            player_requests.append(rec)
        # Correlated chains: content/episode -> player request -> iframe/embed observed immediately after it.
        chains=[]; seen_chain=set()
        evidence=sorted(player_requests,key=lambda x:x.get('t',0))
        embeds=sorted(player_records,key=lambda x:x.get('t',0))
        for pr in evidence:
            after=[e for e in embeds if pr.get('t',0)-0.5 <= e.get('t',0) <= pr.get('t',0)+5.0 and e.get('content_url')==pr.get('content_url')]
            # V6.8.2: the player request owns the consumed episode context; embeds inherit it through this chain.
            for em in after[:8]:
                key=(pr.get('content_url'),json.dumps(pr.get('episode_context',{}),sort_keys=True),pr.get('method'),pr.get('url'),pr.get('post_data',''),em.get('embed_url'))
                if key in seen_chain: continue
                seen_chain.add(key)
                chains.append({'content_url':pr.get('content_url'),'content_kind':pr.get('content_kind'),'episode_context':pr.get('episode_context'),
                               'trigger':{'method':pr.get('method'),'url':pr.get('url'),'resource_type':pr.get('resource_type'),'post_data':pr.get('post_data','')},
                               'embed_url':em.get('embed_url'),'player_host':em.get('player_host'),'verified':True,'evidence':'time_and_content_correlated'})
        # Direct-iframe sites may have no XHR/player API at all. Preserve a structural chain
        # from the content/episode page to the observed iframe instead of declaring correlation missing.
        request_chain_contents={x.get('content_url') for x in chains}
        for em in embeds:
            cu=em.get('content_url',''); epctx=em.get('episode_context')
            key=(cu,json.dumps(epctx or {},sort_keys=True),'DIRECT_IFRAME',em.get('embed_url'))
            if key in seen_chain: continue
            seen_chain.add(key)
            chains.append({'content_url':cu,'content_kind':em.get('content_kind'),'episode_context':epctx,
                           'trigger':{'method':'DOM/FRAME','url':cu,'resource_type':'iframe','post_data':''},
                           'embed_url':em.get('embed_url'),'player_host':em.get('player_host'),'verified':True,
                           'evidence':'direct_iframe_structural_correlation'})

        playback_proofs=[]
        for pr in self.playback_proofs:
            cu=canonical_content(pr.get('content_url',''))
            playback_proofs.append({**pr,'content_url':cu})
        player_data={'detected':bool(player_records or player_requests),'embeds':player_records,'embed_count':len(player_records),
                     'requests':player_requests,'request_count':len(player_requests),'chains':chains,'chain_count':len(chains),
                     'playback_proofs':playback_proofs,'playback_proof_count':len(playback_proofs),'playback_verified':bool(playback_proofs),
                     'direct_media_urls_recorded':False,'noise_filtered':True,'stale_frame_guard':True,'episode_correlation':True,'episode_click_consume_once':True,
                     'episode_match_mode':'BIDIRECTIONAL_NEAREST_0_30S_CONSUME_ONCE',
                     'capture_scope':'CORRELATED_STRUCTURAL_IFRAME_EMBED_AND_PLAYER_REQUEST_METADATA_ONLY'}
        series_player_requests=[x for x in player_requests if x.get('content_kind')=='series']
        correlated_series_requests=[x for x in series_player_requests if x.get('episode_context')]
        series_clicks_present=bool(episode_clicks)
        direct_series_chains=[x for x in chains if x.get('content_kind')=='series' and x.get('evidence')=='direct_iframe_structural_correlation']
        series_correlation_ok=(not series_clicks_present) or (bool(correlated_series_requests) and all(x.get('episode_context') for x in series_player_requests)) or bool(direct_series_chains)
        player_data['series_request_count']=len(series_player_requests)
        player_data['series_correlated_request_count']=len(correlated_series_requests)
        player_data['unmatched_episode_click_count']=sum(1 for x in episode_clicks if not x.get('consumed'))
        player_data['ready']={'player_structure':bool(player_records or player_requests),
                              'player_correlation':bool(chains or player_requests) and series_correlation_ok}
        player_data['missing']=[k for k,v in player_data['ready'].items() if not v]
        player_data['status']='PLAYER_CORRELATED_READY' if not player_data['missing'] else ('PLAYER_STRUCTURE_READY' if player_data['ready']['player_structure'] else 'PLAYER_STRUCTURE_NOT_CAPTURED')

        repo_data={
            'base_url':final_origin or f'{urlparse(self.url).scheme}://{urlparse(self.url).netloc}',
            'start_url':self.url,'final_url':final_url,'redirected':bool(final_origin and final_origin != f'{urlparse(self.url).scheme}://{urlparse(self.url).netloc}'),
            'catalog':{'count':len(cards),'poster_count':sum(bool(x.get('poster')) for x in cards),'items':cards},
            'categories':cats,
            'search':{'verified':bool(search),'mechanisms':search},
            'pagination':{'verified':bool(pagination),'mechanisms':pagination,'templates':templates},
            'series':series,
            'player':player_data,
            'ignored_noise':{'analytics':True,'cloudflare_rum':True,'popover':True,'media_segments':True,'visitor_tracking':True},
            'ready':{'main_page':bool(cards),'posters':bool(cards) and all(bool(x.get('poster')) for x in cards),
                     'search':bool(search),'pagination':bool(pagination),'series_episodes':bool(eps or any(g.get('clicked_episode_count',0) for g in ui_series_groups))}
        }
        missing=[k for k,v in repo_data['ready'].items() if not v]
        repo_data['missing']=missing
        repo_data['status']='READY_FROM_CAPTURE' if not missing else 'PARTIAL_FROM_CAPTURE'
        return {'mode':'MANUAL_LISTEN_ONLY','status':'CAPTURED','url':self.url,'final_url':final_url,
            'runtime':{'available':True,'mode':'MANUAL_LISTEN_ONLY','error':'','duration_seconds':round(time.time()-self.started,1)},
            'catalog':repo_data['catalog'],'categories':cats,'search':search,'pagination':pagination,'series':series,'player':player_data,
            'PLAYER_REPO_DATA':player_data,'CLOUDSTREAM_REPO_DATA':repo_data,'manual_timeline':self.events,'observed_requests':self.net,
            'cloudstream_ready':repo_data['ready']}
    def _force_finalize_from_capture(self):
        """Finalize only from evidence already captured. Never touch Playwright/CDP here."""
        if self.result is not None:
            self.status='done'; self.done_evt.set(); return self.result
        a=RepoAnalyzer()
        final_html=self.last_html or ''
        final_url=self.last_url or self.url
        try:
            result=self._build_result(a,final_html,final_url)
        except Exception as e:
            self.error='FORCE_FINALIZE '+type(e).__name__+': '+str(e)
            result={'mode':'MANUAL_LISTEN_ONLY','status':'CAPTURED','url':self.url,'final_url':final_url,
                'error':self.error,'manual_timeline':list(self.events),'observed_requests':list(self.net),
                'snapshots':list(self.snapshots),'CLOUDSTREAM_REPO_DATA':{'status':'PARTIAL_FROM_CAPTURE','missing':['final_enrichment']}}
        self.result=result
        self.status='done'
        self.done_evt.set()
        return result

    def stop(self, wait_seconds=0.25):
        # V79: STOP must not depend on the observer thread returning from Playwright/CDP.
        # Signal it, allow a tiny grace period, then finalize from already captured evidence
        # on the HTTP handler thread. This guarantees a bounded stop and a real TXT result.
        if self.status in ('done','error') and self.result is not None:
            return self.result
        self.status='stopping'
        self.stop_evt.set()
        self.done_evt.wait(max(0.0, min(float(wait_seconds), 0.5)))
        if self.result is not None:
            self.status='done'; self.done_evt.set(); return self.result
        return self._force_finalize_from_capture()

def start(url):
    s=ManualSession(url)
    with LOCK:SESSIONS[s.id]=s
    return s

def get(sid):
    with LOCK:return SESSIONS.get(sid)
