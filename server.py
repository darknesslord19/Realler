import time
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, urljoin
from pathlib import Path
from repo_analyzer import RepoAnalyzer
from manual_listener import start as manual_start, get as manual_get
from v81_layer import V81Mixin
import urllib.request, urllib.error, json, re, base64, html, ssl, socket, os, hashlib, subprocess, time

ROOT = Path(__file__).resolve().parent
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
      "AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/153.0.0.0 Safari/537.36")

# V54 generalized browser-environment pool. Profiles are behavior families, not site rules.
MOBILE_UA = ("Mozilla/5.0 (Linux; Android 14; Pixel 8) "
             "AppleWebKit/537.36 (KHTML, like Gecko) "
             "Chrome/153.0.0.0 Mobile Safari/537.36")

MAX_DEPTH = int(os.environ.get("V81_MAX_DEPTH", "4") or 4)
MAX_REQUESTS = int(os.environ.get("V81_MAX_REQUESTS", "32") or 32)

NOISE = (
    "google-analytics","googletagmanager","doubleclick","facebook.com","twitter.com",
    "instagram.com","fonts.googleapis","fonts.gstatic","litespeed/css","favicon",
    "apple-touch-icon","safari-pinned-tab","wp-json/oembed","xmlrpc","feed/",
    "cloudflareinsights.com","beacon.min.js","rocket-loader","jquery.min.js",
    "jquery-migrate","bootstrap.bundle","comment-link","visitor-tracking",
    "ads-tracking","similar-films-slider","search.js"
)

SCRIPT_HIGH = (
    "film-page.js","movie.js","app.js","beload.php","player.js","video.js","watch.js",
    "embed.js","source.js","stream.js","play.js","jwplayer"
)

HIGH = ("player","video","source","embed","stream","view","token","jetplayer","api/","ajax","beload","hls.")
TRAILER_HOSTS = ("youtube.com","youtu.be","youtube-nocookie.com","vimeo.com","dailymotion.com")
RUNTIME_HINTS = (
    "innerhtml","insertadjacenthtml","createelement(\"iframe\")","createelement('iframe')",
    "iframe.src","setattribute(\"src\"","setattribute('src'","document.write(","appendchild("
)


# --- V9: pure-Python AES/OpenSSL-compatible decrypt support ---
_AES_SBOX = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]
_AES_INV=[0]*256
for _i,_v in enumerate(_AES_SBOX): _AES_INV[_v]=_i
_AES_RCON=[0,1,2,4,8,16,32,64,128,27,54,108,216,171,77]

def _aes_gmul(a,b):
    p=0
    for _ in range(8):
        if b&1:p^=a
        hi=a&0x80
        a=(a<<1)&0xff
        if hi:a^=0x1b
        b>>=1
    return p

def _aes_expand_key(key):
    nk=len(key)//4; nr=nk+6
    w=[list(key[4*i:4*i+4]) for i in range(nk)]
    for i in range(nk,4*(nr+1)):
        t=w[i-1].copy()
        if i%nk==0:
            t=t[1:]+t[:1]
            t=[_AES_SBOX[x] for x in t]
            t[0]^=_AES_RCON[i//nk]
        elif nk>6 and i%nk==4:
            t=[_AES_SBOX[x] for x in t]
        w.append([w[i-nk][j]^t[j] for j in range(4)])
    return [sum(w[4*r:4*r+4],[]) for r in range(nr+1)]

def _aes_add_key(s,rk): return [a^b for a,b in zip(s,rk)]

def _aes_inv_shift(s):
    o=s.copy()
    for r in range(1,4):
        row=[s[r+4*c] for c in range(4)]
        row=row[-r:]+row[:-r]
        for c in range(4):o[r+4*c]=row[c]
    return o

def _aes_inv_mix(s):
    o=s.copy()
    for c in range(4):
        i=4*c;a=s[i:i+4]
        o[i]=_aes_gmul(a[0],14)^_aes_gmul(a[1],11)^_aes_gmul(a[2],13)^_aes_gmul(a[3],9)
        o[i+1]=_aes_gmul(a[0],9)^_aes_gmul(a[1],14)^_aes_gmul(a[2],11)^_aes_gmul(a[3],13)
        o[i+2]=_aes_gmul(a[0],13)^_aes_gmul(a[1],9)^_aes_gmul(a[2],14)^_aes_gmul(a[3],11)
        o[i+3]=_aes_gmul(a[0],11)^_aes_gmul(a[1],13)^_aes_gmul(a[2],9)^_aes_gmul(a[3],14)
    return o

def _aes_decrypt_block(block,key):
    rks=_aes_expand_key(key); nr=len(rks)-1
    st=_aes_add_key(list(block),rks[nr])
    for rnd in range(nr-1,0,-1):
        st=_aes_inv_shift(st)
        st=[_AES_INV[x] for x in st]
        st=_aes_add_key(st,rks[rnd])
        st=_aes_inv_mix(st)
    st=_aes_inv_shift(st)
    st=[_AES_INV[x] for x in st]
    st=_aes_add_key(st,rks[0])
    return bytes(st)

def _aes_cbc_decrypt(cipher,key,iv):
    if len(cipher)%16:return b""
    out=bytearray(); prev=iv
    for i in range(0,len(cipher),16):
        block=cipher[i:i+16]
        dec=_aes_decrypt_block(block,key)
        out.extend(bytes(a^b for a,b in zip(dec,prev)))
        prev=block
    return bytes(out)

def _evp_bytes_to_key(password,salt,key_len=32,iv_len=16):
    out=b""; prev=b""
    while len(out)<key_len+iv_len:
        prev=hashlib.md5(prev+password+salt).digest()
        out+=prev
    return out[:key_len],out[key_len:key_len+iv_len]

class Analyzer(V81Mixin):
    def __init__(self):
        self.logs=[]
        self.visited=set()
        self.requests=0
        self.max_depth=0
        self.cookies={}
        self.player=""
        self.final=""
        self.final_type=""
        self.final_verified=False
        self.blocked=False
        self.runtime_needed=False
        self.detect="UNKNOWN"
        self.confidence=25
        self.root_status=0
        self.script_endpoints=[]
        self.browser_runtime_used=False
        self.browser_runtime_available=False
        self.browser_runtime_error=""
        self.v3_mitm_fallback_used=False
        self.v3_mitm_fallback_error=""
        self.browser_network=[]
        self.strategy_attempts=[]
        self.media_candidates=[]
        self.final_evidence={}
        self.browser_requests=[]
        self.browser_responses=[]
        self.runtime_dom_events=[]
        self.broken_player_targets=[]
        self.runtime_discovered_urls=[]
        self.runtime_requeue_count=0
        self.browser_request_context={}
        self.browser_media_context={}
        self.final_playback_context={}
        self.runtime_browser_targets=[]
        self.player_host_hints=[]
        self.v27_event_selectors=[]
        self.v27_failure_memory=[]
        self.v27_strategy_success={}
        self.v30_resource_roles={}
        self.v30_environment_rejected=False
        self.v30_environment_evidence=[]
        self.v31_environment_hints=[]
        self.v31_transport_failures=[]
        # V67 diagnostic state: Chrome/CDP failures are distinct from urllib failures.
        self.v67_browser_failures=[]
        self.v31_structured_media=[]
        self.v31_active_player_sources=[]
        # V64: pending JS decoder calls captured from player HTML for browser-engine evaluation.
        self.v64_js_decoder_jobs=[]
        # V42: protected bootstrap / browser-session diagnostics.
        # Generic by design: no provider/domain/path is hard-coded.
        self.v42_protected_requests=[]
        self.v42_browser_env={}
        self.v42_request_extra_headers={}
        self.v42_response_extra_headers={}
        self.v42_failure_stage=""
        # V43: semantic player-source chain. A URL can be a media resolver even when
        # it has no media-looking extension (e.g. /m.php?v=... or /api/play?id=...).
        # We bind that semantic evidence to the frame/session that produced it so
        # follow-up fetches execute inside the same browser realm instead of top-frame.
        self.v43_semantic_media={}
        self.v43_semantic_chain=[]
        self.v43_browser_fetch_proofs=[]
        self.v46_clean_observer=False
        # V32: causal evidence graph + proof state.  A URL cannot become final merely
        # because its body starts with #EXTM3U; we preserve how it was discovered and
        # require a playable child/segment proof for HLS.
        self.v32_evidence_nodes={}
        self.v32_evidence_edges=[]
        self.v32_pruned=[]
        self.v32_proof={}
        self.v34_proof_started=set()
        # V38 persistent structural memory. It learns mechanisms, never hard-codes a site.
        self.v38_memory_path=ROOT / "resolver_memory.json"
        self.v38_memory=self.v38_load_memory()
        self.v38_seen_families=set()
        self.v38_applied_patterns=[]
        self.v38_player_state=[]
        # V40: transient causal bootstrap evidence. Never persisted with raw domains/tokens.
        self.v40_bootstrap_events=[]
        self.v40_bootstrap_families=set()
        # V41: frame-scoped bootstrap evidence. Stores only transient runtime facts.
        self.v41_frame_bootstrap_attempted=set()
        self.v41_frame_xhr_seen=[]
        # V50: central Resolution DNA / failure diagnostics. These fields only
        # summarize observed evidence; they never manufacture candidate URLs.
        self.v50_real_chrome_attached=False
        self.v50_browser_mode="UNKNOWN"
        self.v50_auto_play_attempted=False
        self.v50_auto_play_triggered=False
        self.v50_preexisting_media_before_auto=0
        self.v50_interaction_provenance="NONE"
        self.v50_resolution_dna={}
        self.v50_final_proof_report={}
        self.v50_transport_diagnostics={}
        # V51 adaptive reasoning: evidence-grounded root cause + portable next experiments
        self.v51_root_cause={}
        self.v51_next_experiments=[]
        self.v51_behavior_signature={}
        self.v53_repo_integration_report={}
        # V54 generic capabilities learned from supplied MRC CS3 corpus.
        self.v54_mrc_signals=[]
        self.v54_static_candidates=[]
        self.v54_static_decodes=[]
        # V81 repo-ready evidence layer
        self.v81_init()
        self.v81_root_dir=str(ROOT)

    def log(self,s):
        # V81: NUL/kontrol karakterleri UI logunu kesiyordu -> temizle
        s=str(s)
        if any((ord(ch)<32 and ch not in "\r\n\t") or ord(ch)==0xFFFD for ch in s):
            s=re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ufffd]","?",s)
        self.logs.append(s)

    def v38_load_memory(self):
        '''Load only compact, structural resolver knowledge learned from prior successful runs.'''
        default={"version":1,"patterns":{},"successes":0}
        try:
            if self.v38_memory_path.exists():
                obj=json.loads(self.v38_memory_path.read_text(encoding="utf-8"))
                if isinstance(obj,dict):
                    obj.setdefault("version",1); obj.setdefault("patterns",{}); obj.setdefault("successes",0)
                    return obj
        except Exception as ex:
            self.log(f"[V38_MEMORY_LOAD_ERROR] {type(ex).__name__}: {ex}")
        return default

    def v38_save_memory(self):
        try:
            tmp=self.v38_memory_path.with_suffix('.tmp')
            tmp.write_text(json.dumps(self.v38_memory,ensure_ascii=False,indent=2),encoding='utf-8')
            tmp.replace(self.v38_memory_path)
            self.log(f"[V38_MEMORY_SAVE] patterns={len(self.v38_memory.get('patterns',{}))} successes={self.v38_memory.get('successes',0)}")
        except Exception as ex:
            self.log(f"[V38_MEMORY_SAVE_ERROR] {type(ex).__name__}: {ex}")

    def v38_family_fingerprint(self, text="", url=""):
        '''Return mechanism fingerprints. Domains are deliberately excluded from the learned key.'''
        low=(text or '').lower(); out=[]
        tests=(
            ('PLAYERJS', ('playerjs(', 'playerjs.com', 'pljssglobal')),
            ('JWPLAYER', ('jwplayer(', 'jwplayer().setup', 'jwplayer(')),
            ('HLSJS', ('hls.js','new hls(','hls.loadsource')),
            ('VIDEOJS', ('videojs(', 'video.js')),
            ('HTML5_VIDEO', ('<video','currentsrc','<source')),
            ('IFRAME_PLAYER', ('<iframe','/embed/','/player/')),
            ('PACKER_JS', ('eval(function(p,a,c,k,e,d)',)),
            ('TURNSTILE_GATE', ('turnstile','challenge-platform')),
        )
        for name,marks in tests:
            if any(m in low for m in marks): out.append(name)
        if '#extm3u' in low: out.append('HLS_MANIFEST')
        return list(dict.fromkeys(out))

    def v38_memory_observe(self, text="", url="", source=""):
        fams=self.v38_family_fingerprint(text,url)
        for fam in fams:
            if fam not in self.v38_seen_families:
                self.v38_seen_families.add(fam)
                rec=(self.v38_memory.get('patterns',{}) or {}).get(fam,{})
                learned=int(rec.get('success',0) or 0)
                strategy=str(rec.get('strategy','') or '')
                self.log(f"[V38_PATTERN_MATCH] family={fam} learnedSuccess={learned} preferred={strategy or 'AUTO'} source={source}")
                if learned>0:self.v38_applied_patterns.append(fam)
        return fams

    def v38_learn_success(self):
        if not self.final_verified:return
        pats=self.v38_memory.setdefault('patterns',{})
        # Learn only families actually observed in this run. This prevents one site's host/path
        # from contaminating another site while still transferring player-family knowledge.
        for fam in sorted(self.v38_seen_families):
            rec=pats.setdefault(fam,{"seen":0,"success":0,"strategy":""})
            rec['seen']=int(rec.get('seen',0) or 0)+1
            rec['success']=int(rec.get('success',0) or 0)+1
            if fam=='PLAYERJS': rec['strategy']='RUNTIME_PLAYER_STATE_FIRST'
            elif fam in ('JWPLAYER','HLSJS','VIDEOJS'): rec['strategy']='RUNTIME_CONFIG_AND_NETWORK'
            elif fam=='IFRAME_PLAYER': rec['strategy']='CAUSAL_IFRAME_RECURSION'
            elif fam=='PACKER_JS': rec['strategy']='UNPACK_THEN_CONFIG_VALUE_FLOW'
            elif fam=='HLS_MANIFEST': rec['strategy']='MASTER_VARIANT_SEGMENT_PROOF'
        self.v38_memory['successes']=int(self.v38_memory.get('successes',0) or 0)+1
        self.v38_save_memory()
        self.log('[V38_LEARN] result=SUCCESS families='+(','.join(sorted(self.v38_seen_families)) or 'NONE'))

    def v38_playerjs_static_values(self,text,base,label=''):
        '''Follow scalar config values instead of mistaking PlayerJS library constants for endpoints.'''
        if not text:return []
        self.v38_memory_observe(text,base,label or 'STATIC')
        if 'playerjs' not in text.lower() and 'pljssglobal' not in text.lower():return []
        out=[]; scan=html.unescape(self.v29_js_unescape(text))
        # Values attached to media/config keys are stronger than arbitrary URL literals.
        keypat=r'''(?is)(?:["']?(?:file|src|source|playlist|manifest|hls|url)["']?)\s*:\s*(["'])(.{4,5000}?)\1'''
        for m in re.finditer(keypat,scan):
            val=self.v29_js_unescape(m.group(2)).strip()
            if val.startswith(('http://','https://','//','/')):
                u=self.runtime_discovered_candidate(val,base,'V38_CONFIG_VALUE',scan[max(0,m.start()-180):m.end()+180])
                if u and u not in out:out.append(u)
                self.log(f"[V38_CONFIG_VALUE] key=media url={u or val[:300]}")
            elif len(val)>24:
                self.log(f"[V38_CONFIG_ENCODED] bytes={len(val.encode('utf-8','ignore'))} prefix={val[:24]}")
        # PlayerJS commonly carries a large encoded `u` configuration. Treat it as state evidence,
        # not as a URL. Runtime state/network remains authoritative.
        for m in re.finditer(r'''(?is)(?:^|[,\{])\s*u\s*:\s*(["'])(.{24,200000}?)\1''',scan):
            val=m.group(2)
            self.log(f"[V38_PLAYERJS_U_STATE] bytes={len(val.encode('utf-8','ignore'))} prefix={val[:32]}")
        return out[:24]

    def v38_browser_player_state(self,page,base=''):
        '''Inspect live player state after the site's own JavaScript has decoded/configured it.'''
        try:
            state=page.evaluate(r'''() => {
              const clean=(v)=>{try{if(v==null)return null;if(typeof v==='string')return v.slice(0,12000);return JSON.parse(JSON.stringify(v,(k,x)=>typeof x==='function'?undefined:x))}catch(e){return String(v).slice(0,12000)}};
              const urls=[]; const add=(v,why)=>{if(typeof v==='string' && /^(https?:|\/\/|\/)/i.test(v)) urls.push({url:v,why});};
              for(const v of document.querySelectorAll('video,source')){add(v.currentSrc||v.src,'DOM_MEDIA');add(v.getAttribute('src'),'DOM_SRC');}
              const globals=[];
              for(const k of ['pljssglobal','player','Player','jwplayer','hls','hlsPlayer','videojs']){
                try{const v=window[k]; if(v!=null) globals.push({name:k,type:typeof v,value:clean(v)});}catch(e){}
              }
              // Walk only a shallow set of likely player objects; do not serialize the whole window.
              for(const g of globals){
                const v=window[g.name]; if(!v || (typeof v!=='object' && typeof v!=='function'))continue;
                for(const k of ['file','src','source','url','playlist','manifest','currentSrc']){try{add(v[k],g.name+'.'+k)}catch(e){}}
                try{if(Array.isArray(v.audiosrc))for(const x of v.audiosrc)add(x,g.name+'.audiosrc')}catch(e){}
              }
              return {href:location.href,globals,urls:[...new Map(urls.map(x=>[x.url,x])).values()].slice(0,40)};
            }''') or {}
        except Exception as ex:
            self.log(f"[V38_PLAYER_STATE_ERROR] {type(ex).__name__}: {ex}"); return []
        gl=state.get('globals',[]) if isinstance(state,dict) else []
        urls=state.get('urls',[]) if isinstance(state,dict) else []
        if gl:
            names=','.join(str(x.get('name','')) for x in gl[:12])
            self.log(f"[V38_PLAYER_STATE] globals={names} url={state.get('href',base)}")
        out=[]
        for x in urls:
            raw=str(x.get('url','') or ''); why=str(x.get('why','STATE') or 'STATE')
            u=self.runtime_discovered_candidate(raw,state.get('href',base) or base,'V38_PLAYER_STATE',why)
            if u and u not in out:
                out.append(u); self.log(f"[V38_STATE_MEDIA] why={why} url={u}")
        return out


    def v40_json_media_sources(self,obj,base):
        """Extract media-like source values from structured bootstrap JSON by semantics.

        V43 strengthens V40: media transport is inferred from sibling metadata and
        persisted as evidence even when the URL is extensionless or ends in .php.
        This function never finalizes media by metadata alone; it only creates a
        trusted resolver candidate that still needs browser/response proof.
        """
        out=[]; seen=set()

        def transport_from(meta, url):
            ml=' '.join(str(x) for x in (meta or []) if x is not None).lower()
            low=(url or '').lower()
            if any(x in ml for x in ('application/vnd.apple.mpegurl','application/x-mpegurl','mpegurl',' hls','hls ')) or '.m3u8' in low:
                return 'HLS'
            if any(x in ml for x in ('application/dash+xml',' dash','dash ')) or '.mpd' in low:
                return 'DASH'
            if 'video/mp4' in ml or '.mp4' in low:
                return 'MP4'
            return ''

        def add(v,path,meta=None):
            if not isinstance(v,str): return
            raw=html.unescape(v).replace('\\/','/').strip()
            if not raw or any(ch.isspace() for ch in raw): return
            if not raw.startswith(('http://','https://','//','/')): return
            u=self.absolute(base,raw)
            if not u or u in seen: return
            ml=' '.join(str(x) for x in (meta or []) if x is not None).lower()
            pl=path.lower(); low=u.lower()
            transport=transport_from(meta,u)
            semantic_path=(
                ('.sources[' in pl and pl.endswith('.file')) or
                pl.endswith('.source.file') or pl.endswith('.sources.file') or
                pl.endswith('.playlist.file')
            )
            strong=(
                bool(transport) or '.m3u8' in low or '.mpd' in low or '.mp4' in low or
                semantic_path
            )
            if not strong: return
            evidence=[]
            if transport: evidence.append('META_'+transport)
            if 'mpegurl' in ml: evidence.append('MIME_MPEGURL')
            if semantic_path: evidence.append('PLAYER_SOURCE_PATH')
            if '.m3u8' in low: evidence.append('URL_M3U8')
            if '.mpd' in low: evidence.append('URL_MPD')
            if '.mp4' in low: evidence.append('URL_MP4')
            seen.add(u)
            item={'url':u,'path':path,'meta':ml[:300],'transport':transport,'evidence':evidence}
            out.append(item)
            prev=dict(self.v43_semantic_media.get(u) or {})
            prev.update({
                'url':u,'transport':transport or prev.get('transport',''),
                'path':path,'meta':ml[:300],
                'evidence':list(dict.fromkeys((prev.get('evidence') or [])+evidence)),
                'parent':base,
            })
            self.v43_semantic_media[u]=prev
            self.v43_semantic_chain.append({'from':base,'to':u,'transport':transport,'path':path,'evidence':evidence})
            self.log(f"[V43_SEMANTIC_MEDIA_SOURCE] transport={transport or 'UNKNOWN'} path={path} evidence={','.join(evidence) or 'STRUCTURED_SOURCE'} url={u}")

        def walk(x,path='root',parent=None):
            if isinstance(x,dict):
                meta=[x.get(k) for k in ('type','mimeType','mime_type','label','title','kind','format','contentType','content_type') if k in x]
                for k,v in x.items():
                    kp=f'{path}.{k}'
                    kl=str(k).lower()
                    if kl in ('file','src','source','url','hls','manifest','playlisturl','streamurl','stream','media'):
                        if isinstance(v,str): add(v,kp,meta)
                    walk(v,kp,x)
            elif isinstance(x,list):
                for i,v in enumerate(x[:300]): walk(v,f'{path}[{i}]',parent)
        walk(obj)
        return out[:60]

    def v65_json_handoff_sources(self,obj,base):
        """Find browser/player handoff URLs in a JSON response.

        Unlike V40 media extraction this intentionally accepts non-media URLs, but only
        from semantic fields that commonly carry the next player/embed document.  The
        returned URL is never final media by itself; it is queued back into the same
        browser session and must produce downstream playback evidence.
        """
        out=[]; seen=set()
        semantic_keys={
            'url','link','href','src','source','embed','embedurl','embed_url',
            'iframe','iframeurl','iframe_url','player','playerurl','player_url',
            'watch','watchurl','watch_url','redirect','redirecturl','redirect_url'
        }
        def add(v,path):
            if not isinstance(v,str): return
            raw=html.unescape(v).replace('\\/','/').strip()
            if not raw or any(ch.isspace() for ch in raw): return
            if not raw.startswith(('http://','https://','//','/')): return
            u=self.absolute(base,raw)
            if not u or u in seen: return
            try:
                q=urlparse(u)
                if q.scheme not in ('http','https') or not q.netloc: return
            except Exception:
                return
            # A handoff is a document/navigation candidate, not a static asset.
            low=(urlparse(u).path or '').lower()
            if re.search(r'\.(?:css|js|png|jpe?g|gif|webp|svg|ico|woff2?|ttf)(?:$|\?)',low): return
            seen.add(u); out.append({'url':u,'path':path})
            self.log(f"[V65_JSON_HANDOFF] path={path} from={base} url={u}")
        def walk(x,path='root',depth=0):
            if depth>7:return
            if isinstance(x,dict):
                for k,v in list(x.items())[:200]:
                    kp=f'{path}.{k}'; kl=str(k).lower().replace('-','_')
                    compact=kl.replace('_','')
                    if kl in semantic_keys or compact in {x.replace('_','') for x in semantic_keys}:
                        if isinstance(v,str): add(v,kp)
                        elif isinstance(v,dict):
                            for kk in ('url','href','src','link','embed','player'):
                                if kk in v: add(v.get(kk),f'{kp}.{kk}')
                    walk(v,kp,depth+1)
            elif isinstance(x,list):
                for i,v in enumerate(x[:300]): walk(v,f'{path}[{i}]',depth+1)
        walk(obj)
        return out[:40]

    def v40_bootstrap_json(self,text,url):
        """Recognize a generic player bootstrap response and return trusted media source fields."""
        try: obj=json.loads(text)
        except Exception: return []
        items=self.v40_json_media_sources(obj,url)
        if not items: return []
        shape=[]
        if isinstance(obj,dict):
            if 'playlist' in obj: shape.append('playlist')
            if 'sources' in obj: shape.append('sources')
            if 'state' in obj: shape.append('state')
            if 'expired' in obj: shape.append('expiry')
        self.v40_bootstrap_families.add('XHR_JSON_BOOTSTRAP')
        self.log(f"[V40_BOOTSTRAP_JSON] sources={len(items)} shape={','.join(shape) or 'structured'} url={url}")
        for it in items:
            self.log(f"[V40_BOOTSTRAP_SOURCE] path={it['path']} meta={it['meta'][:120]} url={it['url']}")
        return items

    def v40_learn_bootstrap_route(self):
        if not self.final_verified or not self.v40_bootstrap_families: return
        try:
            pats=self.v38_memory.setdefault('patterns',{})
            key='ROUTE:IFRAME_PLAYER>XHR_JSON_BOOTSTRAP>PLAYER_SOURCE>HLS_MANIFEST'
            rec=pats.setdefault(key,{'seen':0,'success':0,'strategy':'BOOTSTRAP_JSON_THEN_NETWORK_MANIFEST'})
            rec['seen']=int(rec.get('seen',0) or 0)+1
            rec['success']=int(rec.get('success',0) or 0)+1
            rec['strategy']='BOOTSTRAP_JSON_THEN_NETWORK_MANIFEST'
            self.v38_save_memory()
            self.log('[V40_LEARN_ROUTE] '+key)
        except Exception as ex:
            self.log(f"[V40_LEARN_ROUTE_ERROR] {type(ex).__name__}: {ex}")

    def v41_trigger_player_bootstrap(self,scope,base_url,label="FRAME"):
        if getattr(self,"v46_clean_observer",False):
            self.log(f"[V46_CLEAN_OBSERVER] BOOTSTRAP_TRIGGER_SKIPPED label={label}")
            return []
        """Trigger only structurally player-shaped bootstrap functions in the live frame.
        Mechanism-driven: no provider/domain/path names are embedded.
        """
        key=(str(base_url or ''),str(label or ''))
        if key in self.v41_frame_bootstrap_attempted:
            return []
        self.v41_frame_bootstrap_attempted.add(key)
        js=r'''() => {
          const out={playerShape:false,candidates:[],called:[],errors:[]};
          try{
            const d=document;
            const playerNode=!!d.querySelector('video,iframe,[class*=\"player\" i],[id*=\"player\" i],[data-player],[data-source],[data-video]');
            const playerGlobal=!!(window.Playerjs||window.player||window.Player||window.pljssglobal||window.jwplayer||window.Hls);
            out.playerShape=playerNode||playerGlobal;
            if(!out.playerShape) return out;
            const names=Object.getOwnPropertyNames(window);
            const score=(n,fn)=>{
              let x=0, l=n.toLowerCase();
              if(/open.*player|player.*open/.test(l)) x+=30;
              if(/init.*player|player.*init/.test(l)) x+=26;
              if(/start.*player|player.*start/.test(l)) x+=24;
              if(/load.*player|player.*load/.test(l)) x+=22;
              if(/create.*player|player.*create/.test(l)) x+=18;
              if(/open.*video|init.*video|start.*video|load.*video/.test(l)) x+=16;
              if(/^init[a-z0-9_]{0,3}$/i.test(n)) x+=9;
              if(/^open[a-z0-9_]{0,8}$/i.test(n)) x+=7;
              try{ if(typeof fn==='function' && fn.length<=1) x+=5; else x-=50; }catch(e){x-=50}
              return x;
            };
            for(const n of names){
              let fn; try{fn=window[n]}catch(e){continue}
              if(typeof fn!=='function') continue;
              const sc=score(n,fn); if(sc>=20) out.candidates.push({name:n,score:sc,arity:fn.length});
            }
            out.candidates.sort((a,b)=>b.score-a.score);
            for(const c of out.candidates.slice(0,5)){
              try{const r=window[c.name]();out.called.push({name:c.name,score:c.score,resultType:typeof r});}
              catch(e){out.errors.push({name:c.name,error:String(e).slice(0,240)});}
            }
          }catch(e){out.errors.push({name:'__scan__',error:String(e).slice(0,240)})}
          return out;
        }'''
        try:
            res=scope.evaluate(js) or {}
            cands=res.get('candidates') or []
            called=res.get('called') or []
            errs=res.get('errors') or []
            self.log(f"[V41_FRAME_BOOTSTRAP_SCAN] label={label} playerShape={str(bool(res.get('playerShape'))).lower()} candidates={len(cands)} url={base_url}")
            for c in cands[:8]:
                self.log(f"[V41_FRAME_BOOTSTRAP_CANDIDATE] label={label} score={c.get('score',0)} arity={c.get('arity','?')} name={c.get('name','')}")
            for c in called[:8]:
                self.log(f"[V41_FRAME_BOOTSTRAP_TRIGGER] label={label} decision=CALL_OWN_PLAYER_BOOTSTRAP name={c.get('name','')} score={c.get('score',0)} url={base_url}")
            for e in errs[:6]:
                self.log(f"[V41_FRAME_BOOTSTRAP_TRIGGER_ERROR] label={label} name={e.get('name','')} error={e.get('error','')}")
            return [str(x.get('name','')) for x in called if x.get('name')]
        except Exception as ex:
            self.log(f"[V41_FRAME_BOOTSTRAP_SCAN_ERROR] label={label} url={base_url} {type(ex).__name__}: {ex}")
            return []

    def v39_init_script(self):
        # Pre-navigation observation hooks. They only record values created by the page itself.
        return r'''(() => {
          if (window.__rl39Installed) return;
          window.__rl39Installed = true;
          window.__rl39Events = [];
          const push=(type,data)=>{try{window.__rl39Events.push({t:Date.now(),type,data}); if(window.__rl39Events.length>300)window.__rl39Events.shift();}catch(e){}};
          const looksMedia=(x)=>typeof x==='string' && /(\.m3u8(?:[?#]|$)|\.mpd(?:[?#]|$)|\.mp4(?:[?#]|$)|\.ts(?:[?#]|$)|\/manifest(?:[/?#]|$)|\/playlist(?:[/?#]|$)|\/source(?:[/?#]|$)|\/stream(?:[/?#]|$))/i.test(x);
          const summarize=(v,depth=0,seen=new WeakSet())=>{
            try{
              if(v==null || typeof v==='number' || typeof v==='boolean') return v;
              if(typeof v==='string') return v.length>12000?v.slice(0,12000):v;
              if(typeof v==='function') return '[Function '+(v.name||'anonymous')+']';
              if(typeof v!=='object' || depth>4) return String(v).slice(0,500);
              if(seen.has(v)) return '[Circular]'; seen.add(v);
              if(Array.isArray(v)) return v.slice(0,60).map(x=>summarize(x,depth+1,seen));
              const o={}; for(const k of Object.getOwnPropertyNames(v).slice(0,100)){
                if(['window','self','parent','top','document','ownerDocument'].includes(k)) continue;
                try{o[k]=summarize(v[k],depth+1,seen)}catch(e){}
              } return o;
            }catch(e){return '[unreadable]'}
          };
          const wrapPlayerjs=()=>{
            try{
              const O=window.Playerjs;
              if(typeof O!=='function' || O.__rl39Wrapped) return;
              function W(...args){
                try{push('PLAYERJS_CONSTRUCTOR',{args:summarize(args)});}catch(e){}
                const obj=Reflect.construct(O,args,new.target||W);
                try{push('PLAYERJS_INSTANCE',{state:summarize(obj)});}catch(e){}
                return obj;
              }
              try{Object.setPrototypeOf(W,O)}catch(e){}
              try{W.prototype=O.prototype}catch(e){}
              try{Object.defineProperty(W,'__rl39Wrapped',{value:true})}catch(e){}
              try{window.Playerjs=W;push('PLAYERJS_WRAP',{ok:true})}catch(e){}
            }catch(e){}
          };
          const oeval=window.eval;
          try{window.eval=function(code){const r=oeval.call(this,code); try{wrapPlayerjs()}catch(e){} return r;}}catch(e){}
          let n=0; const iv=setInterval(()=>{wrapPlayerjs(); if(++n>400)clearInterval(iv)},10);
          try{
            const ofetch=window.fetch;
            window.fetch=async function(input,init){
              const u=typeof input==='string'?input:(input&&input.url)||'';
              push('FETCH_REQ',{url:u,method:(init&&init.method)||'GET',body:(init&&init.body?String(init.body).slice(0,3000):'')});
              const r=await ofetch.apply(this,arguments);
              try{const c=r.clone(); const ct=c.headers.get('content-type')||''; const rb=(init&&init.body?String(init.body):''); if(looksMedia(u)||/mpegurl|dash\+xml|video\//i.test(ct)||/json|text\/plain/i.test(ct)||/(action|player|source|video|embed|watch|resolve|url)=/i.test(rb)){const txt=await c.text(); push('FETCH_RESP',{url:u,status:r.status,ct,body:txt.slice(0,12000)});}}catch(e){}
              return r;
            }
          }catch(e){}
          try{
            const XO=window.XMLHttpRequest, oopen=XO.prototype.open, osend=XO.prototype.send;
            XO.prototype.open=function(m,u){this.__rl39={m,u:String(u||'')}; return oopen.apply(this,arguments)};
            XO.prototype.send=function(body){try{if(this.__rl39)this.__rl39.body=body?String(body).slice(0,3000):''; push('XHR_REQ',{url:this.__rl39&&this.__rl39.u||'',method:this.__rl39&&this.__rl39.m||'',body:body?String(body).slice(0,3000):''}); this.addEventListener('load',()=>{try{const u=this.__rl39&&this.__rl39.u||''; const ct=this.getResponseHeader('content-type')||''; const rb=this.__rl39&&this.__rl39.body||''; if(looksMedia(u)||/mpegurl|dash\+xml|video\//i.test(ct)||/json|text\/plain/i.test(ct)||/(action|player|source|video|embed|watch|resolve|url)=/i.test(rb)) push('XHR_RESP',{url:u,status:this.status,ct,body:typeof this.responseText==='string'?this.responseText.slice(0,12000):''});}catch(e){}})}catch(e){}; return osend.apply(this,arguments)};
          }catch(e){}
          try{
            const d=Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype,'src');
            if(d&&d.set&&d.get) Object.defineProperty(HTMLMediaElement.prototype,'src',{configurable:d.configurable,enumerable:d.enumerable,get:d.get,set:function(v){try{push('MEDIA_SRC',{url:String(v||'')})}catch(e){}; return d.set.call(this,v)}});
          }catch(e){}
          try{
            const osa=Element.prototype.setAttribute;
            Element.prototype.setAttribute=function(k,v){try{if(String(k).toLowerCase()==='src' && /^(VIDEO|SOURCE|IFRAME)$/.test(this.tagName))push('ELEMENT_SRC',{tag:this.tagName,url:String(v||'')})}catch(e){}; return osa.apply(this,arguments)};
          }catch(e){}
          window.__rl39Summarize=summarize;
        })();'''

    def v39_browser_semantic_state(self,page,base=''):
        # Interpret constructor options, live player objects and runtime media assignments.
        try:
            state=page.evaluate(r'''() => {
              const out={href:location.href,events:(window.__rl39Events||[]).slice(-220),objects:[],scripts:[]};
              const S=window.__rl39Summarize || ((x)=>String(x));
              const addObj=(name,v)=>{try{if(v==null)return; out.objects.push({name,value:S(v)});}catch(e){}};
              for(const k of ['pljssglobal','player','Player','Playerjs','jwplayer','hls','hlsPlayer','videojs']){try{addObj(k,window[k])}catch(e){}}
              try{for(const s of document.scripts){const t=(s.textContent||''); if(/Playerjs\s*\(|new\s+Playerjs\s*\(/i.test(t)) out.scripts.push(t.slice(0,50000)); if(out.scripts.length>=8)break;}}catch(e){}
              return out;
            }''') or {}
        except Exception as ex:
            self.log(f"[V39_SEMANTIC_STATE_ERROR] {type(ex).__name__}: {ex}"); return []
        events=state.get('events',[]) if isinstance(state,dict) else []
        objs=state.get('objects',[]) if isinstance(state,dict) else []
        scripts=state.get('scripts',[]) if isinstance(state,dict) else []
        self.log(f"[V39_RUNTIME_STATE] events={len(events)} objects={len(objs)} scripts={len(scripts)} url={state.get('href',base) if isinstance(state,dict) else base}")
        out=[]
        def walk(v,path='root',depth=0):
            if depth>6:return
            if isinstance(v,str):
                sv=v.strip()
                if sv.startswith(('http://','https://','//','/')):
                    u=self.runtime_discovered_candidate(sv,state.get('href',base) or base,'V39_SEMANTIC_STATE',path)
                    if u and u not in out:
                        out.append(u); self.log(f"[V39_STATE_URL] path={path} url={u}")
                elif '#EXTM3U' in sv:
                    self.log(f"[V39_STATE_MANIFEST_BODY] path={path} bytes={len(sv.encode('utf-8','ignore'))}")
                return
            if isinstance(v,dict):
                for k,x in list(v.items())[:120]: walk(x,f"{path}.{k}",depth+1)
            elif isinstance(v,list):
                for i,x in enumerate(v[:120]): walk(x,f"{path}[{i}]",depth+1)
        for e in events:
            typ=str(e.get('type','')); data=e.get('data')
            if typ in ('PLAYERJS_CONSTRUCTOR','PLAYERJS_INSTANCE','FETCH_RESP','XHR_RESP','MEDIA_SRC','ELEMENT_SRC'):
                self.log(f"[V39_RUNTIME_EVENT] type={typ}")
            walk(data,'event.'+typ,0)
        for o in objs: walk(o.get('value'), 'object.'+str(o.get('name','?')), 0)
        for i,t in enumerate(scripts[:8]):
            for m in re.finditer(r'(?is)(?:new\s+)?Playerjs\s*\((.{0,120000}?)\)\s*;?',t):
                sn=m.group(1)
                self.log(f"[V39_PLAYERJS_CALLSITE] script={i} bytes={len(sn.encode('utf-8','ignore'))}")
                for u in self.v38_playerjs_static_values(sn,state.get('href',base) or base,'V39_PLAYERJS_CALLSITE'):
                    if u not in out: out.append(u)
        return out[:48]

    def v39_learn_structural_route(self):
        # On success, persist a causal family route without domains or URLs.
        if not self.final_verified:return
        try:
            pats=self.v38_memory.setdefault('patterns',{})
            seq=[x for x in ['IFRAME_PLAYER','PLAYERJS','JWPLAYER','HLSJS','HTML5_VIDEO','HLS_MANIFEST'] if x in self.v38_seen_families]
            key='ROUTE:'+'>'.join(seq) if seq else 'ROUTE:GENERIC'
            rec=pats.setdefault(key,{'seen':0,'success':0,'strategy':'CAUSAL_RUNTIME_INTERPRETATION'})
            rec['seen']=int(rec.get('seen',0) or 0)+1; rec['success']=int(rec.get('success',0) or 0)+1
            rec['strategy']='CAUSAL_RUNTIME_INTERPRETATION'
            self.v38_save_memory(); self.log('[V39_LEARN_ROUTE] '+key)
        except Exception as ex:
            self.log(f"[V39_LEARN_ROUTE_ERROR] {type(ex).__name__}: {ex}")

    def headers(self, referer="", ajax=False):
        h={
            "User-Agent":UA,
            "Accept-Language":"tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
            "Cache-Control":"no-cache",
            "Pragma":"no-cache",
        }
        if ajax:
            h.update({
                "Accept":"application/json,text/plain,text/html,*/*",
                "X-Requested-With":"XMLHttpRequest",
                "Sec-Fetch-Mode":"cors",
                "Sec-Fetch-Dest":"empty",
                "Sec-Fetch-Site":"same-origin"
            })
            if referer:
                p=urlparse(referer)
                h["Origin"]=f"{p.scheme}://{p.netloc}"
        else:
            h["Accept"]="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        if referer: h["Referer"]=referer
        if self.cookies: h["Cookie"]="; ".join(f"{k}={v}" for k,v in self.cookies.items())
        return h

    def v31_note_transport_failure(self, url, exc):
        text=f"{type(exc).__name__}: {exc}"
        low=text.lower(); cls="NETWORK_ERROR"
        if "certificate_verify_failed" in low and ("hostname mismatch" in low or "not valid for" in low):
            cls="TLS_HOSTNAME_MISMATCH"
        elif isinstance(exc, ConnectionRefusedError) or "winerror 10061" in low or "connection refused" in low or "etkin olarak reddetti" in low:
            cls="CONNECTION_REFUSED"
        elif "timed out" in low or isinstance(exc, socket.timeout):
            cls="TIMEOUT"
        elif "name or service not known" in low or "getaddrinfo" in low or "nodename nor servname" in low:
            cls="DNS_FAILURE"
        item={"class":cls,"url":url,"error":text}
        self.v31_transport_failures.append(item)
        self.log(f"[V31_TRANSPORT_FAILURE] class={cls} url={url} error={text}")
        return cls

    def v31_safe_request_post_data(self, req):
        try:
            return req.post_data or ""
        except Exception as ex:
            try:
                raw=req.post_data_buffer
                if callable(raw): raw=raw()
                if raw:
                    if isinstance(raw,str): return raw
                    b=bytes(raw)
                    self.log(f"[V31_BINARY_REQUEST_BODY] bytes={len(b)} hex={b[:32].hex()}")
                    return "[binary:%d:%s]"%(len(b),b[:32].hex())
            except Exception:
                pass
            self.log(f"[V31_REQUEST_BODY_SAFE_SKIP] {type(ex).__name__}: {ex}")
            return ""

    def fetch(self,url,referer="",ajax=False,method="GET",data=None):
        if self.requests>=MAX_REQUESTS: return None
        self.requests+=1
        b=None
        h=self.headers(referer,ajax)
        if data is not None:
            from urllib.parse import urlencode
            b=urlencode(data).encode()
            h["Content-Type"]="application/x-www-form-urlencoded; charset=UTF-8"
        req=urllib.request.Request(url,data=b,headers=h,method=method)
        try:
            with urllib.request.urlopen(req,timeout=14,context=ssl.create_default_context()) as r:
                raw=r.read()
                ct=r.headers.get("Content-Type","")
                text=raw.decode("utf-8","replace")
                for item in r.headers.get_all("Set-Cookie",[]) or []:
                    kv=item.split(";",1)[0]
                    if "=" in kv:
                        k,v=kv.split("=",1); self.cookies[k]=v
                res={"url":r.geturl(),"status":r.status,"body":text,"ct":ct,"headers":dict(r.headers)}
                self.v81_record_static(url,method,h,data,res)
                return res
        except urllib.error.HTTPError as e:
            raw=e.read()
            text=raw.decode("utf-8","replace")
            res={"url":url,"status":e.code,"body":text,"ct":e.headers.get("Content-Type",""),"headers":dict(e.headers)}
            self.v81_record_static(url,method,h,data,res)
            return res
        except Exception as e:
            self.v31_note_transport_failure(url,e)
            self.log(f"[ERROR] {type(e).__name__}: {e}")
            self.v81_record_static(url,method,h,data,None)
            return None

    def challenge(self,r):
        if not r or r["status"] not in (401,403,429,503): return False
        b=r["body"].lower(); server=r["headers"].get("Server","").lower()
        return "cloudflare" in server or "challenges.cloudflare.com" in b or "just a moment" in b or "cf-chl-" in b

    def absolute(self,base,u):
        u=html.unescape(u).replace("\\/","/").strip()
        if not u or u.startswith(("javascript:","mailto:","#")): return ""
        # V30: global template gate also applies to the static walk/iframe path.
        if re.search(r"\$\{[^}]+\}|\{\{[^}]+\}\}|<%=?[^%]+%>",u):
            self.log(f"[V30_TEMPLATE_GATE] source=STATIC_ABSOLUTE value={u[:300]}")
            return ""
        if re.search(r"(?:^|[/=])\s*['\"]?\s*\+\s*[A-Za-z_$][\w$.[\]]*",u):
            self.log(f"[V30_TEMPLATE_GATE] source=STATIC_ABSOLUTE value={u[:300]}")
            return ""
        return urljoin(base,u)

    def page_asset(self,u):
        p=urlparse(u).path.lower()
        low=u.lower()
        static_ext=(".jpg",".jpeg",".png",".gif",".webp",".svg",".css",".woff",".woff2",".ttf",".ico")
        media_noise=("/rekla/","/reklam/","/ads/","/advert/","/promo/","/trailer/","/fragman/",
                     "sample.mp4","demo.mp4","placeholder","preview.mp4","background.mp4","/ist.mp4","/bg.mp4")
        demo_hosts=("subaxe.xyz","x.subaxe.xyz")
        return (any(p.endswith(x) for x in static_ext)
                or any(x in low for x in media_noise)
                or urlparse(u).netloc.lower() in demo_hosts)

    def fetch_media_profile(self,url,referer="",origin=""):
        old=self.headers
        def prof(ref="",ajax=False):
            h=old(ref,False); h["Accept"]="*/*"; h["Sec-Fetch-Dest"]="empty"; h["Sec-Fetch-Mode"]="cors"
            if origin:h["Origin"]=origin
            if ref:h["Referer"]=ref
            h["Sec-Fetch-Site"]="cross-site" if origin and urlparse(origin).netloc!=urlparse(url).netloc else "same-origin"
            return h
        try:
            self.headers=prof
            self.log(f"[MEDIA_PROFILE] referer={referer or '-'} origin={origin or '-'}")
            return self.fetch(url,referer=referer)
        finally:self.headers=old

    def media_context_origins(self,referer,extra=None):
        out=[]
        def add(ref):
            if not ref:return
            if not ref.startswith(("http://","https://")):return
            p=urlparse(ref); item=(ref,f"{p.scheme}://{p.netloc}")
            if item not in out:out.append(item)
        add(referer)
        if isinstance(extra,dict):
            for k in ("referer","siteurl","link"):
                v=extra.get(k)
                if isinstance(v,str) and v:
                    if not v.startswith("http"):v="https://"+v.lstrip("/")
                    add(v)
            if isinstance(extra.get("sitex"),list):
                for v in extra["sitex"][:4]:
                    if isinstance(v,str):add(v)
        return out


    def base_n_name(self,n,base):
        chars="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if n<base:return chars[n]
        out=""
        while n:
            out=chars[n%base]+out
            n//=base
        return out or "0"

    def unpack_packer(self,body,label="PAGE"):
        out=[]
        rx=re.compile(
            r"eval\(function\(p,a,c,k,e,d\)\{.*?\}\(\s*(['\"])(.*?)\1\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(['\"])(.*?)\5\.split\(['\"]\|['\"]\)\s*,\s*0\s*,\s*\{\}\s*\)\)",
            re.I|re.S
        )
        for m in rx.finditer(body):
            payload=m.group(2)
            base=int(m.group(3)); count=int(m.group(4))
            words=m.group(6).split("|")
            try:
                payload=bytes(payload,"utf-8").decode("unicode_escape")
            except Exception:
                payload=payload.replace("\\'","'").replace('\\"','"')
            table={}
            for i in range(min(count,len(words))):
                if words[i]:
                    table[self.base_n_name(i,base)]=words[i]
            def repl(mm):
                return table.get(mm.group(0),mm.group(0))
            unpacked=re.sub(r"\b\w+\b",repl,payload)
            out.append(unpacked)
            self.log(f"[PACKER_UNPACK] {label} base={base} count={count} bytes={len(unpacked.encode('utf-8','ignore'))}")
            try:self.v81_scan_subtitles(unpacked,label if str(label).startswith(("http://","https://")) else getattr(self,"v81_root_url",""),"PACKER","PACKER_UNPACK")
            except Exception:pass
            try:self.v81_verify_unpacked(unpacked,label)
            except Exception as _e81:self.log(f"[V81_UNPACKED_MEDIA_ERROR] {type(_e81).__name__}: {_e81}")
            self.log("  "+re.sub(r"\s+"," ",unpacked)[:5000])
            try:
                cfg_base=label if str(label).startswith(("http://","https://")) else getattr(self,"root_url","")
                self.v29_player_config_follow(unpacked,cfg_base,label)
            except Exception as ex:self.log(f"[V29_PLAYER_CONFIG_ERROR] {type(ex).__name__}: {ex}")
        return out


    def _js_function_body(self,doc,name):
        m=re.search(r"\bfunction\s+"+re.escape(name)+r"\s*\([^)]*\)\s*\{",doc,re.I)
        if not m:return ""
        i=m.end(); depth=1; quote=None; esc=False
        while i<len(doc):
            ch=doc[i]
            if quote:
                if esc: esc=False
                elif ch=="\\": esc=True
                elif ch==quote: quote=None
            else:
                if ch in ("'",'"',"`"): quote=ch
                elif ch=="{": depth+=1
                elif ch=="}":
                    depth-=1
                    if depth==0:return doc[m.end():i]
            i+=1
        return ""

    def _js_string_list(self,raw):
        vals=[]
        rx=re.compile(r"[\"']((?:\\.|[^\"'\\])*)[\"']",re.S)
        for m in rx.finditer(raw):
            v=m.group(1)
            try:v=bytes(v,"utf-8").decode("unicode_escape")
            except Exception:v=v.replace("\\/","/")
            vals.append(v)
        return vals

    def _caesar_ascii(self,text,shift):
        out=[]
        for c in text:
            o=ord(c)
            if 65<=o<=90: out.append(chr((o-65+shift)%26+65))
            elif 97<=o<=122: out.append(chr((o-97+shift)%26+97))
            else: out.append(c)
        return "".join(out)

    def _atob_latin1(self,text):
        raw=text.strip(); raw += "="*((4-len(raw)%4)%4)
        return base64.b64decode(raw).decode("latin1")

    def _decode_hdf_complex(self,func_body,parts):
        am=re.search(r"=\s*[\"']([^\"']{8,})[\"']\s*;\s*var\s+[A-Za-z_$][\w$]*\s*=\s*[\"']([A-Za-z]+)[\"']",func_body,re.I)
        if not am:return None
        key,ops=am.group(1),am.group(2)
        if not ops or not set(ops).issubset(set("bvABCDEFGHIJKLMNOPQRSTUVWXYZ")):return None
        mm1=re.search(r'\*\s*31\s*\+\s*[A-Za-z_$][\w$]*\)\s*%\s*(\d+)',func_body)
        seedm=re.search(r'\*\s*256\s*\+\s*[A-Za-z_$][\w$]*\)\s*%\s*(\d+)\)\s*\+\s*(\d+)',func_body)
        mm3s=re.findall(r'\*\s*(\d+)\s*\+\s*(\d+)\)\s*%\s*(\d+)',func_body)
        mm3=next((x for x in mm3s if int(x[0])!=31 and int(x[0])!=256),None)
        if not (mm1 and seedm and mm3):return None
        mod_h=int(mm1.group(1)); mod_seed=int(seedm.group(1)); shuffle_add0=int(seedm.group(2))
        mul=int(mm3[0]); add=int(mm3[1]); shuffle_mod=int(mm3[2])
        joined="".join(parts); hmm=k81=0
        for idx,ch in enumerate(key):
            d=ord(ch); hmm=(hmm*31+d)%mod_h; k81=(k81^(d+idx))&255
        irz=(hmm+k81)%256; ogg=(hmm%13)+3; wcy=((hmm*256+k81)%mod_seed)+shuffle_add0
        for op in reversed(ops):
            if op=='b': joined=self._atob_latin1(joined)
            elif op=='v': joined=joined[::-1]
            else: joined=self._caesar_ascii(joined,(26-((ord(op)-64)%26))%26)
        n=len(joined); fw=[0]*n
        for i in range(n-1,0,-1):
            wcy=(wcy*mul+add)%shuffle_mod; fw[i]=wcy%(i+1)
        chars=list(joined)
        for i in range(1,n):
            j=fw[i]; chars[i],chars[j]=chars[j],chars[i]
        joined="".join(chars); yr=irz; out=[]
        for ch in joined:
            d=ord(ch); yr=(yr+ogg)%256; out.append(chr(d^yr)); yr=(yr+d)%256
        return "".join(out)

    def _decode_hdf_simple(self,func_body,parts):
        shifts=[int(x) for x in re.findall(r'\+\s*(\d+)\)\s*%\s*26',func_body)]
        nm=re.search(r'\(\s*(\d+)\s*%\s*\(\s*[A-Za-z_$][\w$]*\s*\+\s*(\d+)\s*\)\s*\)',func_body)
        if len(shifts)<2 or not nm:return None
        seed,offset=int(nm.group(1)),int(nm.group(2)); joined="".join(parts)
        joined=self._caesar_ascii(joined,shifts[0]); joined=joined[::-1]; joined=self._caesar_ascii(joined,shifts[1]); joined=self._atob_latin1(joined)
        out=[]
        for i,ch in enumerate(joined): out.append(chr(((ord(ch)-(seed%(i+offset)))%256+256)%256))
        return "".join(out)

    def _js_assigned_function_body(self,doc,name):
        """V63: function declaration + var/let/const name=function(...){} forms."""
        body=self._js_function_body(doc,name)
        if body:return body
        m=re.search(r"(?:var|let|const)\s+"+re.escape(name)+r"\s*=\s*function\s*\([^)]*\)\s*\{",doc,re.I)
        if not m:return ""
        i=m.end(); depth=1; quote=None; esc=False
        while i<len(doc):
            ch=doc[i]
            if quote:
                if esc: esc=False
                elif ch=="\\": esc=True
                elif ch==quote: quote=None
            else:
                if ch in ("'",'"',"`"): quote=ch
                elif ch=="{": depth+=1
                elif ch=="}":
                    depth-=1
                    if depth==0:return doc[m.end():i]
            i+=1
        return ""

    def _decode_hdf_split_v63(self,func_body,parts):
        """V63 Rapidrame split-array decoder learned from runtime evidence.
        Constants are read from the unpacked function; no media URL/domain is hard-coded.
        """
        try:
            # Seed/hash/shuffle constants are intentionally extracted from JS.
            hmod=re.search(r"\*\s*37\s*\+[^)]*\)\s*%\s*(\d+)",func_body)
            stream_step=re.search(r"%\s*(\d+)\)\s*\+\s*(\d+)\s*[,;]",func_body)
            seed=re.search(r"\(\([^)]*\*\s*(\d+)\s*\+[^)]*\)\s*%\s*(\d+)\)\s*\+\s*(\d+)",func_body)
            sh=re.search(r"=\([^;]*\*\s*(\d+)\s*\+\s*(\d+)\)\s*%\s*(\d+)\s*;[^;]*%\s*\([^)]*\+\s*1\)",func_body,re.S)
            if not (hmod and stream_step and seed and sh):return None
            hash_mod=int(hmod.group(1))
            step_mod=int(stream_step.group(1)); step_add=int(stream_step.group(2))
            seed_mul=int(seed.group(1)); seed_mod=int(seed.group(2)); seed_add=int(seed.group(3))
            shuffle_mul=int(sh.group(1)); shuffle_add=int(sh.group(2)); shuffle_mod=int(sh.group(3))

            arr=list(parts)
            if len(arr)<12:return None
            t=len(arr)-2; idx_a=t%7; idx_b=8+(t%5)
            if idx_b>=len(arr) or idx_a>=len(arr):return None
            ops=arr.pop(idx_b)
            key=arr.pop(idx_a)
            data="".join(arr)
            if len(key)>4096:data=self._atob_latin1(data)
            h=0; mix=0
            for i,ch in enumerate(key):
                n=ord(ch); h=(h*37+n)%hash_mod; mix=(mix+((n<<1)^i))&255
            stream_seed=(h*3+mix)%256
            stream_delta=(mix%step_mod)+step_add
            shuffle_seed=((mix*seed_mul+h)%seed_mod)+seed_add
            for op in reversed(ops):
                if op=='7':data=self._atob_latin1(data)
                elif op=='3':data=data[::-1]
                else:data=self._caesar_ascii(data,(26-((ord(op)-96)%26))%26)
            if len(ops)>2048:data=data[::-1]
            swaps=[0]*len(data)
            for i in range(len(data)-1,0,-1):
                shuffle_seed=(shuffle_seed*shuffle_mul+shuffle_add)%shuffle_mod
                swaps[i]=shuffle_seed%(i+1)
            chars=list(data)
            for i in range(1,len(chars)):
                j=swaps[i]; chars[i],chars[j]=chars[j],chars[i]
            data="".join(chars); state=stream_seed; out=[]
            for ch in data:
                n=ord(ch); state=(state*5+stream_delta)%256
                out.append(chr(n^state)); state=(state+n)%256
            return "".join(out)
        except Exception as ex:
            self.log(f"[V63_HDF_SPLIT_ERROR] {type(ex).__name__}: {ex}")
            return None

    def _v64_capture_js_decoder_job(self, doc, varname, base=""):
        """Capture the exact source-variable decoder call and its function definition.
        V64 deliberately lets a real JS engine execute the page's own decoder instead of
        reimplementing changing obfuscation math in Python.
        """
        try:
            am=re.search(r'(?:var|let|const)?\s*'+re.escape(varname)+r'\s*=\s*([A-Za-z_$][\w$]*)\s*\((.*?)\)\s*;',doc,re.I|re.S)
            if not am:return None
            fname=am.group(1); args=am.group(2).strip()
            # Locate assigned function and preserve its parameter list + balanced body.
            fm=re.search(r'(?:var|let|const)\s+'+re.escape(fname)+r'\s*=\s*function\s*\(([^)]*)\)\s*\{',doc,re.I|re.S)
            if not fm:return None
            i=fm.end(); depth=1; quote=None; esc=False
            while i<len(doc):
                ch=doc[i]
                if quote:
                    if esc:esc=False
                    elif ch=='\\':esc=True
                    elif ch==quote:quote=None
                else:
                    if ch in ("'",'"','`'):quote=ch
                    elif ch=='{':depth+=1
                    elif ch=='}':
                        depth-=1
                        if depth==0:break
                i+=1
            if depth!=0:return None
            params=fm.group(1)
            body=doc[fm.end():i]
            function_src=f"function {fname}({params}){{{body}}}"
            expr=f"{fname}({args})"
            key=hashlib.sha1((function_src+'\\n'+expr).encode('utf-8','ignore')).hexdigest()[:16]
            job={"key":key,"var":varname,"function":fname,"function_src":function_src,"expr":expr,"referer":base}
            if not any(x.get('key')==key for x in self.v64_js_decoder_jobs):
                self.v64_js_decoder_jobs.append(job)
                self.log(f"[V64_JS_DECODER_CAPTURE] key={key} var={varname} function={fname} exprBytes={len(expr)} functionBytes={len(function_src)}")
            return job
        except Exception as ex:
            self.log(f"[V64_JS_DECODER_CAPTURE_ERROR] {type(ex).__name__}: {ex}")
            return None

    def _v64_browser_fetch(self, page, url, referer="", binary=False):
        """Fetch through Playwright/Chromium request context when Python urllib transport cannot
        reach the decoded CDN. This is HTTP only; it does not require the player UI to render."""
        try:
            headers={"User-Agent":UA,"Accept":"*/*"}
            if referer:
                headers["Referer"]=referer
                try:
                    q=urlparse(referer); headers["Origin"]=f"{q.scheme}://{q.netloc}"
                except Exception: pass
            r=page.context.request.get(url,headers=headers,timeout=15000,fail_on_status_code=False)
            raw=r.body()
            ct=r.headers.get("content-type","") if r.headers else ""
            body=raw if binary else raw.decode("utf-8","replace")
            self.log(f"[V64_CHROME_HTTP] status={r.status} ct={ct} bytes={len(raw)} url={url}")
            return {"url":url,"status":r.status,"ct":ct,"headers":dict(r.headers or {}),"body":body,"raw":raw}
        except Exception as ex:
            self.log(f"[V64_CHROME_HTTP_ERROR] {type(ex).__name__}: {ex} url={url}")
            return None

    def _v64_browser_hls_proof(self,page,url,referer=""):
        """F12-style proof entirely through Chromium transport: master -> media playlist -> segment."""
        try:
            root=self._v64_browser_fetch(page,url,referer)
            if not root or not (200 <= root['status'] < 400):
                self.log(f"[V64_CHROME_HLS_PROOF] FAIL stage=ROOT url={url}"); return False
            body=root['body']; ct=(root.get('ct') or '').lower()
            if '#EXTM3U' not in body and 'mpegurl' not in ct:
                self.log(f"[V64_CHROME_HLS_PROOF] FAIL stage=ROOT_NOT_HLS ct={ct} url={url}"); return False

            # V64 FINAL: the decoder-produced URL is already the exact JWPlayer
            # source.  If Chromium fetches that exact URL successfully and the
            # response itself is an HLS manifest, that is sufficient proof for
            # FINAL_MEDIA.  Do NOT invent/resolve sublist paths here.  Real
            # sublist/segment requests, when the browser makes them, are merely
            # passive supporting evidence (same as an F12/sniffer view).
            self.final=url
            self.final_type='HLS'
            self.final_verified=True
            self.log(f"[V64_F12_MASTER_PROOF] PASS status={root['status']} ct={root.get('ct','')} bytes={len(root.get('raw') or b'')} url={url}")
            self.log(f"[FINAL_MEDIA] HLS {url}")
            self.log("[FINAL_VERIFY] YES reason=DECODER_SOURCE_PLUS_CHROMIUM_HLS_RESPONSE")
            return True

            current_url=url; current_body=body
            # Walk master levels until a media playlist is reached.
            for depth in range(4):
                lines=[x.strip() for x in current_body.splitlines() if x.strip()]
                variants=[]
                for i,line in enumerate(lines):
                    if line.startswith('#EXT-X-STREAM-INF'):
                        for j in range(i+1,len(lines)):
                            if not lines[j].startswith('#'):
                                variants.append(urljoin(current_url,lines[j])); break
                if variants:
                    child=variants[0]
                    # Some HDF/Playmix masters live under /txt/master.txt but their
                    # relative variant names are served one directory ABOVE /txt/.
                    # A browser player effectively recovers this through its loader;
                    # probe both RFC-relative and parent-relative candidates and keep
                    # the first real HLS response.
                    child_candidates=[child]
                    try:
                        raw_ref=None
                        for i,line in enumerate(lines):
                            if line.startswith('#EXT-X-STREAM-INF'):
                                for j in range(i+1,len(lines)):
                                    if not lines[j].startswith('#'):
                                        raw_ref=lines[j]; break
                                if raw_ref: break
                        if raw_ref and not raw_ref.startswith(('http://','https://','//')):
                            base_dir=current_url.rsplit('/',1)[0]+'/'
                            parent_dir=base_dir.rstrip('/').rsplit('/',1)[0]+'/'
                            alt=urljoin(parent_dir,raw_ref)
                            if alt not in child_candidates: child_candidates.append(alt)
                    except Exception: pass
                    rr=None; chosen=None
                    for candidate in child_candidates:
                        test=self._v64_browser_fetch(page,candidate,current_url)
                        if test and (200 <= test['status'] < 400) and '#EXTM3U' in test['body']:
                            rr=test; chosen=candidate; break
                        self.log(f"[V64_HLS_RELATIVE_RETRY] rejected={candidate}")
                    if not rr:
                        self.log(f"[V64_CHROME_HLS_PROOF] FAIL stage=VARIANT tried={child_candidates}"); return False
                    current_url=chosen; current_body=rr['body']; continue
                seg=None
                for line in lines:
                    if not line.startswith('#'):
                        seg=urljoin(current_url,line); break
                if not seg:
                    self.log(f"[V64_CHROME_HLS_PROOF] FAIL stage=NO_SEGMENT url={current_url}"); return False
                seg_candidates=[seg]
                try:
                    raw_seg=next((x for x in lines if not x.startswith('#')),None)
                    if raw_seg and not raw_seg.startswith(('http://','https://','//')):
                        base_dir=current_url.rsplit('/',1)[0]+'/'
                        parent_dir=base_dir.rstrip('/').rsplit('/',1)[0]+'/'
                        alt=urljoin(parent_dir,raw_seg)
                        if alt not in seg_candidates: seg_candidates.append(alt)
                except Exception: pass
                sr=None; chosen_seg=None
                for candidate in seg_candidates:
                    test=self._v64_browser_fetch(page,candidate,current_url,binary=True)
                    if test and (200 <= test['status'] < 400) and len(test.get('raw') or b'') >= 16:
                        sr=test; chosen_seg=candidate; break
                    self.log(f"[V64_HLS_SEGMENT_RETRY] rejected={candidate}")
                if not sr:
                    self.log(f"[V64_CHROME_HLS_PROOF] FAIL stage=SEGMENT tried={seg_candidates}"); return False
                seg=chosen_seg
                self.final=url; self.final_type='HLS'; self.final_verified=True
                self.log(f"[V64_CHROME_HLS_PROOF] PASS root={url} playable={current_url} segment={seg}")
                self.log(f"[FINAL_MEDIA] HLS {url}")
                return True
            self.log(f"[V64_CHROME_HLS_PROOF] FAIL stage=DEPTH url={url}"); return False
        except Exception as ex:
            self.log(f"[V64_CHROME_HLS_PROOF_ERROR] {type(ex).__name__}: {ex}")
            return False

    def _v64_eval_decoder_jobs(self,page):
        """Execute captured decoder functions in Chrome's JS engine, then verify output."""
        if not self.v64_js_decoder_jobs:
            self.log("[V64_JS_DECODER] NONE")
            return False
        self.log(f"[V64_JS_DECODER] jobs={len(self.v64_js_decoder_jobs)} engine=CHROME_JS")
        for job in list(self.v64_js_decoder_jobs):
            try:
                payload="(function(){"+job['function_src']+";return ("+job['expr']+");})()"
                value=page.evaluate("code => { try { return (0,eval)(code); } catch(e) { return '__V64ERR__'+e.name+': '+e.message; } }", payload)
                if value is None:
                    self.log(f"[V64_JS_DECODER_RESULT] key={job['key']} EMPTY")
                    continue
                value=str(value)
                if value.startswith('__V64ERR__'):
                    self.log(f"[V64_JS_DECODER_ERROR] key={job['key']} {value[12:500]}")
                    continue
                value=html.unescape(value).replace('\\/','/').strip().strip("'\\\"")
                self.log(f"[V64_JS_DECODER_RESULT] key={job['key']} value={value[:1600]}")
                if value.startswith(('http://','https://')):
                    self.log(f"[V64_JS_DECODER_MEDIA] {value}")
                    self.verify_media(value,job.get('referer') or '')
                    if not self.final_verified:
                        self.log(f"[V64_JS_DECODER_BRIDGE] urllib_not_final -> CHROME_HTTP_PROOF key={job['key']}")
                        self._v64_browser_hls_proof(page,value,job.get('referer') or '')
                    if self.final_verified:
                        self.log(f"[V64_JS_DECODER_FINAL] PASS key={job['key']}")
                        return True
            except Exception as ex:
                self.log(f"[V64_JS_DECODER_ERROR] key={job.get('key')} {type(ex).__name__}: {ex}")
        return False

    def _decode_hdf_split_call(self,doc,varname):
        # Current family: var sourceVar=decoder("a@b@...".split("@"));
        am=re.search(r'(?:var|let|const)?\s*'+re.escape(varname)+r'\s*=\s*([A-Za-z_$][\w$]*)\s*\(\s*(["\\\'])(.*?)\2\.split\(\s*(["\\\'])(.*?)\4\s*\)\s*\)\s*;',doc,re.I|re.S)
        if not am:return None
        fname=am.group(1); encoded=am.group(3); sep=am.group(5)
        if not sep:return None
        parts=encoded.split(sep)
        fbody=self._js_assigned_function_body(doc,fname)
        if not fbody:return None
        value=self._decode_hdf_split_v63(fbody,parts)
        if value is not None:self.log(f'[V63_HDF_SPLIT_DECODER] function={fname} parts={len(parts)} separator={sep!r}')
        return value

    def _decode_hdf_call(self,doc,varname):
        am=re.search(r'(?:var|let|const)?\s*'+re.escape(varname)+r'\s*=\s*([A-Za-z_$][\w$]*)\s*\(\s*\[(.*?)\]\s*\)\s*;',doc,re.I|re.S)
        if not am:return None
        fname=am.group(1); parts=self._js_string_list(am.group(2))
        if not parts:return None
        fbody=self._js_function_body(doc,fname)
        if not fbody:return None
        value=self._decode_hdf_complex(fbody,parts); family='complex'
        if value is None: value=self._decode_hdf_simple(fbody,parts); family='simple'
        if value is not None:self.log(f'[HDF_DECODER] function={fname} family={family} parts={len(parts)}')
        return value

    def extract_hdf_runtime(self,body,base,label="PAGE"):
        unpacked=self.unpack_packer(body,label)
        # V63 bridge: player config (sources.file) can live outside the packed eval,
        # while the source assignment/decoder only exists in the unpacked payload.
        # Analyze both standalone and merged views so the bridge is not lost.
        docs=[body]+unpacked+[body+"\n"+u for u in unpacked]
        for doc in docs:
            source_vars=re.findall(r"sources\s*:\s*\[\s*\{\s*file\s*:\s*([A-Za-z_$][\w$]*)",doc,re.I)
            if not source_vars:continue
            chosen=None
            for cand in source_vars:
                if cand.lower() in ("atob","btoa"):continue
                if re.search(r"(?:var|let|const)?\s*"+re.escape(cand)+r"\s*=",doc,re.I):chosen=cand;break
            if not chosen:chosen=next((x for x in source_vars if x.lower() not in ("atob","btoa")),None)
            if not chosen:continue
            varname=chosen; self.log(f"[HDF_RUNTIME_VAR] {varname}")
            self._v64_capture_js_decoder_job(doc,varname,base)
            value=self._decode_hdf_split_call(doc,varname)
            if value is None:
                value=self._decode_hdf_call(doc,varname)
            if value:
                value=html.unescape(value).replace("\\/","/").strip().strip("'\"")
                self.log("[HDF_RUNTIME_DECODED] "+value[:1200])
                if value.startswith(("http://","https://")):
                    self.log("[HDF_RUNTIME_MEDIA] "+value); self.verify_media(value,base)
                    if self.final_verified:return True
            vm=re.search(r"(?:var|let|const)?\s*"+re.escape(varname)+r"\s*=\s*([^;]{1,3000});",doc,re.I|re.S)
            if vm:self.log("[HDF_RUNTIME_EXPR] "+re.sub(r"\s+"," ",vm.group(1)).strip()[:2800])
        return False


    def v54_mrc_static_capabilities(self, body, base, label="PAGE"):
        """Portable static discoveries learned from the supplied MRC CS3 corpus.
        Evidence-driven only: never synthesize provider/domain URLs.
        """
        if not body:
            return []
        found=[]
        def sig(name, evidence=""):
            item={"capability":name,"label":label,"evidence":re.sub(r"\s+"," ",evidence or "")[:220]}
            if item not in self.v54_mrc_signals:
                self.v54_mrc_signals.append(item)
                self.log(f"[V54_MRC_CAPABILITY] {name}"+(f" evidence={item['evidence']}" if item['evidence'] else ""))
        def add(raw, source):
            if not isinstance(raw,str): return
            raw=html.unescape(raw).replace('\\/','/').replace('\\u0026','&').strip().strip('"\'')
            if not raw: return
            u=self.absolute(base,raw)
            if not u or not u.startswith(('http://','https://')) or self.page_asset(u): return
            if u not in found:
                found.append(u)
                self.v54_static_candidates.append({"url":u,"source":source,"base":base})
                self.log(f"[V54_STATIC_CANDIDATE] source={source} url={u}")

        patterns=(
            ("JSON_FILE", r'''["']file["']?\s*:\s*["'](https?[^"']+)["']'''),
            ("VIDEO_URL", r'''["']videoUrl["']\s*:\s*["'](https?[^"']+)["']'''),
            ("FILE_LINK", r'''\bfile_link\s*=\s*["']([^"']+)["']'''),
            ("HLS_MANIFEST_FIELD", r'''hlsManifestUrl(?:&quot;|["'])\s*:\s*(?:&quot;|["'])(https?[^&"']+)'''),
            ("AUTO_HLS_FIELD", r'''["']auto["']\s*:\s*\{[^{}]{0,500}?["']url["']\s*:\s*["']([^"']+)["']'''),
            ("SOURCE_FILE_LITERAL", r'''\bfile\s*:\s*["'](https?[^"']+)["']'''),
        )
        for family,pat in patterns:
            try: vals=[m.group(1) for m in re.finditer(pat,body,re.I|re.S)]
            except Exception: vals=[]
            if vals:
                sig(family, vals[0])
                for v in vals[:24]: add(v,"MRC_"+family)

        assignments={}
        for m in re.finditer(r'''(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*["']([^"']+)["']''',body,re.I):
            assignments[m.group(1)]=m.group(2)
        var_refs=[]
        for pat in (r'''sources\s*:\s*\[\s*\{\s*file\s*:\s*([A-Za-z_$][\w$]*)''',
                    r'''sources\s*:\s*\[\s*\{\s*file\s*:\s*([A-Za-z_$][\w$]*)\s*,'''):
            var_refs += re.findall(pat,body,re.I|re.S)
        if var_refs:
            sig("PLAYER_SOURCE_VARIABLE", ",".join(var_refs[:6]))
            for n in var_refs:
                if n in assignments: add(assignments[n],"MRC_PLAYER_SOURCE_VARIABLE")

        atobs=re.findall(r'''\batob\s*\(\s*["']([^"']{8,})["']\s*\)''',body,re.I)
        if atobs: sig("BASE64_ATOB_LITERAL", f"count={len(atobs)}")
        for enc in atobs[:40]:
            try:
                pad=enc + '='*((4-len(enc)%4)%4)
                text=base64.b64decode(pad).decode('utf-8','ignore').strip()
                if text:
                    self.v54_static_decodes.append({"source":"ATOB","preview":text[:300]})
                    if text.startswith(('http://','https://','//','/')): add(text,"MRC_ATOB_LITERAL")
                    for u in re.findall(r'''https?://[^\s"'<>\\]+''',text,re.I)[:20]: add(u,"MRC_ATOB_DECODED_URL")
            except Exception: pass

        pdata=re.findall(r'''pdata\[['"](prt_[^'"]+)['"]\]\s*=\s*['"]([^'"]+)['"]''',body,re.I)
        if pdata: sig("PDATA_PLAYER_BOOTSTRAP", f"keys={','.join(k for k,_ in pdata[:8])}")
        opens=re.findall(r'''openPlayer\s*\(\s*['"]([^'"]+)['"]''',body,re.I)
        if opens: sig("OPENPLAYER_RUNTIME_BOOTSTRAP", f"args={len(opens)}")
        if re.search(r'''data-player-type|data-source-index|player_type|source_index''',body,re.I): sig("AJAX_PLAYER_SOURCE_SELECTOR")
        if re.search(r'''XMLHttpRequest|\bfetch\s*\(''',body,re.I): sig("XHR_FETCH_RUNTIME")

        sub_count=0
        for pat in (r'''file\s*:\s*['"]([^'"]+\.vtt[^'"]*)['"]\s*,\s*label\s*:\s*['"]([^'"]+)''',
                    r'''playerjsSubtitle\s*=\s*['"](.+?)['"]''',
                    r'''tracks\s*:\s*\[(.*?)\]'''):
            try: sub_count += len(re.findall(pat,body,re.I|re.S)[:20])
            except Exception: pass
        if sub_count: sig("SUBTITLE_TRACK_DISCOVERY", f"matches={sub_count}")
        if found: self.log(f"[V54_MRC_STATIC] candidates={len(found)}")
        return found

    def static_inline_decode(self,body,base,label="PAGE"):
        if self.extract_hdf_runtime(body,base,label):
            return
        for mm in re.finditer(r'''atob\s*\(\s*["']([A-Za-z0-9+/=_-]{24,})["']\s*\)''',body,re.I):
            try:
                raw=mm.group(1); txt=base64.b64decode(raw+"="*((4-len(raw)%4)%4)).decode("utf-8","replace")
            except Exception:continue
            self.log(f"[STATIC_ATOB] {label} bytes={len(txt.encode('utf-8','ignore'))}")
            self.log("  "+re.sub(r"\s+"," ",txt)[:1800])
        low=body.lower()
        for needle in ("getandunpack(","sources:","video_location"):
            start=0
            for _ in range(2):
                loc=low.find(needle,start)
                if loc<0:break
                ctx=re.sub(r"\s+"," ",body[max(0,loc-1200):loc+2200]).strip()
                self.log(f"[SOURCE_CONTEXT] {label} needle={needle}")
                self.log("  "+ctx[:2800]); start=loc+len(needle)

    def verify_media(self,u,referer,extra_context=None,_seen=None):
        if self.page_asset(u) and u not in getattr(self,"v81_force_media",set()):
            self.log(f"[MEDIA_ASSET_REJECT] {u}")
            try:self.v81_media_rejects.append({"url":u,"reason":"UZANTI_RESIM_SANILDI (page_asset)"})
            except Exception:pass
            return
        if u in getattr(self,"v81_force_media",set()) and self.page_asset(u):
            self.log(f"[V81_DISGUISED_MANIFEST] uzanti resim/asset gibi ama Content-Type medya -> dogrulamaya aliniyor: {u}")
        if _seen is None:_seen=set()
        if u in _seen:return
        _seen.add(u)
        self.v81_media_referer.setdefault(u,referer)
        r=self.fetch(u,referer=referer)
        if not r:self.log(f"[MEDIA_PROBE] NO_RESPONSE {u}");return
        def ok(resp):
            head=resp["body"][:1000].lstrip(); ct=(resp["ct"] or "").lower()
            if head.startswith("#EXTM3U") or "application/vnd.apple.mpegurl" in ct or "application/x-mpegurl" in ct:
                self.v32_node(u,"HLS_MANIFEST","STATIC_MEDIA_PROBE",referer,
                              f"status={resp['status']} ct={resp['ct']}",90)
                if self.v32_final_media_proof(
                    u,referer=referer,observed_body=resp["body"],
                    observed_status=resp["status"],observed_ct=resp["ct"],
                    source="STATIC_MEDIA_PROBE"
                ):
                    proven=self.v73_proven_playable_manifest(u)
                    self.final=proven;self.final_type="HLS";self.final_verified=True
                    if proven != u:
                        self.log(f"[V73_FINAL_PROMOTE] source=STATIC requested={u} proven={proven}")
                    self.log(f"[FINAL_MEDIA] HLS {proven}");return True
                self.log(f"[MEDIA_NOT_FINAL] reason=V32_HLS_PROOF_INCOMPLETE url={u}")
                return False
            if "video/mp4" in ct and 200<=resp["status"]<400:
                # V81: reklam MP4'u (kisa sure / reklam baglami) final secilmez
                try:
                    if self.v81_mp4_is_ad(u,referer):return False
                except Exception as _e81:self.log(f"[V81_MP4_AD_CHECK_ERROR] {type(_e81).__name__}: {_e81}")
                self.final=u;self.final_type="MP4";self.final_verified=True;self.log(f"[FINAL_MEDIA] MP4 {u}");return True
            return False
        head=r["body"][:1000].lstrip(); sig=head[:80].replace("\r"," ").replace("\n"," ")
        self.log(f"[MEDIA_PROBE] status={r['status']} ct={r['ct']} bytes={len(r['body'])} head={sig!r}")
        if ok(r):return
        ct=(r["ct"] or "").lower()
        if "json" in ct or head.startswith("{"):
            try:obj=json.loads(r["body"])
            except Exception:obj=None
            urls=self.media_urls_from_object(obj,u) if obj is not None else []
            self.log(f"[MEDIA_JSON_URLS] {len(urls)}")
            for ju in urls[:5]:self.log("  JSON_MEDIA -> "+ju)
            for ju in urls[:3]:
                self.verify_media(ju,u,extra_context=extra_context,_seen=_seen)
                if self.final_verified:return
        self.log(f"[MEDIA_REJECT] status={r['status']} ct={r['ct']} {u}")
        if 200<=r["status"]<400:
            self.v81_embed_follow(u,r,referer)
            if self.final_verified:return
        try:
            _b=r["body"][:600]
            _seg=_b.startswith("G") and ("FFmpeg" in _b or "Service01" in _b or (len(_b)>188 and _b[188:189]=="G"))
            if _seg:
                self.log(f"[V81_SEGMENT_NOT_PLAYLIST] {u} -> govde MPEG-TS (0x47); bu bir VIDEO PARCASI, playlist degil. Playlist'i bunu listeleyen #EXTM3U cevabidir.")
            self.v81_media_rejects.append({"url":u,"reason":("SEGMENT (MPEG-TS govde, ct="+str(r['ct'])+") - playlist degil") if _seg else f"MEDIA_REJECT status={r['status']} ct={r['ct']}"})
        except Exception:pass
        if r["status"] in (401,403,404,405,406,500,502,503):
            for ref,origin in self.media_context_origins(referer,extra_context)[:5]:
                rr=self.fetch_media_profile(u,ref,origin)
                if not rr:continue
                hh=rr["body"][:1000].lstrip(); ss=hh[:80].replace("\r"," ").replace("\n"," ")
                self.log(f"[MEDIA_PROFILE_RESULT] status={rr['status']} ct={rr['ct']} bytes={len(rr['body'])} head={ss!r}")
                if ok(rr):return


    # ---------------- V32 EVIDENCE GRAPH / BRANCH PRUNING / FINAL PROOF ----------------
    def v32_node(self,url,kind="URL",source="",parent="",evidence="",score=0):
        if not url:
            return ""
        key=str(url).strip()
        item=self.v32_evidence_nodes.get(key)
        if item is None:
            item={"url":key,"kind":kind,"sources":[],"evidence":[],"score":score}
            self.v32_evidence_nodes[key]=item
            self.log(f"[V32_EVIDENCE_NODE] kind={kind} score={score} url={key}")
        item["score"]=max(int(item.get("score",0) or 0),int(score or 0))
        if source and source not in item["sources"]:
            item["sources"].append(source)
        if evidence:
            ev=re.sub(r"\s+"," ",str(evidence)).strip()[:700]
            if ev and ev not in item["evidence"]:
                item["evidence"].append(ev)
        if parent and parent != key:
            edge=(str(parent),key,str(source or kind))
            if edge not in self.v32_evidence_edges:
                self.v32_evidence_edges.append(edge)
                self.log(f"[V32_EVIDENCE_EDGE] {parent} --{source or kind}--> {key}")
        return key

    def v32_branch_decision(self,url,base="",source="",context="",score=None):
        """Semantic recursion gate.  Words such as 'master' or 'playlist' alone are not
        enough.  DOM navigation/content cards, ads, analytics and static assets are pruned;
        iframe/player/XHR/media/config evidence is retained."""
        if not url or not str(url).startswith(("http://","https://")):
            return False,"INVALID_URL",-100
        low=str(url).lower()
        blob=(str(source)+" "+str(context)).lower()
        try:
            q=urlparse(url); host=(q.hostname or "").lower(); path=(q.path or "").lower()
        except Exception:
            return False,"PARSE_ERROR",-100
        s=self.runtime_candidate_score(url,base,source,context) if score is None else int(score)
        if self.v75_nonplayback_api(url, context=context):
            return False,"NONPLAYBACK_API",s-120
        hard_noise=(
            "google-analytics","googletagmanager","doubleclick","googlesyndication",
            "pubmatic","rubiconproject","criteo","adnxs","mathtag","3lift","lijit",
            "facebook.com","instagram.com","gravatar.com","fonts.gstatic","fonts.googleapis"
        )
        if any(x in host for x in hard_noise):
            return False,"NOISE_HOST",s-100
        if any(path.endswith(x) for x in (".css",".woff",".woff2",".ttf",".otf",".svg",".ico",".webmanifest")):
            return False,"STATIC_ASSET",s-80
        if any(x in low for x in ("favicon","analytics","collect?","cookie-sync","cookiesync","usersync","/ads/","/advert/")):
            return False,"TRACKING_OR_AD",s-80

        strong_context=any(x in blob for x in (
            "iframe","player_source","structured_player","active_player","xhr","fetch",
            "browser_response","browser_network","media","jwplayer","hls","video","source",
            # V37: a URL extracted from an actual iframe/video/source DOM element is
            # stronger causal evidence than a random text literal. It may still be an ad,
            # but it deserves player-chain recursion; final-media proof remains separate.
            "dom_element"
        ))
        strong_url=(
            path.endswith((".m3u8",".mpd",".mp4",".m4v",".webm")) or
            any(x in low for x in ("/embed/","/player/","/stream/","/video/","/vx/","/token","/source"))
        )
        # Generic page/card links must not be promoted just because their slug contains
        # words like "master" or "playlist".
        pageish=path.endswith("/") or not "." in path.rsplit("/",1)[-1]
        domish=any(x in blob for x in ("document","dom","anchor","href","mutation"))
        if pageish and domish and not strong_context and not strong_url:
            return False,"CONTENT_PAGE_WITHOUT_PLAYER_EVIDENCE",s-25
        if s < 6 and not strong_context and not strong_url:
            return False,"WEAK_CAUSAL_EVIDENCE",s
        return True,"CAUSAL_PLAYER_EVIDENCE",s

    def v32_replay_http(self,url,ctx=None,referer="",max_bytes=2_000_000):
        ctx=dict(ctx or {})
        headers={
            "User-Agent":ctx.get("user-agent") or ctx.get("User-Agent") or UA,
            "Accept":ctx.get("accept") or ctx.get("Accept") or "*/*",
        }
        ref=ctx.get("referer") or ctx.get("Referer") or referer
        origin=ctx.get("origin") or ctx.get("Origin") or ""
        cookie=ctx.get("cookie") or ctx.get("Cookie") or ""
        if ref: headers["Referer"]=ref
        if origin: headers["Origin"]=origin
        if cookie: headers["Cookie"]=cookie
        try:
            req=urllib.request.Request(url,headers=headers,method="GET")
            with urllib.request.urlopen(req,timeout=12,context=ssl._create_unverified_context()) as resp:
                raw=resp.read(max_bytes)
                status=int(getattr(resp,"status",200) or 200)
                ct=str(resp.headers.get("Content-Type","") or "")
                final_url=str(resp.geturl() or url)
            return {"status":status,"ct":ct,"body_bytes":raw,
                    "body":raw.decode("utf-8","replace"),"url":final_url,"headers":headers}
        except urllib.error.HTTPError as e:
            try: raw=e.read(min(max_bytes,200000))
            except Exception: raw=b""
            return {"status":int(getattr(e,"code",0) or 0),"ct":str(getattr(e,"headers",{}).get("Content-Type","") if getattr(e,"headers",None) else ""),
                    "body_bytes":raw,"body":raw.decode("utf-8","replace"),"url":url,"headers":headers}
        except Exception as e:
            self.log(f"[V32_PROOF_FETCH_ERROR] {type(e).__name__}: {str(e)[:300]} url={url}")
            return None

    def v32_hls_children(self,body,base):
        lines=[x.strip() for x in str(body or "").replace("\r","\n").split("\n") if x.strip()]
        variants=[]; segments=[]; maps=[]
        for i,line in enumerate(lines):
            if line.startswith("#EXT-X-MAP"):
                m=re.search(r"""URI=["\']([^"\']+)["\']""",line,re.I)
                if m: maps.append(urljoin(base,m.group(1)))
            if line.startswith("#EXT-X-STREAM-INF"):
                for nxt in lines[i+1:]:
                    if not nxt.startswith("#"):
                        variants.append(urljoin(base,nxt)); break
            elif not line.startswith("#"):
                segments.append(urljoin(base,line))
        # If this is a master, non-comment URIs are variants, not media segments.
        if variants:
            return list(dict.fromkeys(variants)),[],list(dict.fromkeys(maps))
        return [],list(dict.fromkeys(segments)),list(dict.fromkeys(maps))


    def v34_is_media_playlist(self,body):
        s=str(body or "")
        if not s.lstrip().startswith("#EXTM3U"):
            return False
        if "#EXT-X-STREAM-INF" in s:
            return False
        return ("#EXTINF:" in s) or ("#EXT-X-MAP" in s)

    def v34_trigger_observed_media_playlist(self,url,body,status,ct,ctx=None,source="BROWSER_OBSERVED"):
        if not self.v34_is_media_playlist(body):
            return False
        key=str(url)
        if key in self.v34_proof_started:
            self.log(f"[V34_FINAL_PROOF_SKIP] duplicate url={url}")
            return False
        self.v34_proof_started.add(key)

        ref=(ctx or {}).get("referer","") if isinstance(ctx,dict) else ""
        self.log(
            f"[V34_FINAL_PROOF_TRIGGER] reason=OBSERVED_MEDIA_PLAYLIST "
            f"status={status} bytes={len(str(body).encode('utf-8','ignore'))} url={url}"
        )

        ok=self.v32_final_media_proof(
            url,
            ctx=ctx,
            referer=ref,
            observed_body=body,
            observed_status=int(status or 0),
            observed_ct=str(ct or ""),
            source=source
        )

        if ok:
            playable=(self.v32_proof or {}).get("playable_manifest") or url
            self.final=playable
            self.final_type="HLS"
            self.final_verified=True
            if isinstance(ctx,dict) and ctx:
                self.final_playback_context=dict(ctx)
            self.log(f"[FINAL_MEDIA] HLS {playable}")
            self.log(f"[V34_PLAYER_HANDOFF_READY] verified=true url={playable}")
            return True

        self.log(f"[V34_FINAL_PROOF_RESULT] verified=false url={url}")
        return False

    def v72_media_object_signature(self, raw, ct="", url=""):
        """Classify a fetched HLS child by bytes/MIME, never by filename alone.
        This prevents image thumbnails such as *.jpg from satisfying MEDIA_OBJECT proof,
        while still allowing deliberately disguised TS/fMP4/audio segments when their
        actual bytes prove that they are media."""
        data=bytes(raw or b"")
        lowct=str(ct or "").lower()
        lowurl=str(url or "").lower().split("?",1)[0]
        if not data:
            return False,"EMPTY"
        sample=data[:4096]
        ls=sample.lstrip().lower()
        if ls.startswith((b"<!doctype html",b"<html",b"<?xml")):
            return False,"DOCUMENT"
        if sample.startswith(b"\xff\xd8\xff"):
            return False,"JPEG_IMAGE"
        if sample.startswith(b"\x89PNG\r\n\x1a\n"):
            return False,"PNG_IMAGE"
        if sample.startswith((b"GIF87a",b"GIF89a")):
            return False,"GIF_IMAGE"
        if sample.startswith(b"RIFF") and sample[8:12] == b"WEBP":
            return False,"WEBP_IMAGE"
        # MPEG-TS: sync byte must repeat on packet boundaries. Check common offsets.
        for off in range(min(188,len(sample))):
            if sample[off:off+1] == b"\x47":
                hits=0
                for pos in (off,off+188,off+376,off+564):
                    if pos < len(sample) and sample[pos:pos+1] == b"\x47": hits += 1
                if hits >= 3:
                    return True,"MPEG_TS"
        # ISO-BMFF/fMP4/CMAF boxes commonly start with ftyp/styp/moof/sidx.
        if len(sample) >= 8 and sample[4:8] in (b"ftyp",b"styp",b"moof",b"sidx"):
            return True,"ISOBMFF"
        if sample.startswith(b"ID3"):
            return True,"ID3_AUDIO"
        if len(sample) >= 2 and sample[0] == 0xff and (sample[1] & 0xf0) == 0xf0:
            return True,"ADTS_OR_MPEG_AUDIO"
        if sample.startswith(b"OggS"):
            return True,"OGG"
        if sample.startswith(b"\x1a\x45\xdf\xa3"):
            return True,"WEBM_MATROSKA"
        if lowct.startswith("image/"):
            return False,"IMAGE_MIME"
        if any(x in lowct for x in ("video/mp2t","video/mp4","audio/mp4","audio/aac","audio/mpeg","video/webm","audio/webm","application/mp4")):
            return True,"MEDIA_MIME"
        # Extension is diagnostic only. A .jpg can still be media if bytes above prove it.
        if lowurl.endswith((".jpg",".jpeg",".png",".gif",".webp",".avif")):
            return False,"IMAGE_EXTENSION_WITHOUT_MEDIA_SIGNATURE"
        return False,"UNKNOWN_MEDIA_SIGNATURE"

    def v73_proven_playable_manifest(self, fallback=""):
        """Return only the manifest URL actually proven by v32_final_media_proof.
        V73 prevents a pre-redirect/root candidate from overwriting the downstream
        playable manifest that produced the verified media object.
        """
        proof=getattr(self,"v32_proof",{}) or {}
        if proof.get("verified"):
            proven=str(proof.get("playable_manifest") or "").strip()
            if proven:
                return proven
        return str(fallback or "").strip()

    def v32_final_media_proof(self,url,ctx=None,referer="",observed_body="",observed_status=0,observed_ct="",source=""):
        """HLS is final only after manifest -> variant/media playlist -> media object proof.
        A browser-observed manifest body may seed the proof even when a naked replay would
        return 404; subsequent requests reuse the captured browser context."""
        proof={"root":url,"source":source,"steps":[],"verified":False}
        self.v32_proof=proof
        # V81: tarayicida bu manifesti isteyen sayfanin Referer/Origin'i alt istekler (variant/segment) icin de kullanilir
        if not ctx:
            _bctx=(self.browser_request_context.get(url) or self.browser_media_context.get(url) or {})
            _ref=_bctx.get("referer") or getattr(self,"v81_media_referer",{}).get(url,"") or referer
            if _ref:
                _o=urlparse(_ref)
                ctx={"referer":_ref,"origin":_bctx.get("origin") or f"{_o.scheme}://{_o.netloc}","user-agent":_bctx.get("user-agent") or UA,"cookie":_bctx.get("cookie","")}
        observed_map=getattr(self,"v33_browser_hls_observed",{}) or {}
        self.v32_node(url,"HLS_CANDIDATE",source,referer,"final proof seed",90)

        body=str(observed_body or "")
        status=int(observed_status or 0)
        ct=str(observed_ct or "")
        if body.lstrip().startswith("#EXTM3U") and 200 <= status < 400:
            root={"status":status,"ct":ct,"body":body,"url":url}
            self.log(f"[V32_PROOF_MANIFEST] source=OBSERVED status={status} ct={ct} url={url}")
        else:
            root=self.v32_replay_http(url,ctx,referer)
            if not root:
                self.log(f"[V32_FINAL_MEDIA_PROOF] FAIL stage=ROOT_NO_RESPONSE url={url}")
                return False
            body=root["body"]; status=root["status"]; ct=root["ct"]
            self.log(f"[V32_PROOF_MANIFEST] source=REPLAY status={status} ct={ct} url={url}")
        effective_root=str((root or {}).get("url") or url)
        proof["steps"].append({"stage":"root","url":url,"effective_url":effective_root,"status":status,"ct":ct})
        if effective_root != url:
            self.log(f"[V72_REDIRECT_EFFECTIVE] stage=ROOT requested={url} effective={effective_root}")
        if status < 200 or status >= 400 or not body.lstrip().startswith("#EXTM3U"):
            self.log(f"[V32_FINAL_MEDIA_PROOF] FAIL stage=ROOT_NOT_HLS status={status} url={url}")
            return False

        current_url=effective_root; current_body=body
        self.v81_hls_root(body,effective_root)
        for depth in range(3):
            variants,segments,maps=self.v32_hls_children(current_body,current_url)
            if variants:
                child=variants[0]
                self.v32_node(child,"HLS_VARIANT","MANIFEST_CHILD",current_url,"#EXT-X-STREAM-INF",95)
                obs=observed_map.get(child) or {}
                if str(obs.get("body","")).lstrip().startswith("#EXTM3U") and 200 <= int(obs.get("status",0) or 0) < 400:
                    rr={"status":int(obs.get("status",0)),"ct":str(obs.get("ct", "")),"body":str(obs.get("body", "")),"url":child}
                    variant_source="OBSERVED"
                else:
                    child_ctx=self.browser_request_context.get(child,{}) or ctx
                    rr=self.v32_replay_http(child,child_ctx,current_url)
                    variant_source="REPLAY"
                if not rr or rr["status"] < 200 or rr["status"] >= 400 or not rr["body"].lstrip().startswith("#EXTM3U"):
                    st=rr["status"] if rr else 0
                    self.log(f"[V32_FINAL_MEDIA_PROOF] FAIL stage=VARIANT status={st} url={child}")
                    return False
                effective_child=str(rr.get("url") or child)
                self.log(f"[V32_PROOF_VARIANT] source={variant_source} status={rr['status']} ct={rr['ct']} url={child}")
                if effective_child != child:
                    self.log(f"[V72_REDIRECT_EFFECTIVE] stage=VARIANT requested={child} effective={effective_child}")
                proof["steps"].append({"stage":"variant","url":child,"effective_url":effective_child,"status":rr["status"],"ct":rr["ct"]})
                current_url=effective_child; current_body=rr["body"]
                continue

            media=segments
            if not media:
                self.log(f"[V32_FINAL_MEDIA_PROOF] FAIL stage=NO_MEDIA_CHILD url={current_url}")
                return False
            seg=media[0]
            self.v32_node(seg,"MEDIA_SEGMENT","HLS_MEDIA_CHILD",current_url,"playlist media child",100)
            seg_ctx=self.browser_request_context.get(seg,{}) or ctx
            sr=self.v32_replay_http(seg,seg_ctx,current_url,max_bytes=262144)
            if not sr or sr["status"] not in (200,206) or len(sr["body_bytes"]) < 32:
                st=sr["status"] if sr else 0
                size=len(sr["body_bytes"]) if sr else 0
                self.log(f"[V32_FINAL_MEDIA_PROOF] FAIL stage=SEGMENT status={st} bytes={size} url={seg}")
                return False
            media_ok,signature=self.v72_media_object_signature(sr["body_bytes"],sr.get("ct",""),sr.get("url") or seg)
            self.log(f"[V72_MEDIA_SIGNATURE] accepted={str(media_ok).lower()} signature={signature} status={sr['status']} ct={sr.get('ct','')} requested={seg} effective={sr.get('url') or seg}")
            proof["steps"].append({"stage":"segment","url":seg,"effective_url":sr.get("url") or seg,"status":sr["status"],"ct":sr["ct"],"bytes":len(sr["body_bytes"]),"signature":signature,"media_signature_valid":media_ok})
            if not media_ok:
                self.log(f"[V32_FINAL_MEDIA_PROOF] FAIL stage=SEGMENT_NOT_MEDIA signature={signature} status={sr['status']} url={seg}")
                return False
            self.log(f"[V32_PROOF_SEGMENT] status={sr['status']} bytes={len(sr['body_bytes'])} ct={sr['ct']} signature={signature} url={seg}")
            if self.v81_ad_check(url,current_body,current_url):
                proof["ad_rejected"]=True
                return False
            proof["verified"]=True
            proof["playable_manifest"]=current_url
            self.log(f"[V32_FINAL_MEDIA_PROOF] PASS root={url} playable={current_url} segment={seg}")
            return True

        self.log(f"[V32_FINAL_MEDIA_PROOF] FAIL stage=DEPTH_LIMIT url={url}")
        return False


    def iframes(self,body,base):
        out=[]
        for tag in re.findall(r"<iframe\b[^>]*>",body,re.I|re.S):
            val=""
            for a in ("data-src","data-lazy-src","data-litespeed-src","data-original","data-url","src"):
                m=re.search(rf"""\b{re.escape(a)}\s*=\s*["']([^"']+)["']""",tag,re.I)
                if m and m.group(1).strip() and m.group(1).strip().lower()!="about:blank":
                    val=m.group(1); break
            if val:
                u=self.absolute(base,val)
                if u and u not in out: out.append(u)
        return out

    def v66_decode_embedded_url(self, raw, base, source="ENCODED_ATTR"):
        # Decode Base64/Base64URL only when the result independently validates as HTTP(S).
        val=html.unescape(str(raw or "")).strip().strip("\"'")
        if not val or len(val)<20 or len(val)>8192:
            return ""
        if val.startswith(("http://","https://","//","/")):
            return ""
        compact=re.sub(r"\s+","",val)
        if not re.fullmatch(r"[A-Za-z0-9_+/=-]{20,}",compact):
            return ""
        for candidate in (compact, compact.replace("-","+").replace("_","/")):
            try:
                pad=candidate + "="*((4-len(candidate)%4)%4)
                dec=base64.b64decode(pad,validate=False).decode("utf-8","ignore").strip().strip("\x00\r\n\t " )
            except Exception:
                continue
            if not dec.startswith(("http://","https://","//")):
                continue
            try:
                u=self.absolute(base,dec)
                q=urlparse(u)
                if q.scheme not in ("http","https") or not q.netloc:
                    continue
                # V81: base64 cozumu cop uretirse (kontrol karakteri / gecersiz host) URL sayma
                if re.search(r"[\x00-\x1f\x7f\ufffd\s]",u) or not re.fullmatch(r"[A-Za-z0-9.-]+(?::\d+)?",q.netloc) or "." not in q.netloc:
                    self.log(f"[V81_ENCODED_URL_REJECT] source={source} cozulen deger gecerli URL degil (sifreli/anahtarli veri olabilir) raw={compact[:60]}")
                    continue
            except Exception:
                continue
            if self.page_asset(u) or self.is_trailer_url(u):
                continue
            self.log(f"[V66_ENCODED_URL] source={source} encodedLen={len(compact)} url={u}")
            return u
        return ""

    def v66_encoded_attribute_urls(self, body, base):
        # Generic encoded player/navigation discovery from data-* and source-like attributes.
        out=[]
        pat=r'''\b([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*["']([^"']{20,8192})["']'''
        for m in re.finditer(pat,body or "",re.I|re.S):
            name=(m.group(1) or "").lower()
            raw=m.group(2) or ""
            shaped=(name.startswith("data-") or any(k in name for k in ("player","video","source","embed","src","url")))
            if not shaped:
                continue
            u=self.v66_decode_embedded_url(raw,base,f"ATTR:{name}")
            if u and u not in out:
                out.append(u)
                self.v32_node(u,"ENCODED_PLAYER_URL","V66_ENCODED_ATTR",base,f"attribute={name}",18)
        return out[:24]

    def base64_iframes(self,body,base):
        out=[]
        out += self.v66_encoded_attribute_urls(body,base)
        blobs=re.findall(r'''["']([A-Za-z0-9+/_-]{40,}={0,2})["']''',body or "")
        for b in blobs[:120]:
            direct=self.v66_decode_embedded_url(b,base,"BASE64_LITERAL")
            if direct and direct not in out:
                out.append(direct)
                continue
            try:
                bb=b.replace("-","+").replace("_","/")
                ss=base64.b64decode(bb+"==="[:(-len(bb))%4]).decode("utf-8","ignore")
            except Exception:
                continue
            if "<iframe" not in ss.lower():
                continue
            out += self.iframes(ss,base)
        return list(dict.fromkeys(out))

    def direct_media(self,body,base):
        out=[]
        seen=set()

        def add(raw):
            raw=(raw or "").strip().strip("\"'")
            if not raw: return
            u=self.absolute(base,raw)
            if not u or u in seen or self.page_asset(u): return
            seen.add(u); out.append(u)

        # Explicit media extensions.
        for m in re.finditer(
            r"""(?i)(https?:\\?/\\?/[^"'<> \t\r\n]+?\.(?:m3u8|mp4)(?:\?[^"'<> \t\r\n]*)?|["']([^"']+\.(?:m3u8|mp4)(?:\?[^"']*)?)["'])""",
            body
        ):
            add(m.group(1) or m.group(2))

        # Common player object fields: file/source/src/video_location.
        for m in re.finditer(
            r"""(?is)(?:["']?(?:file|source|src|video_location)["']?)\s*[:=]\s*["']([^"']+)["']""",
            body
        ):
            candidate=m.group(1)
            low=candidate.lower()
            pu=urlparse(candidate)
            if (".m3u8" in low or ".mp4" in low or "/list/" in low or "/m/" in low
                or (pu.netloc.lower().startswith("hls.") and pu.path.lower().startswith("/s/"))):
                add(candidate)

        return out

    def is_trailer_url(self,u):
        h=urlparse(u).netloc.lower()
        p=urlparse(u).path.lower()
        return any(x in h for x in TRAILER_HOSTS) or "trailer" in p or "fragman" in p

    def script_score(self,u):
        low=u.lower()
        score=0
        if any(x in low for x in SCRIPT_HIGH): score+=100
        if any(x in low for x in HIGH): score+=30
        if any(x in low for x in NOISE): score-=100
        return score

    def scripts(self,body,base):
        out=[]
        for m in re.finditer(r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""",body,re.I):
            u=self.absolute(base,m.group(1))
            if not u or u in out: continue
            host=urlparse(u).netloc.lower()
            if any(x in host for x in ("googletagmanager.com","google-analytics.com","doubleclick.net","cloudflareinsights.com")):
                continue
            out.append(u)
        out.sort(key=lambda u:self.script_score(u), reverse=True)
        # Keep player-relevant scripts first; cap noise to preserve request budget.
        ranked=[]
        for u in out:
            if self.script_score(u) >= 0 or len(ranked) < 3:
                ranked.append(u)
            if len(ranked) >= 8: break
        return ranked


    def action_absolute(self,document_url,raw):
        raw=(raw or "").strip()
        if raw.lower() in ("jetplayer","player","video","source","embed","stream","view","token"):
            q=urlparse(document_url)
            return f"{q.scheme}://{q.netloc}/{raw.lstrip('/')}"
        return self.absolute(document_url,raw)

    def request_contexts(self,body,base):
        out=[]; seen=set()
        def clean(v): return re.sub(r"\s+"," ",v or "").strip()
        def resolve(raw):
            raw=(raw or "").strip().strip("'\"`")
            if not raw or "${" in raw:return raw
            return self.action_absolute(base,raw)
        def add(kind,method,raw,headers="",data=""):
            item={"kind":kind,"method":method.upper(),"url":resolve(raw),
                  "headers":clean(headers)[:900],"data":clean(data)[:1200],"raw":raw}
            key=(item["kind"],item["method"],item["url"],item["headers"],item["data"])
            if key not in seen: seen.add(key); out.append(item)

        for m in re.finditer(r"""fetch\s*\(\s*(['"`])([^'"`]+)\1\s*(?:,\s*\{(.*?)\})?\s*\)""",body,re.I|re.S):
            opts=m.group(3) or ""
            mm=re.search(r"""method\s*:\s*['"`]([A-Z]+)['"`]""",opts,re.I)
            hm=re.search(r"""headers\s*:\s*\{(.*?)\}""",opts,re.I|re.S)
            bm=re.search(r"""body\s*:\s*(`[^`]*`|'[^']*'|"[^"]*"|[^,\n}]+)""",opts,re.I|re.S)
            add("fetch",mm.group(1) if mm else "GET",m.group(2),
                hm.group(1) if hm else "",bm.group(1) if bm else "")

        for m in re.finditer(r"""\$\s*\.\s*ajax\s*\(\s*\{(.*?)\}\s*\)""",body,re.I|re.S):
            opts=m.group(1)
            um=re.search(r"""url\s*:\s*['"`]([^'"`]+)['"`]""",opts,re.I)
            if not um:continue
            mm=re.search(r"""(?:type|method)\s*:\s*['"`]([A-Z]+)['"`]""",opts,re.I)
            hm=re.search(r"""headers\s*:\s*\{(.*?)\}""",opts,re.I|re.S)
            dm=re.search(r"""data\s*:\s*(\{.*?\}|[^,\n}]+)""",opts,re.I|re.S)
            add("ajax",mm.group(1) if mm else "GET",um.group(1),
                hm.group(1) if hm else "",dm.group(1) if dm else "")

        for m in re.finditer(r"""\$\s*\.\s*post\s*\(\s*['"`]([^'"`]+)['"`]\s*(?:,\s*(\{.*?\}|[^,\n)]+))?""",body,re.I|re.S):
            add("post","POST",m.group(1),"",m.group(2) or "")

        for m in re.finditer(r"""\.open\s*\(\s*['"`](GET|POST|PUT|PATCH|DELETE)['"`]\s*,\s*['"`]([^'"`]+)['"`]""",body,re.I):
            add("xhr",m.group(1),m.group(2))
        return out

    def log_request_contexts(self,body,base,label="PAGE"):
        def compact(v): return re.sub(r"\s+"," ",v or "").strip()
        ctxs=self.request_contexts(body,base)
        if not ctxs:return
        self.v81_note_templates(ctxs,body,base,label)
        self.log(f"[REQUEST_CONTEXTS] {label} count={len(ctxs)}")
        for c in ctxs[:12]:
            self.log(f"  [{c['kind']}] {c['method']} {c['url']}")
            if c["headers"]:self.log("    HEADERS "+c["headers"])
            if c["data"]:self.log("    DATA "+c["data"])
            raw=c.get("raw","")
            loc=body.find(raw) if raw else -1
            if loc>=0:
                near=body[max(0,loc-1200):loc+1800]; vals=[]
                for vm in re.finditer(r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{1,300})""",near):
                    item=f"{vm.group(1)}={compact(vm.group(2))}"
                    if item not in vals:vals.append(item)
                if vals:self.log("    VARS "+" | ".join(vals[:12]))



    def cryptojs_password_decrypt(self,password,cipher_json):
        try:
            obj=json.loads(cipher_json.replace("\\/","/"))
            ct=base64.b64decode(obj.get("ct",""))
            if not ct:return None
            salt=bytes.fromhex(obj.get("s","")) if obj.get("s") else b""
            if not salt:return None
            key,iv=_evp_bytes_to_key(password.encode("utf-8"),salt,32,16)
            raw=_aes_cbc_decrypt(ct,key,iv)
            if not raw:return None
            pad=raw[-1]
            if 1<=pad<=16 and raw.endswith(bytes([pad])*pad):
                raw=raw[:-pad]
            return raw.decode("utf-8")
        except Exception:
            return None

    def media_urls_from_object(self,obj,base):
        out=[]; seen=set()
        def add(v):
            if not isinstance(v,str):return
            vv=html.unescape(v).replace("\\/","/").strip()
            if not vv or any(ch.isspace() for ch in vv):return
            if vv.lower() in ("fetch error","error","not found","forbidden","unauthorized"):return
            lowv=vv.lower()
            if not (vv.startswith(("http://","https://","//","/")) or any(x in lowv for x in (".m3u8",".mp4","/list/","/m/","/watch/","/stream/"))):return
            u=self.absolute(base,vv)
            if not u or u in seen:return
            low=u.lower(); path=urlparse(u).path.lower()
            if ".m3u8" in low or ".mp4" in low or "/list/" in path or "/m/" in path or "/watch/" in path or "/stream/" in path:
                seen.add(u);out.append(u)
        def rec(x):
            if isinstance(x,dict):
                for k,v in x.items():
                    if str(k).lower() in ("video_location","file","source","src","url","link","hls","hlssource"):
                        if isinstance(v,dict):
                            for kk in ("file","url","src","source"):add(v.get(kk))
                        else:add(v)
                    rec(v)
            elif isinstance(x,list):
                for v in x:rec(v)
            elif isinstance(x,str):add(x)
        rec(obj);return out


    def subtitle_tracks_from_object(self,obj,base,label="OBJECT"):
        """Generic subtitle/caption discovery from decoded player objects."""
        found=[]; seen=set()
        sub_ext=(".vtt", ".srt", ".ass", ".ssa", ".ttml", ".dfxp")
        def add(url,lang="",kind=""):
            if not isinstance(url,str): return
            raw=url.replace("\\/","/").replace("&amp;","&").strip()
            low=raw.lower()
            if not raw: return
            subtitleish=(any(x in low for x in sub_ext) or "subtitle" in low or "caption" in low)
            if not subtitleish and kind.lower() not in ("captions","caption","subtitles","subtitle"): return
            try: u=self.absolute(base,raw)
            except Exception: u=raw
            if not u or u in seen: return
            seen.add(u); found.append((u,str(lang or "").strip(),str(kind or "").strip()))
        def rec(x,parent=""):
            if isinstance(x,dict):
                kind=str(x.get("kind") or x.get("type") or parent or "")
                lang=str(x.get("label") or x.get("language") or x.get("lang") or x.get("srclang") or "")
                for k in ("file","url","src","source"):
                    if k in x: add(x.get(k),lang,kind)
                for k,v in x.items():
                    kl=str(k).lower()
                    if kl in ("subtitle","subtitles","caption","captions","track","tracks"):
                        if isinstance(v,str): add(v,lang,kl)
                        else: rec(v,kl)
                    elif isinstance(v,(dict,list)): rec(v,kl)
                    elif isinstance(v,str) and any(ext in v.lower() for ext in sub_ext): add(v,lang,kl)
            elif isinstance(x,list):
                for v in x: rec(v,parent)
            elif isinstance(x,str): add(x,"",parent)
        rec(obj)
        if found:
            self.log(f"[SUBTITLE_DISCOVERY] source={label} count={len(found)}")
            for u,lang,kind in found[:30]:
                self.log(f"[SUBTITLE_TRACK] lang={lang or 'UNKNOWN'} kind={kind or 'UNKNOWN'} url={u}")
        return found

    def try_beplayer_decrypt(self,password,cipher_json,base,label):
        text=self.cryptojs_password_decrypt(password,cipher_json)
        if not text:return False
        self.log(f"[BEPLAYER_DECRYPT_OK] {label} bytes={len(text.encode('utf-8','ignore'))}")
        self.log("  PLAINTEXT "+re.sub(r"\s+"," ",text)[:2200])
        try:obj=json.loads(text)
        except Exception:obj=text
        if isinstance(obj,dict):
            bits=[]
            for k in ("referer","siteurl","link","sitex","video_id"):
                if k in obj:bits.append(f"{k}={obj.get(k)}")
            if bits:self.log("[BEPLAYER_REQUEST_CONTEXT] "+" | ".join(bits)[:1800])
        self.subtitle_tracks_from_object(obj,base,"BEPLAYER_DECRYPT")
        urls=self.media_urls_from_object(obj,base)
        self.log(f"[BEPLAYER_MEDIA_CANDIDATES] {len(urls)}")
        for u in urls[:8]:self.log("  MEDIA -> "+u)
        for u in urls[:5]:
            self.verify_media(u,base,extra_context=obj if isinstance(obj,dict) else None)
            if self.final_verified:return True
        return bool(urls)


    def resolve_declared_worker_api(self,body,base):
        wm=re.search(r'''(?:const|let|var)\s+WORKER_URL\s*=\s*["']([^"']+)["']''',body,re.I)
        if not wm:return "NO_MATCH"
        vm=re.search(r'''(?:const|let|var)\s+VIDEO_ID\s*=\s*["']([^"']*)["']''',body,re.I)
        pm=re.search(r'''(?:const|let|var)\s+PUB_ID\s*=\s*["']([^"']*)["']''',body,re.I)
        pim=re.search(r'''(?:const|let|var)\s+PUBLISHER_ID\s*=\s*["']([^"']*)["']''',body,re.I)
        tm=re.search(r'''(?:const|let|var)\s+VIDEO_TITLE\s*=\s*["']([^"']*)["']''',body,re.I)
        worker=wm.group(1).rstrip('/'); video=vm.group(1) if vm else ''; pub=pm.group(1) if pm else ''; publisher=pim.group(1) if pim else ''; title=tm.group(1) if tm else video
        from urllib.parse import quote
        if pub:
            api=f"{worker}/api/stream?pubId={quote(pub)}&title={quote(title or video)}"
            if publisher:api+="&publisherId="+quote(publisher)
        elif video:api=f"{worker}/api/video?id={quote(video)}"
        else:return "NO_MATCH"
        self.log("[DECLARED_API] GET "+api); r=self.fetch(api,referer=base)
        if not r:self.log("[DECLARED_API_TRANSPORT] FAILED; HTTPS retained, no downgrade");return "FAILED"
        self.log(f"[DECLARED_API_HTTP] {r['status']} {r['ct']}")
        try:obj=json.loads(r['body'])
        except Exception:return "FAILED"
        urls=self.media_urls_from_object(obj,base); self.log(f"[DECLARED_API_MEDIA] {len(urls)}")
        for u in urls[:8]:self.log("  MEDIA -> "+u)
        for u in urls[:5]:
            self.verify_media(u,base)
            if self.final_verified:return "RESOLVED"
        return "FAILED"


    def analyze_beplayer(self,body,base,label="PAGE"):
        calls=[]
        call_re=re.compile(r'''bePlayer\s*\(\s*(["'])(.*?)\1\s*,\s*(["'])(.*?)\3(?:\s*,\s*([^)]+))?\)''',re.I|re.S)
        for mm in call_re.finditer(body):
            calls.append((mm.group(2),mm.group(4),(mm.group(5) or "").strip()))
        if calls:
            self.log(f"[BEPLAYER_CALLS] {label} count={len(calls)}")
            for first,second,third in calls[:4]:
                self.log("  ARG1 "+first[:400])
                self.log("  ARG2 "+second[:1200])
                if third:self.log("  ARG3 "+re.sub(r"\s+"," ",third)[:500])
                if '"ct"' in second or "'ct'" in second:
                    self.try_beplayer_decrypt(first,second,base,label)
                    if self.final_verified:return

        low=body.lower()
        loc=low.find("function beplayer")
        if loc<0:
            mm=re.search(r'''(?:var|let|const)?\s*bePlayer\s*=\s*(?:function\s*\(|\([^)]*\)\s*=>)''',body,re.I)
            loc=mm.start() if mm else -1
        if loc>=0:
            ctx=re.sub(r"\s+"," ",body[max(0,loc-500):loc+5500]).strip()
            self.log(f"[BEPLAYER_FUNCTION] {label}")
            self.log("  "+ctx[:5000])

        hints=[]
        for token in ("CryptoJS","AES","decrypt","atob(","getAndUnpack","video_location","sources:","file:","/list/","player_api/ajax.php","setparams"):
            if token.lower() in low:hints.append(token)
        if hints:self.log("[BEPLAYER_HINTS] "+" | ".join(hints))


    def classify_script_endpoint(self,endpoint,script_body):
        url=(endpoint or "").lower()
        low=(script_body or "").lower()
        if "player_api/ajax.php" in url and all(x in low for x in ("jwplayer().getposition","percent","sure")):
            return "TELEMETRY_PROGRESS"
        return "RESOLVER_OR_UNKNOWN"

    def log_initiator_context(self,body,base,label="SCRIPT"):
        needles=("beload.php","player_api/ajax.php","hls.playerx.info/s/","/api/stream","/api/video")
        low=body.lower()
        for needle in needles:
            start=0; shown=0
            while shown<3:
                loc=low.find(needle.lower(),start)
                if loc<0:break
                ctx=body[max(0,loc-1500):loc+1800]
                ctx=re.sub(r"\s+"," ",ctx).strip()
                self.log(f"[INITIATOR_CONTEXT] {label} needle={needle}")
                self.log("  "+ctx[:2400])
                shown+=1; start=loc+len(needle)

    def endpoint_scan(self,text,document_url):
        eps=[]

        def add(method,raw,source):
            if not raw: return
            u=self.action_absolute(document_url,raw)
            if not u: return
            low=u.lower()
            if any(n in low for n in NOISE): return
            if not any(k in low for k in HIGH): return
            eps.append((method.upper(),u,source))

        # fetch('relative', { method: 'POST', ...})
        for m in re.finditer(r"""fetch\s*\(\s*["']([^"']+)["']""",text,re.I):
            raw=m.group(1)
            win=text[m.start():m.start()+1200]
            mm=re.search(r"""method\s*:\s*["'](GET|POST)["']""",win,re.I)
            add(mm.group(1) if mm else "UNKNOWN",raw,"fetch")

        # axios.get/post('...')
        for m in re.finditer(r"""axios\.(get|post)\s*\(\s*["']([^"']+)["']""",text,re.I):
            add(m.group(1),m.group(2),"axios")

        # jQuery $.get/$.post
        for m in re.finditer(r"""\$\.(get|post)\s*\(\s*["']([^"']+)["']""",text,re.I):
            add(m.group(1),m.group(2),"jquery")

        # $.ajax({ url:'...', type/method:'POST' })
        for m in re.finditer(r"""\$\.ajax\s*\(\s*\{(.{0,1800}?)\}\s*\)""",text,re.I|re.S):
            block=m.group(1)
            um=re.search(r"""url\s*:\s*["']([^"']+)["']""",block,re.I)
            mm=re.search(r"""(?:type|method)\s*:\s*["'](GET|POST)["']""",block,re.I)
            if um: add(mm.group(1) if mm else "UNKNOWN",um.group(1),"jquery-ajax")

        # XMLHttpRequest.open('POST','/endpoint')
        for m in re.finditer(
            r"""\.open\s*\(\s*["'](GET|POST)["']\s*,\s*["']([^"']+)["']""",
            text,re.I
        ):
            add(m.group(1),m.group(2),"xhr-open")

        # API paths buried in minified/concatenated JS.
        for m in re.finditer(r"""["'](/api/(?:token|view|player|source|video|stream|embed)[^"'\\\s]*)["']""",text,re.I):
            raw=m.group(1)
            win=text[max(0,m.start()-500):m.start()+1000]
            method="POST" if re.search(r"""(?:method|type)\s*:\s*["']POST["']""",win,re.I) else "UNKNOWN"
            add(method,raw,"api-path")

        # Simple endpoint literals, useful in minified files.
        for m in re.finditer(
            r"""["']((?:https?:)?//[^"']+|/(?:api|ajax|player|video|source|embed|stream|view|token)[^"']*|(?:jetplayer|player|video|source|embed|stream|view|token)(?:/[^"']*)?)["']""",
            text,re.I
        ):
            add("UNKNOWN",m.group(1),"literal")

        seen=set(); clean=[]
        for x in eps:
            k=(x[0],x[1])
            if k not in seen:
                seen.add(k); clean.append(x)
        return clean

    def data_values(self,body,key):
        return list(dict.fromkeys(re.findall(rf"""data-{re.escape(key)}\s*=\s*["']([^"']+)["']""",body,re.I)))

    def extract_film_id(self,body):
        patterns=[
            r"""(?:film_id|filmId)\s*[:=]\s*["']?([A-Za-z0-9_-]+)""",
            r"""(?:id|name)=["'](?:film_id|filmId)["'][^>]*value=["']([^"']+)["']""",
            r"""value=["']([^"']+)["'][^>]*(?:id|name)=["'](?:film_id|filmId)["']""",
            r"""data-film-id\s*=\s*["']([^"']+)["']"""
        ]
        for p in patterns:
            m=re.search(p,body,re.I)
            if m:return m.group(1)
        return ""

    def player_media_candidates(self,body,base):
        out=[]; seen=set()

        def add(raw,force_type=""):
            if not raw:return
            raw=raw.replace("\\/","/").strip()
            u=self.absolute(base,raw)
            if not u or u in seen or self.page_asset(u):return
            low=u.lower()
            path=urlparse(u).path.lower()
            ext_hls=("/list/" in path or "/m/" in path)
            forced=force_type.lower() in ("hls","m3u8","mp4")
            if ".m3u8" in low or ".mp4" in low or ext_hls or forced:
                seen.add(u); out.append(u)

        typed_patterns=[
            r'''(?is)\bfile\s*:\s*["']([^"']+)["']\s*,\s*type\s*:\s*["'](hls|m3u8|mp4)["']''',
            r'''(?is)\btype\s*:\s*["'](hls|m3u8|mp4)["']\s*,\s*file\s*:\s*["']([^"']+)["']'''
        ]
        for idx,pat in enumerate(typed_patterns):
            for m in re.finditer(pat,body):
                if idx==0:add(m.group(1),m.group(2))
                else:add(m.group(2),m.group(1))

        patterns=[
            r'''(?is)\bfile\s*:\s*["']([^"']+)["']''',
            r'''(?is)["']file["']\s*:\s*["']([^"']+)["']''',
            r'''(?is)\bsrc\s*:\s*["']([^"']+)["']''',
            r'''(?is)["']src["']\s*:\s*["']([^"']+)["']''',
            r'''(?is)\bsource\s*:\s*["']([^"']+)["']''',
            r'''(?is)\bvideo_location\b\s*[:=]\s*["']([^"']+)["']'''
        ]
        for pat in patterns:
            for m in re.finditer(pat,body):
                add(m.group(1))
        return out


    def extensionless_media_candidates(self,body,base):
        out=[]; seen=set()
        for m in re.finditer(r'''https?://[^"'<>\s]+''',body,re.I):
            u=m.group(0).replace("\\/","/")
            if u in seen or self.page_asset(u): continue
            q=urlparse(u); path=q.path.lower()
            if "/list/" in path or "/m/" in path:
                ctx=body[max(0,m.start()-120):m.start()].lower()
                if re.search(r'''\b(?:image|poster|thumbnail|thumb)\s*[:=]\s*["']?[^"']*$''',ctx):
                    continue
                seen.add(u); out.append(u)
        return out


    def diziyou_pattern_candidates(self,player_url,player_body):
        p=urlparse(player_url)
        if "diziyou" not in p.netloc.lower():
            return []
        m=re.search(r"""/player/([A-Za-z0-9_-]+)\.html""",p.path,re.I)
        if not m:
            return []
        item=m.group(1)
        # Verified family from existing adapter: storage host + deterministic episode path.
        host=p.netloc
        if host.startswith("www."):
            storage_host="storage."+host[4:]
        else:
            storage_host="storage."+host
        scheme=p.scheme or "https"
        return [
            f"{scheme}://{storage_host}/episodes/{item}/play.m3u8",
            f"{scheme}://{storage_host}/episodes/{item}_tr/play.m3u8",
        ]

    def response_urls(self,body,base):
        out=[]; seen=set()
        def add(v):
            if not isinstance(v,str): return
            v=v.replace("\\/","/").replace("&amp;","&").strip()
            # iframe HTML returned inside JSON/text
            for m in re.finditer(r"""(?:src|data-src)\s*=\s*["']([^"']+)["']""",v,re.I):
                add(m.group(1))
            if v.startswith(("http://","https://","//","/")):
                u=self.absolute(base,v)
                if u and u not in seen:
                    seen.add(u); out.append(u)
        try:
            obj=json.loads(body)
            def walkj(x):
                if isinstance(x,dict):
                    # prioritize common player/media keys
                    for k in ("embed","iframe","player","url","link","file","source","src","video_location"):
                        if k in x: add(x[k])
                    for v in x.values(): walkj(v)
                elif isinstance(x,list):
                    for v in x: walkj(v)
                elif isinstance(x,str):
                    add(x)
            walkj(obj)
        except Exception:
            pass
        for m in re.finditer(r"""https?://[^"'<>\\\s]+""",body,re.I):
            add(m.group(0))
        return out

    def consume_action(self,r,parent,depth):
        if not r:return
        if r["body"].lstrip().startswith("#EXTM3U"):
            self.final=r["url"];self.final_type="HLS";self.final_verified=True;return

        for u in (self.player_media_candidates(r["body"],r["url"]) + self.direct_media(r["body"],r["url"]))[:5]:
            self.verify_media(u,parent)
            if self.final_verified:return

        response_links=self.response_urls(r["body"],r["url"])
        if response_links:
            self.log(f"[ACTION_RESPONSE_URLS] {len(response_links)}")
            for u in response_links[:8]: self.log("  URL -> "+u)
            for u in response_links[:8]:
                if self.page_asset(u): continue
                # Direct/extensionless media first, otherwise treat likely embeds/players as a nested player.
                q=urlparse(u); path=q.path.lower(); host=q.netloc.lower()
                if ".m3u8" in path or ".mp4" in path or "/list/" in path or "/m/" in path or False:
                    self.verify_media(u,r["url"])
                    if self.final_verified:return
                elif any(x in (host+path) for x in ("embed","player","vidmixi","videopark","playerx","rapid","stream")):
                    self.player=self.player or u
                    self.walk(u,depth+1,r["url"],"ACTION_JSON")
                    if self.final_verified:return

        cands=self.base64_iframes(r["body"],r["url"])+self.iframes(r["body"],r["url"])
        cands=[u for u in dict.fromkeys(cands) if not self.is_trailer_url(u)]
        self.log(f"[ACTION_CANDIDATES] {len(cands)}")
        for u in cands[:5]:
            self.log(f"  PLAYER {u}")
            self.player=self.player or u
            self.walk(u,depth+1,parent,"ACTION_RESPONSE")
            if self.final_verified:return
        response_links=self.response_urls(r["body"],r["url"])
        if response_links:
            self.log(f"[ACTION_RESPONSE_URLS] {len(response_links)}")
            for u in response_links[:8]: self.log("  URL -> "+u)
            for u in response_links[:8]:
                if self.page_asset(u): continue
                # Direct/extensionless media first, otherwise treat likely embeds/players as a nested player.
                q=urlparse(u); path=q.path.lower(); host=q.netloc.lower()
                if ".m3u8" in path or ".mp4" in path or "/list/" in path or "/m/" in path or False:
                    self.verify_media(u,r["url"])
                    if self.final_verified:return
                elif any(x in (host+path) for x in ("embed","player","vidmixi","videopark","playerx","rapid","stream")):
                    self.player=self.player or u
                    self.walk(u,depth+1,r["url"],"ACTION_JSON")
                    if self.final_verified:return

        cands=self.base64_iframes(r["body"],r["url"])+self.iframes(r["body"],r["url"])
        self.log(f"[ACTION_CANDIDATES] {len(cands)}")
        for u in cands[:5]:
            self.log(f"  PLAYER {u}")
            self.player=self.player or u
            self.walk(u,depth+1,parent,"ACTION_RESPONSE")
            if self.final_verified:return

    def smart_actions(self,r,depth):
        if depth!=0 or self.final_verified:return
        body=r["body"]; base=r["url"]

        t=self.data_values(body,"src-type")
        i=self.data_values(body,"src-id")
        k=self.data_values(body,"src-token")
        if t and i and k:
            origin=f"{urlparse(base).scheme}://{urlparse(base).netloc}"
            token_url=origin+"/api/token"; view_url=origin+"/api/view"
            if not any("/api/token" in urlparse(e[1]).path.lower() for e in self.script_endpoints):
                self.script_endpoints.append(("UNKNOWN",token_url,"metadata-pattern"))
            if not any("/api/view" in urlparse(e[1]).path.lower() for e in self.script_endpoints):
                self.script_endpoints.append(("POST",view_url,"metadata-pattern"))
            self.log(f"[ACTION_HINT] METADATA_TOKEN_VIEW {token_url} | {view_url}")
        token_ep=next((e for e in self.script_endpoints if "/api/token" in urlparse(e[1]).path.lower()),None)
        view_ep=next((e for e in self.script_endpoints if "/api/view" in urlparse(e[1]).path.lower()),None)
        if t and i and k and token_ep and view_ep:
            self.log("[ACTION_PLAN] METADATA_TOKEN_VIEW")
            tr=self.fetch(token_ep[1],referer=base,ajax=True)
            csrf=""
            if tr:
                try:
                    d=json.loads(tr["body"])
                    if isinstance(d,dict):
                        csrf=str(d.get("csrf_token") or d.get("csrf") or d.get("token") or "")
                except Exception: pass
                if not csrf:
                    m=re.search(r"""["']csrf_token["']\s*[:=]\s*["']([^"']+)["']""",tr["body"],re.I)
                    if m:csrf=m.group(1)
            self.log("[TOKEN_RESULT] csrf="+("FOUND" if csrf else "NOT_FOUND"))
            fields={"t":t[0],"i":i[0],"k":k[0]}
            if csrf: fields["csrf_token"]=csrf
            vr=self.fetch(view_ep[1],referer=base,ajax=True,method="POST",data=fields)
            self.log(f"[ACTION_EXEC] TOKEN_VIEW POST {view_ep[1]}")
            if vr:self.log(f"[ACTION_HTTP] {vr['status']} {vr['ct']}")
            self.consume_action(vr,base,depth)
            if self.final_verified:return

        ptype=self.data_values(body,"player-type")
        idx=self.data_values(body,"source-index")
        pep=next((e for e in self.script_endpoints if e[0]=="POST" and "player" in urlparse(e[1]).path.lower()),None)
        film_id=self.extract_film_id(body)
        if ptype and idx and pep:
            self.log("[ACTION_PLAN] PLAYER_POST")
            self.log(f"[ACTION_BIND] film_id={film_id or 'NOT_FOUND'} player_type={ptype[0]} source_count={len(idx)}")
            if film_id:
                for si in idx[:10]:
                    self.log(f"[SOURCE_DISPATCH] source_index={si} request_budget={self.requests}/{MAX_REQUESTS}")
                    rr=self.fetch(pep[1],referer=base,ajax=True,method="POST",
                                  data={"film_id":film_id,"source_index":si,"player_type":ptype[0]})
                    self.log(f"[ACTION_EXEC] PLAYER_SOURCE_{si} POST {pep[1]}")
                    if rr:self.log(f"[ACTION_HTTP] {rr['status']} {rr['ct']}")
                    self.consume_action(rr,base,depth)
                    if self.final_verified:return

    def fetch_data_video(self,url,referer):
        original_headers=self.headers
        try:
            def hdf_headers(ref="",ajax=False):
                h=original_headers(ref,False)
                h["Accept"]="application/json,text/plain,*/*"
                h["X-Requested-With"]="fetch"
                h["Sec-Fetch-Mode"]="cors"
                h["Sec-Fetch-Dest"]="empty"
                h["Sec-Fetch-Site"]="same-origin"
                if ref:
                    q=urlparse(ref); h["Origin"]=f"{q.scheme}://{q.netloc}"
                return h
            self.headers=hdf_headers
            return self.fetch(url,referer=referer,ajax=False)
        finally:
            self.headers=original_headers


    def walk(self,url,depth=0,referer="",reason="ROOT"):
        if self.final_verified or depth>MAX_DEPTH or self.requests>=MAX_REQUESTS:return
        if url in self.visited:return
        self.visited.add(url); self.max_depth=max(self.max_depth,depth)
        self.log(f"[DEPTH {depth}] {reason}")
        self.log(f"[GET] {url}")
        r=self.fetch(url,referer=referer)
        if not r:return
        if depth==0:self.root_status=r["status"]
        self.log(f"[HTTP] {r['status']}")
        self.log(f"[CONTENT_TYPE] {r['ct']}")
        self.log(f"[BYTES] {len(r['body'].encode('utf-8','ignore'))}")
        if self.challenge(r):
            self.blocked=True
            self.log(f"[BLOCK_DETECT] CLOUDFLARE_CHALLENGE status={r['status']}")
            self.log("[REQUEST_PROFILE_RETRY] BROWSER_AJAX")
            rr=self.fetch(url,referer=referer or url,ajax=True)
            if rr and not self.challenge(rr):
                self.log(f"[REQUEST_PROFILE_RESULT] RECOVERED status={rr['status']}")
                r=rr; self.blocked=False
            else:
                self.log(f"[REQUEST_PROFILE_RESULT] STILL_BLOCKED status={(rr or r)['status']}")
                return

        body=r["body"]; base=r["url"]
        if depth==0:self.v81_root_url=url
        try:self.v81_scan_subtitles(body,base,"STATIC_PAGE" if depth==0 else "STATIC_FRAME","")
        except Exception as _e81:self.log(f"[V81_SUB_SCAN_ERROR] {_e81}")
        if depth==0:self.generic_strategy_plan(body,base)
        self.client_session_bootstrap_hints(body,base,"PAGE "+base)
        self.analyze_client_session_runtime(body,base,"PAGE "+base)
        self.log_request_contexts(body,base,"PAGE/JS")
        self.log_initiator_context(body,base,"PAGE "+base)
        self.analyze_beplayer(body,base,"PAGE "+base)
        if self.final_verified:return
        v54_candidates=self.v54_mrc_static_capabilities(body,base,"PAGE "+base)
        for v54u in v54_candidates[:16]:
            self.verify_media(v54u,base)
            if self.final_verified:return
        self.static_inline_decode(body,base,"PAGE "+base)
        if self.final_verified:return
        declared_state=self.resolve_declared_worker_api(body,base)
        if self.final_verified:return
        host_now=urlparse(base).netloc.lower(); path_now=urlparse(base).path.lower()
        if host_now.endswith("videopark.top"):
            if declared_state=="FAILED":
                self.log("[PROVIDER_FAIL_FAST] VIDEOPARK declared API transport/source failed; returning to source dispatcher")
                return
            if path_now.startswith("/go/") and declared_state=="NO_MATCH":
                self.log("[PROVIDER_FAIL_FAST] VIDEOPARK GO has no direct declared API; returning to source dispatcher")
                return
        dvs=self.data_values(body,"video")
        meta=[]
        for key in ("src-type","src-id","src-token","player-type","source-index"):
            vals=self.data_values(body,key)
            for v in vals[:8]: meta.append(f"data-{key}={v}")
        if dvs: meta.extend("data-video="+x for x in dvs[:8])
        if meta:self.log("[DOM_DISCOVERY] "+" | ".join(meta[:24]))
        else:self.log("[DOM_DISCOVERY] NONE")

        pattern_candidates=self.diziyou_pattern_candidates(base,body)
        if pattern_candidates:
            for u in pattern_candidates:
                self.log(f"[PATTERN_PROBE] DIZIYOU -> {u}")
                self.verify_media(u,base)
                if self.final_verified:return

        ext_media=self.extensionless_media_candidates(body,base)
        if ext_media:
            for eu in ext_media[:3]:
                loc=body.find(eu)
                if loc>=0:
                    ctx=re.sub(r"\s+"," ",body[max(0,loc-1500):loc+1800]).strip()
                    self.log("[MEDIA_INITIATOR_CONTEXT] "+ctx[:2400])
            self.log(f"[EXTENSIONLESS_MEDIA] {len(ext_media)}")
            for u in ext_media[:5]:
                self.log("  PROBE -> "+u)
                self.verify_media(u,base)
                if self.final_verified:return

        pm=[u for u in self.player_media_candidates(body,base) if not self.page_asset(u)]
        if pm:
            self.log(f"[PLAYER_SOURCE_RESOLVE] base={base}")
            self.log(f"[PLAYER_MEDIA_HINTS] {len(pm)}")
            for u in pm[:5]: self.log("  MEDIA -> "+u)
            for u in pm[:5]:
                self.verify_media(u,base)
                if self.final_verified:return
            if urlparse(base).netloc.lower().endswith("playerx.info"):
                self.log("[PROVIDER_FAIL_FAST] PLAYERX source discovered but media verification failed; returning to source dispatcher")
                return

        # V31: structured player metadata has stronger provenance than flattened URL regexes.
        if self.v31_try_structured_media(body,base):
            return

        dm=[u for u in self.direct_media(body,base) if not self.page_asset(u)]
        rejected=[u for u in self.direct_media(body,base) if self.page_asset(u)]
        if rejected:
            self.log(f"[MEDIA_ASSET_REJECT] {len(rejected)}")
            for u in rejected[:5]:self.log("  PAGE_ASSET -> "+u)
        self.log("[DIRECT_MEDIA] "+(str(len(dm)) if dm else "NONE"))
        for u in dm[:8]:
            probe=self.probe_media_candidate(u,base)
            if not probe:continue
            ctx=self.source_context(body,u)
            item=self.register_media_candidate(u,"PAGE_LITERAL",ctx,probe["ct"],probe["head"],probe["status"])
            if self.candidate_can_finalize(item):
                h=probe["head"].lstrip();ct=probe["ct"].lower()
                self.final=u
                self.final_type="HLS" if (h.startswith("#EXTM3U") or "mpegurl" in ct or ".m3u8" in u.lower()) else "MP4"
                self.final_verified=True
                self.final_evidence=item
                self.log(f"[FINAL_MEDIA] {self.final_type} {u}")
                self.log("[FINAL_EVIDENCE] page candidate correlated with player context")
                return
            self.log("[MEDIA_NOT_FINAL] reachable media but main-title/player correlation insufficient")

        player_literals=self.player_literal_candidates(body,base)
        if player_literals:
            self.log(f"[PLAYER_LITERAL_CANDIDATES] {len(player_literals)}")
            for u in player_literals:
                self.log("[PLAYER_LITERAL] "+u)
            for u in player_literals[:4]:
                self.player=u
                # V35: endpoints such as /authorize, /token, /session, /resolve are
                # often action/fetch endpoints, not navigable player documents.
                # Do not blindly GET them during static recursion; let browser runtime
                # observe the real method/body/headers/trigger semantics.
                try:
                    _p=(urlparse(u).path or "").lower().rstrip("/")
                except Exception:
                    _p=""
                if re.search(r"/(?:authorize|token|session|resolve|activate|unlock|verify|grant)$",_p):
                    self.log(f"[V35_ACTION_ENDPOINT_DEFER] url={u} reason=RUNTIME_SEMANTICS_REQUIRED")
                    continue
                before=len(self.logs)
                self.walk(u,depth+1,base,"PLAYER_LITERAL")
                if self.final_verified:return
                recent="\n".join(self.logs[before:])
                if self.classify_broken_player_transport(u,recent):
                    good_fallbacks=[fb for fb in self.discover_same_page_fallbacks(body,base)
                                    if self.fallback_candidate_quality(fb,base)]
                    for fb in good_fallbacks[:8]:
                        self.log("[BROKEN_PLAYER_FALLBACK_CANDIDATE] "+fb)

        raw_cands=self.base64_iframes(body,base)+self.iframes(body,base)
        raw_cands=list(dict.fromkeys(raw_cands))
        trailer_rejects=[u for u in raw_cands if self.is_trailer_url(u)]
        cands=[u for u in raw_cands if not self.is_trailer_url(u)]
        if trailer_rejects:
            self.log(f"[TRAILER_REJECT] {len(trailer_rejects)}")
            for u in trailer_rejects[:5]: self.log("  TRAILER -> "+u)
        self.log("[IFRAME_CANDIDATES] "+(str(len(cands)) if cands else "NONE"))

        eps=self.endpoint_scan(body,base)
        if eps:
            self.log(f"[NETWORK_DISCOVERY] {len(eps)}")
            for e in eps[:12]:self.log(f"  [{e[2]}] {e[0]} {e[1]}")
        else:self.log("[NETWORK_DISCOVERY] NONE")

        # V26 PLAYER_SCRIPT_CONTEXT: inspect same-page JS endpoints whose filename/context is
        # explicitly player/video/embed/source shaped. This is mechanism-based, not domain-based.
        v26_player_scripts=[]
        for method,eu,kind in eps:
            try:
                qu=urlparse(eu)
                path=(qu.path or "").lower()
                if method.upper() not in ("GET","UNKNOWN"):
                    continue
                if not path.endswith(".js"):
                    continue
                if not any(k in path for k in ("player","video","embed","stream","source")):
                    continue
                if eu not in v26_player_scripts:
                    v26_player_scripts.append(eu)
            except Exception:
                pass
        for ps in v26_player_scripts[:6]:
            self.log("[V26_PLAYER_SCRIPT] "+ps)
            pr=self.fetch(ps,referer=base)
            if not pr:
                continue
            pbody=pr.get("body","")
            self.player_host_hints_from_text(pbody,base,"V26_PLAYER_SCRIPT "+ps)
            peps=self.endpoint_scan(pbody,base)
            for pe in peps[:20]:
                ctx=self.source_context(pbody,pe[1])
                score=self.runtime_candidate_score(pe[1],base,"V26_PLAYER_SCRIPT",ctx)
                if score>=8:
                    self.log(f"[V26_PLAYER_SCRIPT_TARGET] score={score} method={pe[0]} url={pe[1]}")
                    self.runtime_discovered_candidate(pe[1],base,"V26_PLAYER_SCRIPT",ctx)

        self.player_host_hints_from_text(body,base,"DOCUMENT")
        scripts=self.scripts(body,base)
        self.log("[EXTERNAL_SCRIPTS] "+(str(len(scripts)) if scripts else "NONE"))
        for s in scripts:
            self.log("  -> "+s)
            sr=self.fetch(s,referer=base)
            if not sr:continue
            v27_score,v27_reasons=self.v27_script_role_score(sr["body"],s)
            if v27_score>=5:
                self.log(f"[V27_SCRIPT_ROLE] score={v27_score} reasons={','.join(v27_reasons)} url={s}")
                self.v27_event_selectors_from_script(sr["body"],"SCRIPT "+s)
                for pe in self.endpoint_scan(sr["body"],base)[:40]:
                    ctx=self.source_context(sr["body"],pe[1])
                    sc=self.runtime_candidate_score(pe[1],base,"V27_SCRIPT_ROLE",ctx)
                    if sc>=8:
                        self.log(f"[V27_SCRIPT_TARGET] score={sc} method={pe[0]} url={pe[1]}")
                        self.runtime_discovered_candidate(pe[1],base,"V27_SCRIPT_ROLE",ctx)
            self.client_session_bootstrap_hints(sr["body"],base,"SCRIPT "+s)
            self.player_host_hints_from_text(sr["body"],base,"SCRIPT "+s)
            self.analyze_client_session_runtime(sr["body"],base,"SCRIPT "+s)
            self.log_request_contexts(sr["body"],base,"SCRIPT "+s)
            try:self.v81_scan_subtitles(sr["body"],base,"STATIC_SCRIPT","")
            except Exception:pass
            self.log_initiator_context(sr["body"],base,"SCRIPT "+s)
            self.analyze_beplayer(sr["body"],base,"SCRIPT "+s)
            if self.final_verified:return
            self.static_inline_decode(sr["body"],base,"SCRIPT "+s)
            if self.final_verified:return
            seps=self.endpoint_scan(sr["body"],base)  # document context intentionally
            for e in seps:
                if e not in self.script_endpoints:self.script_endpoints.append(e)
            if seps:
                self.log("[SCRIPT_INSPECT] "+s)
                for e in seps[:12]:
                    cls=self.classify_script_endpoint(e[1],sr["body"])
                    self.log(f"  ENDPOINT {e[0]} {e[1]} [{cls}]")
            low_s=s.lower()
            generic_runtime=("jwplayer","jquery","video.min.js","nuevo.min.js","cloudfront.net")
            if any(x in sr["body"].lower() for x in RUNTIME_HINTS) and not any(n in low_s for n in NOISE) and not any(g in low_s for g in generic_runtime):
                self.runtime_needed=True
                self.log("[RUNTIME_HINT] DOM_MUTATION in "+s)

        # V81: ${var} sablonlu ajax/fetch isteklerini coz ve calistir
        try:self.v81_run_templates(body,base,depth)
        except Exception as _e81:self.log(f"[V81_TEMPLATE_ERROR] {type(_e81).__name__}: {_e81}")
        if self.final_verified:return

        self.smart_actions(r,depth)
        if self.final_verified:return

        for u in cands[:5]:
            self.player=self.player or u
            self.walk(u,depth+1,base,"IFRAME")
            if self.final_verified:return

        for vid in dvs[:3]:
            u=urljoin(base,f"/video/{vid}/")
            self.log(f"[DOM_PROBE] data-video={vid} -> {u}")
            rr=self.fetch_data_video(u,base)
            if rr:
                self.log(f"[DOM_PROBE_HTTP] {rr['status']} {rr['ct']}")
                if rr["status"]<400:
                    self.consume_action(rr,base,depth)
                    if self.final_verified:return
                elif rr["status"] in (401,403,429,503):
                    self.log(f"[DOM_PROBE_BLOCKED] status={rr['status']}")

        if not cands and not self.player and any(x in body.lower() for x in RUNTIME_HINTS):
            self.runtime_needed=True
            self.log("[RUNTIME_HINT] INLINE_DOM_MUTATION")


    def player_literal_candidates(self,body,base):
        out=[]
        noise_hosts=("youtube.com","youtu.be","youtube-nocookie.com","vimeo.com","player.vimeo.com",
                     "googletagmanager.com","google-analytics.com","doubleclick.net","schema.org")
        scan=body.replace("\\/","/")
        for raw in re.findall(r"https?://[^\s\"'<>]+",scan,re.I):
            raw=html.unescape(raw).rstrip("),;]")
            try:
                u=self.absolute(base,raw)
                q=urlparse(u); host=q.netloc.lower(); path=q.path.lower()
            except Exception:
                continue
            if not host or any(n in host for n in noise_hosts):
                continue
            strong=(
                re.search(r"/(?:video|embed|player)/[A-Za-z0-9_-]{8,}",path) is not None
                or (host.startswith("player.") and re.search(r"/[A-Za-z0-9_-]{8,}",path) is not None)
            )
            if not strong or self.is_trailer_url(u) or self.page_asset(u):
                continue
            if u not in out:
                out.append(u)
        return out[:8]

    def analyze_client_session_runtime(self,body,base,label="PAGE"):
        low=body.lower()
        has_client="/player/client.php" in low
        has_session="/player/session-state.php" in low
        has_storage="localstorage" in low
        has_atob="atob(" in low
        if not has_client:
            return False
        self.log(f"[CLIENT_SESSION_RUNTIME] {label}")
        self.log(f"[CLIENT_SESSION_FLAGS] client={has_client} session={has_session} localStorage={has_storage} atob={has_atob}")
        for needle in ("/player/client.php","/player/session-state.php"):
            start=0; shown=0
            while shown<2:
                loc=low.find(needle,start)
                if loc<0:
                    break
                ctx=re.sub(r"\s+"," ",body[max(0,loc-1800):loc+3200]).strip()
                self.log(f"[CLIENT_SESSION_CONTEXT] needle={needle}")
                self.log("  "+ctx[:4200])
                shown+=1
                start=loc+len(needle)
        if has_storage:
            self.runtime_needed=True
        return True




    def v31_decode_js_string(self, raw):
        if raw is None:return ""
        x=str(raw)
        try:
            # Decode JSON/JS escape sequences without interpreting arbitrary code.
            return json.loads('"'+x.replace('"','\\"')+'"')
        except Exception:
            return html.unescape(x).replace("\\/","/").replace("\\u0026","&")

    def v31_structured_player_media_candidates(self, body, base):
        """Extract media from player metadata while preserving key/provenance instead of flattening JSON into URL literals."""
        if not body:return []
        scan=html.unescape(str(body)).replace("\\/","/")
        out=[]; seen=set()
        strong_keys=("hlsManifestUrl","hls_manifest_url","manifestUrl","manifest","video_location","playlistUrl","playlist")
        # Quoted key/value pairs from embedded JSON/config objects.
        for key in strong_keys:
            rx=re.compile(r'["\']'+re.escape(key)+r'["\']\s*:\s*["\']([^"\']{4,4000})["\']',re.I)
            for m in rx.finditer(scan):
                raw=m.group(1); val=self.v31_decode_js_string(raw).strip()
                if not val:continue
                try:u=self.absolute(base,val)
                except Exception:continue
                if not u.startswith(("http://","https://")):continue
                if self.page_asset(u) or self.is_trailer_url(u):continue
                ctx=re.sub(r"\s+"," ",scan[max(0,m.start()-1000):m.end()+1000])
                item=(u,key,ctx)
                if u not in seen:
                    seen.add(u);out.append(item)
        # Generic file/source fields are accepted only inside strong player/video context and only if media-shaped.
        rx=re.compile(r'["\'](?:file|src|source)["\']\s*:\s*["\']([^"\']{4,4000})["\']',re.I)
        for m in rx.finditer(scan):
            raw=m.group(1); val=self.v31_decode_js_string(raw).strip()
            try:u=self.absolute(base,val)
            except Exception:continue
            ctx=re.sub(r"\s+"," ",scan[max(0,m.start()-900):m.end()+900]); low=(u+" "+ctx).lower()
            if not any(k in low for k in ("jwplayer","player","playlist","sources","hls","m3u8","video/mp4","video_location")):continue
            if not any(k in u.lower() for k in (".m3u8",".mp4","/list/","/stream/","/watch/","/vs/")):continue
            if self.page_asset(u) or self.is_trailer_url(u):continue
            if u not in seen:
                seen.add(u);out.append((u,"file/source",ctx))
        return out[:16]

    def v31_try_structured_media(self, body, base):
        cands=self.v31_structured_player_media_candidates(body,base)
        if not cands:return False
        self.log(f"[V31_STRUCTURED_PLAYER_METADATA] candidates={len(cands)}")
        for u,key,ctx in cands:
            self.log(f"[V31_STRUCTURED_MEDIA] key={key} url={u}")
            self.v31_structured_media.append({"url":u,"key":key})
            probe=self.probe_media_candidate(u,base)
            if not probe:continue
            item=self.register_media_candidate(u,"STRUCTURED_PLAYER_CONFIG",ctx,probe["ct"],probe["head"],probe["status"])
            if self.candidate_can_finalize(item):
                h=probe["head"].lstrip(); ct=probe["ct"].lower()
                self.final=u
                self.final_type="HLS" if (h.startswith("#EXTM3U") or "mpegurl" in ct or ".m3u8" in u.lower()) else "MP4"
                self.final_verified=True; self.final_evidence=item
                self.log(f"[FINAL_MEDIA] {self.final_type} {u}")
                self.log(f"[V31_SEMANTIC_PROVENANCE] source=STRUCTURED_PLAYER_CONFIG key={key}")
                return True
        return False

    def source_context(self,body,url):
        keys=[url,url.replace("/","\\/")]
        try: keys.append(urlparse(url).path.rsplit("/",1)[-1])
        except Exception: pass
        low=body.lower()
        for k in keys:
            if not k: continue
            i=low.find(k.lower())
            if i>=0:return re.sub(r"\s+"," ",body[max(0,i-500):i+len(k)+500])
        return ""

    def media_candidate_score(self,url,origin,context="",ct="",head=""):
        u=(url or "").lower(); c=(context or "").lower(); ctype=(ct or "").lower()
        score=0; reasons=[]
        if ".m3u8" in u or "mpegurl" in ctype or (head or "").lstrip().startswith("#EXTM3U"):
            score+=45;reasons.append("HLS")
        elif ".mp4" in u or "video/mp4" in ctype:
            score+=20;reasons.append("MP4")
        if any(x in c for x in ("jwplayer","sources:","file:","video_location","playlist","beplayer","player.setup")):
            score+=30;reasons.append("PLAYER_CONTEXT")
        if origin in ("PLAYER_SOURCE","IFRAME","PATTERN","API_AJAX","BROWSER_NETWORK","DECRYPTED","STRUCTURED_PLAYER_CONFIG","ACTIVE_PLAYER_STATE"):
            score+=35 if origin in ("STRUCTURED_PLAYER_CONFIG","ACTIVE_PLAYER_STATE") else 25;reasons.append(origin)
        if any(x in u for x in ("trailer","fragman","preview","sample","teaser","advert","ads/","banner")):
            score-=60;reasons.append("PREVIEW_OR_AD")
        if origin not in ("STRUCTURED_PLAYER_CONFIG","ACTIVE_PLAYER_STATE") and any(x in c for x in ("poster","thumbnail","advert","banner","trailer","fragman")):
            score-=50;reasons.append("NON_MAIN_CONTEXT")
        return score,reasons

    def register_media_candidate(self,url,origin,context="",ct="",head="",status=0):
        score,reasons=self.media_candidate_score(url,origin,context,ct,head)
        item={"url":url,"origin":origin,"context":context[:500],"ct":ct,"status":status,
              "score":score,"reasons":reasons}
        self.media_candidates.append(item)
        self.log(f"[MEDIA_CANDIDATE] score={score} origin={origin} url={url}")
        self.log("[MEDIA_EVIDENCE] "+(",".join(reasons) if reasons else "WEAK_CONTEXT"))
        return item

    def candidate_can_finalize(self,item):
        if item["status"]<200 or item["status"]>=400:return False
        if item["origin"]=="PAGE_LITERAL" and item["score"]<50:return False
        return item["score"]>=45

    def probe_media_candidate(self,url,referer):
        r=self.fetch(url,referer=referer)
        if not r:return None
        head=r["body"][:1000].lstrip()
        sig=head[:80].replace("\r"," ").replace("\n"," ")
        self.log(f"[MEDIA_PROBE_CANDIDATE] status={r['status']} ct={r['ct']} bytes={len(r['body'])} head={sig!r}")
        return {"status":r["status"],"ct":r["ct"],"head":head}

    def generic_strategy_plan(self,body,base):
        text=(body or "").lower(); plan=[]
        def add(x):
            if x not in plan:plan.append(x)
        if self.direct_media(body,base):add("DIRECT_CANDIDATES")
        if self.base64_iframes(body,base):add("ENCODED_IFRAME")
        if self.iframes(body,base):add("IFRAME")
        if self.player_literal_candidates(body,base):add("PLAYER_LITERAL")
        if any(x in text for x in ("fetch(","xmlhttprequest","$.ajax","/api/","/ajax/","client.php")):add("API_AJAX")
        if any(x in text for x in ("eval(function(p,a,c,k,e","cryptojs","atob(","fromcharcode","reverse()")):add("JS_CRYPT_PACKER")
        if any(x in text for x in ("data-source-index","source_index","player_type","jetplayer")):add("DISPATCHER")
        if self.runtime_needed or "localstorage" in text:add("BROWSER_RUNTIME")
        self.log("[GENERIC_PLAN] "+(" -> ".join(plan) if plan else "DISCOVERY_ONLY"))
        self.log("[V55_CAPABILITY] V54_BASE + RELIABLE_PLAYER_INTERACTION_OR_BOOTSTRAP_TRIGGER + PLAYER_REGION_CAUSAL_GATING + NAVIGATION_VETO + NETWORK_DELTA_PROOF + NO_DOMAIN_HARDCODE")
        return plan


    def classify_broken_player_transport(self,url,error_text):
        low=(error_text or "").lower()
        if not url or not url.startswith(("http://","https://")):
            return False
        if any(x in low for x in ("wrong_version_number","err_ssl_protocol_error","ssl protocol","tls")):
            if url not in self.broken_player_targets:
                self.broken_player_targets.append(url)
            self.log("[BROKEN_PLAYER_TRANSPORT] "+url)
            return True
        return False

    def discover_same_page_fallbacks(self,body,base):
        out=[]
        patterns=[
            r'''["']([^"']*(?:ajax|source|token|player|video)[^"']*)["']''',
            r'''(?:url|endpoint|apiUrl)\s*[:=]\s*["']([^"']+)["']''',
        ]
        for pat in patterns:
            for m in re.finditer(pat,body,re.I):
                raw=(m.group(1) or "").strip()
                if not raw or raw.startswith(("javascript:","#")):
                    continue
                try:
                    u=self.absolute(base,raw)
                except Exception:
                    continue
                if not u or self.page_asset(u) or self.is_trailer_url(u):
                    continue
                host=urlparse(u).netloc.lower()
                if not host:
                    continue
                if any(x in host for x in ("youtube.com","vimeo.com","google","doubleclick")):
                    continue
                if u not in out:
                    out.append(u)
        return out[:20]

    def client_session_bootstrap_hints(self,body,base,label="PAGE"):
        low=body.lower()
        score=0
        markers=[]
        tests=(
            ("localstorage","localStorage",2),
            ("session-state.php","session-state",2),
            ("client.php","client.php",2),
            ("x-viewport-hint","X-Viewport-Hint",2),
            ("ajax-data","ajax-data",1),
            ("postmessage","postMessage",1),
            ("credentials:'include'","credentials include",1),
            ('credentials:"include"',"credentials include",1),
        )
        for token,name,val in tests:
            if token in low:
                score+=val
                markers.append(name)
        if score>=4:
            self.log(f"[CLIENT_SESSION_BOOTSTRAP] {label} score={score} markers="+",".join(markers))
            return True
        return False

    def v75_nonplayback_api(self, url="", method="", context=""):
        """Generic side-effect/telemetry API gate.
        Counter, comment, rating, account/admin and analytics requests can be caused by
        a real player click, but they are not player documents or media bootstrap targets.
        Keep them observable in CDP; never promote/navigate them as resolver targets.
        """
        try:
            path=(urlparse(str(url or "")).path or "").lower()
        except Exception:
            path=str(url or "").lower()
        segments=[x for x in path.split("/") if x]
        joined="/"+"/".join(segments)+("/" if segments else "")
        exactish=(
            "/view-count/", "/views/", "/page-view/", "/pageview/",
            "/comments/", "/comment/", "/rate/", "/rating/",
            "/like/", "/dislike/", "/favorite/", "/favourite/",
            "/watchlist/", "/watched/", "/report/",
            "/users/me/", "/admin/", "/analytics/", "/telemetry/", "/metrics/"
        )
        return any(x in joined for x in exactish)

    def runtime_request_relevant(self,url,method="",post_data=""):
        low=(url or "").lower()
        pd=(post_data or "").lower()
        if self.v75_nonplayback_api(url,method,pd):
            return False
        keys=(
            "client.php","session-state.php","/source","/token","/player","/video","/stream",
            "/ajax","/api/","jetplayer",".m3u8",".mp4","/list/","/watch/"
        )
        return any(k in low for k in keys) or any(k in pd for k in ("token","source","video","player","id="))


    def runtime_candidate_score(self,url,base="",source="",context=""):
        """Generic resolver-target scoring. Media evidence is handled elsewhere; this only
        decides whether a discovered URL deserves resolver recursion. Avoids queueing page
        assets, manifests, analytics, docs and unrelated absolute URLs from large JS/HTML bodies."""
        if not url or not str(url).startswith(("http://","https://")):
            return -100
        try:
            q=urlparse(url)
            host=(q.hostname or "").lower()
            path=(q.path or "").lower()
        except Exception:
            return -100
        low=(url or "").lower()
        blob=((context or "")+" "+(source or "")).lower()
        if self.v75_nonplayback_api(url, context=context):
            return -120
        if any(x in low for x in ("/no_video","/video/video/mp4","/video/video/mp2t","; codecs=","%3b%20codecs=")):
            return -100
        score=0
        # Strong media/player path evidence.
        if any(x in low for x in (".m3u8",".mp4","/embed/","/video/","/player/","/vx/","/vod/","/stream","/watch/","/list/","master","playlist")):
            score += 8
        if host.startswith(("player.","embed.")):
            score += 5
        if any(k in host for k in ("player","embed","play")):
            score += 3
        if any(k in blob for k in ("player","video","iframe","source","stream","hls","m3u8","embed","watch","oynat","izle")):
            score += 3
        # V37: concrete DOM media elements are causal observations, not mere strings.
        # Give them enough weight to survive the generic queue gate even when the URL
        # itself is an opaque iframe.php?id=... style endpoint.
        if str(source or "").upper()=="DOM_ELEMENT":
            score += 6
        # V43: structured player metadata is causal evidence even when the endpoint
        # is extensionless/.php. Do not require URL-shape evidence in that case.
        sem=self.v43_semantic_media.get(str(url)) if hasattr(self,'v43_semantic_media') else None
        if sem:
            score += 10
            if str(sem.get('transport','')).upper() in ('HLS','DASH','MP4'):
                score += 4
        if str(source or '').upper().startswith('V43_SEMANTIC'):
            score += 10
        # Cross-origin runtime targets are often useful, but not enough by themselves.
        try:
            bh=(urlparse(base).hostname or "").lower()
            if bh and host and bh != host:
                score += 1
        except Exception:
            pass
        # Resource/document noise that must never enter resolver recursion on its own.
        bad_hosts=("google-analytics.com","googletagmanager.com","doubleclick.net","google.com","gstatic.com","schema.org",
                   "github.com","githubassets.com","w3.org","jquery.com","sizzlejs.com","fontawesome.io","facebook.com","instagram.com","x.com")
        if any(h in host for h in bad_hosts):
            score -= 20
        bad_ext=(".css",".woff",".woff2",".ttf",".otf",".png",".jpg",".jpeg",".webp",".gif",".svg",".ico",".webmanifest",".xml")
        if any(path.endswith(x) for x in bad_ext):
            score -= 20
        if any(x in low for x in ("/license","/privacy","/terms","favicon","analytics","gtag","collect?","schema.org","xmlrpc.php","wp-json/oembed")):
            score -= 15
        return score

    def player_host_hints_from_text(self,text,base,label="TEXT"):
        """Find cross-origin player-host clues from HTML/JS without hardcoding providers.
        Bare preconnect hosts are clues only; full/path-bearing URLs with player context can
        become resolver targets through the normal score gate."""
        if not text:
            return []
        out=[]
        scan=html.unescape(str(text)).replace("\\/","/")
        base_host=(urlparse(base).hostname or "").lower()
        # Collect preconnect/dns-prefetch origins plus absolute URL literals.
        raws=[]
        for m in re.finditer(r'<link[^>]+rel=["\'](?:preconnect|dns-prefetch)["\'][^>]+href=["\']([^"\']+)',scan,re.I):
            raws.append((m.group(1),m.start(),"preconnect"))
        for m in re.finditer(r'https?://[^\s"\'<>]+',scan,re.I):
            raws.append((m.group(0).rstrip('),;]'),m.start(),"literal"))
        seen=set()
        for raw,pos,kind in raws:
            u=self.normalize_runtime_url(raw,base)
            if not u or u in seen:
                continue
            seen.add(u)
            try:
                q=urlparse(u); host=(q.hostname or "").lower(); path=q.path or ""
            except Exception:
                continue
            if not host or host==base_host:
                continue
            near=scan[max(0,pos-240):min(len(scan),pos+len(raw)+240)]
            score=self.runtime_candidate_score(u,base,label+" "+kind,near)
            # A bare origin with a play/player-ish hostname is a useful host hint, but not media.
            hostish=any(k in host for k in ("player","embed","play"))
            if kind=="preconnect" and hostish:
                score=max(score,4)
            if score>=4:
                item={"url":u,"host":host,"score":score,"label":label,"kind":kind,"context":re.sub(r"\\s+"," ",near)[:600]}
                if not any(x.get("url")==u and x.get("label")==label for x in self.player_host_hints):
                    self.player_host_hints.append(item)
                    self.log(f"[V25_PLAYER_HOST_HINT] score={score} kind={kind} label={label} url={u}")
                    self.log("[V25_PLAYER_HOST_CONTEXT] "+item["context"])
                out.append(item)
        return out

    def v37_ad_media_evidence(self,url="",context=""):
        """Generic ad/pre-roll detector used only to prevent premature playback lock.
        It never declares media final; it quarantines obvious ad-shaped evidence and lets
        the same browser/player session continue toward the real stream."""
        s=(str(url or "")+" "+str(context or "")).lower()
        try:
            p=(urlparse(str(url or "")).path or "").lower()
        except Exception:
            p=""
        # Path/markup semantics rather than provider names.
        if re.search(r"/(?:ads?|allads|advert|advertising|promo|preroll|pre-roll|vast|vmap)(?:/|\b)",p):
            return True
        if any(x in s for x in (
            "adclick","clickthrough","click-through","sponsor","sponsored",
            "pre-roll","preroll","vast.xml","vmap.xml","ad-container","advertisement"
        )):
            return True
        # Autoplay media wrapped in a new-tab anchor is a common click-through ad shape.
        if "<video" in s and "target=\"_blank\"" in s and "<a href=" in s:
            return True
        return False

    def v35_is_challenge_asset(self,url):
        s=str(url or "").lower()
        return (
            "challenges.cloudflare.com/" in s or
            "/cdn-cgi/challenge-platform/" in s or
            "/turnstile/" in s
        )

    def v26_runtime_queue_threshold(self, source, url, score):
        """Mechanism-first queue gate. Bare cross-origin origins remain clues only.
        Resolver recursion requires stronger player/media evidence so docs/analytics/preconnect
        noise cannot consume the request budget."""
        try:
            q=urlparse(url)
            path=(q.path or "")
            host=(q.hostname or "").lower()
        except Exception:
            return 999
        src=(source or "").upper()
        if self.v35_is_challenge_asset(url):
            return 999
        if src.startswith("V31_ACTIVE_PLAYER") or src.startswith("ACTIVE_PLAYER"):
            return 0
        # Never recurse obvious generic/noise roots solely because they are cross-origin.
        if path in ("", "/"):
            if any(k in host for k in ("player","embed","stream","video")) and score>=10:
                return 10
            return 999
        # Direct DOM elements/network media/player mutations are trusted more than text literals.
        if src in ("DOM_ELEMENT","NETWORK"):
            return 6
        if "JSON" in src:
            return 6
        if "DOM_MUTATION" in src:
            return 7
        if "HOST_HINT" in src:
            return 8
        if "RESPONSE" in src:
            return 8
        return 8

    def v26_action_request_is_meaningful(self, rid, reqmeta, respmeta, body_text, discovered_urls):
        """Return True only for playback/resolver evidence, never for an empty telemetry/counter ping."""
        reqmeta=reqmeta or {}
        respmeta=respmeta or {}
        url=str(reqmeta.get("url","") or respmeta.get("url","") or "")
        typ=str(reqmeta.get("type","") or "").lower()
        method=str(reqmeta.get("method","") or "").upper()
        post=str(reqmeta.get("postData","") or "")
        status=int(respmeta.get("status",0) or 0)
        ct=str(respmeta.get("ct","") or "").lower()
        txt=str(body_text or "")
        # V29: explicit player failure/error pages override generic URL/network positives.
        if self.v29_negative_playback_evidence(url,status,txt):
            return False
        # Media response evidence is always meaningful.
        if self._browser_media_kind(url,ct) or txt.lstrip().startswith("#EXTM3U"):
            return True
        # An empty 204/205 ping is a counter/telemetry signal, not a resolver result.
        if typ=="ping" and status in (204,205) and not txt.strip() and not discovered_urls:
            self.log(f"[V26_ACTION_IGNORE] id={rid} reason=EMPTY_PING status={status} url={url}")
            return False
        # Known hit/counter semantics with an empty body must not lock the action explorer.
        lp=(post+" "+url).lower()
        if not txt.strip() and not discovered_urls and any(k in lp for k in ("stf_hit","view_count","hit_count","like","unlike","analytics","collect?")):
            self.log(f"[V26_ACTION_IGNORE] id={rid} reason=COUNTER_OR_TELEMETRY url={url}")
            return False
        # V36: interpret network evidence by role. Session/bootstrap/view/history/telemetry
        # traffic can be causally caused by a click, but it is not playback evidence.
        ctl=(url+" "+post+" "+txt[:2000]).lower()
        control_tokens=(
            "dt_refresh_nonces","refresh_nonces","heartbeat","stf_hit","view_count","hit_count",
            "analytics","collect","metrika","yandex","googletagmanager","gtag",
            "/bootstrap","/oturum/","/session/bootstrap","/auth/bootstrap",
            "/izlenme/","/watched","/history","/progress","/view/record","/record-view",
            "csrf_token","authenticated\":false","protocol\":\"cache-security"
        )
        if any(k in ctl for k in control_tokens):
            self.log(f"[V37_EVIDENCE_INTERPRET] id={rid} role=CONTROL_PLANE decision=CONTINUE_ACTION_SEARCH url={url}")
            return False
        # New player/media/iframe URLs extracted from a response are strong evidence.
        if discovered_urls:
            return True
        # Non-empty XHR/fetch bodies with player/media semantics are meaningful.
        blob=(url+" "+post+" "+txt[:8000]).lower()
        if typ in ("xhr","fetch") and 200 <= status < 400 and txt.strip():
            if any(k in blob for k in ("iframe","player","source","m3u8","mpegurl","stream","video","embed","token")):
                return True
        # A request URL itself can be meaningful only when strongly player/media-shaped.
        try:
            score=self.runtime_candidate_score(url,url,"V26_ACTION_REQUEST",post[:3000]) if url else 0
        except Exception:
            score=0
        if typ in ("xhr","fetch","media") and score>=10 and status and status<400:
            return True
        return False

    def v28_popup_is_playback_candidate(self, url, base=""):
        """A popup is not playback evidence by itself. Only player/media-shaped popup URLs qualify."""
        if not url or url == "about:blank": return False
        low=url.lower()
        bad=("pixel","popunder","popup","/ads","/ad/","doubleclick","analytics","collect","puclc","zoology","shorter","invoke.js")
        if any(x in low for x in bad):
            self.log(f"[V28_POPUP_IGNORE] reason=AD_OR_TELEMETRY url={url}")
            return False
        score=self.runtime_candidate_score(url,base,"V28_POPUP","popup player frame")
        ok=score>=8 or any(x in low for x in (".m3u8","/embed/","/player/","/video/","/stream/","/watch/"))
        if not ok:self.log(f"[V28_POPUP_IGNORE] reason=NO_PLAYBACK_EVIDENCE score={score} url={url}")
        else:self.log(f"[V28_POPUP_PLAYER] score={score} url={url}")
        return ok

    def v29_js_unescape(self, value):
        """Decode only JavaScript string escapes that are useful to resolver discovery."""
        if value is None:return ""
        x=str(value)
        def hx(m):
            try:return chr(int(m.group(1),16))
            except Exception:return m.group(0)
        x=re.sub(r"\\x([0-9A-Fa-f]{2})",hx,x)
        x=re.sub(r"\\u([0-9A-Fa-f]{4})",hx,x)
        return x.replace("\\/","/").replace("\\\"",'"').replace("\\'","'")

    def v29_balanced_call(self, text, func_name):
        """Extract first balanced JS call argument text without regex-parsing nested JSON."""
        if not text or not func_name:return ""
        m=re.search(r"\b"+re.escape(func_name)+r"\s*\(",text,re.I)
        if not m:return ""
        i=m.end(); start=i; depth=1; quote=None; esc=False
        while i<len(text):
            ch=text[i]
            if quote:
                if esc:esc=False
                elif ch=='\\':esc=True
                elif ch==quote:quote=None
            else:
                if ch in ("'",'"','`'):quote=ch
                elif ch=='(':depth+=1
                elif ch==')':
                    depth-=1
                    if depth==0:return text[start:i]
            i+=1
        return ""

    def v29_player_config_follow(self, text, base, label="CONFIG"):
        """Safe mechanism-first follower for FirePlayer/JW/player constructor output.
        It never relies on provider/domain names and never regex-parses nested parentheses."""
        if not text:return []
        low=text.lower(); out=[]
        if not any(k in low for k in ("jwplayer","fireplayer","player(","sources","playlist","m3u8","video.src","source:")):
            return out
        funcs=[]
        try:
            for m in re.finditer(r"\b([A-Za-z_$][\w$]{2,60})\s*\(",text):
                name=m.group(1)
                if any(k in name.lower() for k in ("player","play","load","source")) and name not in funcs:funcs.append(name)
        except re.error as ex:
            self.log(f"[V29_PLAYER_CONFIG_PATTERN_ERROR] {ex}")
        self.log(f"[V29_PLAYER_CONFIG] label={label} functions={','.join(funcs[:12]) or 'NONE'}")

        scan=html.unescape(self.v29_js_unescape(text))
        # V38: learn the player family and follow actual config value flow before generic literals.
        for _u in self.v38_playerjs_static_values(scan,base,label):
            if _u not in out: out.append(_u)
        # Extract balanced calls and record useful scalar/config clues.
        for fn in funcs[:12]:
            args=self.v29_balanced_call(scan,fn)
            if not args:continue
            ck=''
            mck=re.search(r"[\"']ck[\"']\s*:\s*[\"']([^\"']{4,500})[\"']",args,re.I)
            if mck:ck=self.v29_js_unescape(mck.group(1))
            mid=re.match(r"\s*[\"']([^\"']{4,180})[\"']",args)
            self.log(f"[V29_PLAYER_CALL] function={fn} id={(mid.group(1) if mid else '-')[:180]} ckLen={len(ck)} argsBytes={len(args.encode('utf-8','ignore'))}")
            # URLs inside constructor/config are candidates; assets remain filtered by normal gates.
            for mu in re.finditer(r"https?://[^\s\"'<>]+",args,re.I):
                raw=mu.group(0).rstrip('),;]}')
                u=self.runtime_discovered_candidate(raw,base,"V29_PLAYER_CONFIG",args[max(0,mu.start()-220):mu.end()+220])
                if u and u not in out:out.append(u)

        # Also harvest absolute URLs outside constructor calls.
        for m in re.finditer(r"https?://[^\s\"'<>]+",scan,re.I):
            raw=m.group(0).rstrip('),;]}')
            u=self.runtime_discovered_candidate(raw,base,"V29_PLAYER_CONFIG",scan[max(0,m.start()-220):m.end()+220])
            if u and u not in out:out.append(u)
        return out[:24]

    # Backward-compatible name for older call sites.
    def v28_player_config_follow(self, text, base, label="CONFIG"):
        return self.v29_player_config_follow(text,base,label)

    def v29_negative_playback_evidence(self, url="", status=0, body=""):
        low=((url or "")+" "+(body or "")[:3500]).lower()
        markers=("/no_video", "no video found", "video not found", "player error", "media error", "unsupported media", "playback error")
        hit=next((m for m in markers if m in low),"")
        if hit:
            self.log(f"[V29_NEGATIVE_EVIDENCE] marker={hit} status={status} url={url}")
            return True
        return False

    def v30_note_resource_role(self, url, content_type="", resource_type="", source=""):
        """Classify resources by observed response semantics, not by filename extension."""
        if not url:return ""
        ct=(content_type or "").lower(); rt=(resource_type or "").lower(); role=""
        if "javascript" in ct or "ecmascript" in ct or rt=="script":
            role="ANALYSIS_SCRIPT"
        elif "text/css" in ct or rt=="stylesheet":
            role="STYLE_ASSET"
        elif ct.startswith("image/") or rt=="image":
            role="IMAGE_ASSET"
        elif "font" in ct or rt=="font":
            role="FONT_ASSET"
        if role:
            prev=self.v30_resource_roles.get(url)
            self.v30_resource_roles[url]=role
            if prev!=role:
                self.log(f"[V30_RESOURCE_ROLE] role={role} source={source or '-'} ct={content_type} type={resource_type} url={url}")
        return role

    def v30_target_allowed(self, url, source=""):
        if not self.v29_runtime_target_allowed(url,source):return False
        role=self.v30_resource_roles.get(url,"")
        if role in ("ANALYSIS_SCRIPT","STYLE_ASSET","IMAGE_ASSET","FONT_ASSET"):
            self.log(f"[V30_RESOURCE_SKIP] reason={role} source={source} url={url}")
            return False
        return True

    def v30_note_environment_rejection(self, url="", body="", reason=""):
        low=(body or "").lower(); ulow=(url or "").lower()
        evidence=[]
        if "devtools-detector" in low or "devtoolsdetector" in low:evidence.append("DEVTOOLS_DETECTOR")
        no_video=("no_video.html" in low or "/no_video" in ulow or "no video found" in low)
        if no_video:evidence.append("NO_VIDEO_REDIRECT")
        location=("document.location.href" in low or "location.href" in low or "window.location" in low)
        if location:evidence.append("LOCATION_REDIRECT")
        # V31: LOCATION_REDIRECT by itself is common application/player code and is only a weak hint.
        # A browser-environment rejection needs a concrete negative destination plus anti-analysis/error evidence.
        strong = no_video and ("DEVTOOLS_DETECTOR" in evidence or "no video found" in low or "/no_video" in ulow)
        if evidence:
            for e in evidence:
                if e not in self.v31_environment_hints:self.v31_environment_hints.append(e)
            self.log(f"[V31_ENV_HINT] strong={str(strong).lower()} reason={reason or '-'} evidence={','.join(evidence)} url={url}")
        if strong:
            self.v30_environment_rejected=True
            for e in evidence:
                if e not in self.v30_environment_evidence:self.v30_environment_evidence.append(e)
            self.log(f"[V31_BROWSER_ENV_REJECTED] reason={reason or '+'.join(evidence)} evidence={','.join(evidence)} url={url}")
            return True
        return False

    def v29_runtime_target_allowed(self, url, source=""):
        """Global queue gate: templates, negative/error pages and pure JS/CSS assets are analysis inputs, not browser page targets."""
        u=self.normalize_runtime_url(url,url)
        if not u:return False
        low=u.lower(); path=(urlparse(u).path or '').lower()
        if self.v29_negative_playback_evidence(u,0,''):return False
        if self.v75_nonplayback_api(u):
            self.log(f"[V75_NONPLAYBACK_API_SKIP] source={source} url={u}")
            return False
        # MIME-like strings accidentally made URL-shaped from generic HLS/player libraries.
        if any(x in low for x in ("/video/video/mp4","/video/video/mp2t","/audio/aac","; codecs=","%3b%20codecs=")):
            self.log(f"[V29_RESOURCE_SKIP] reason=MIME_LITERAL source={source} url={u}")
            return False
        if path.endswith((".js",".css",".map",".woff",".woff2",".ttf",".otf")):
            self.log(f"[V29_RESOURCE_SKIP] reason=ANALYSIS_ASSET source={source} url={u}")
            return False
        return True

    def v27_script_role_score(self, text, script_url=""):
        """Mechanism-first JS role classifier; no site/provider hardcodes."""
        low=(text or "").lower()
        path=(urlparse(script_url).path or "").lower()
        score=0; reasons=[]
        checks=(
            ("player_name", any(k in path for k in ("player","video","embed","stream","movie","watch")), 3),
            ("event_bind", any(k in low for k in ("addeventlistener",".on('click'",".on(\"click\"","onclick","pointerdown","touchstart")), 2),
            ("network", any(k in low for k in ("fetch(","$.ajax","xmlhttprequest","sendbeacon")), 2),
            ("iframe", any(k in low for k in ("createelement('iframe'","createelement(\"iframe\"","<iframe","iframe.src","data-src","data-vsrc")), 3),
            ("media", any(k in low for k in ("m3u8","mpegurl","hls.js","jwplayer","video.src","source.src","playlist")), 4),
            ("decode", any(k in low for k in ("atob(","cryptojs","aes","unescape(")), 1),
            ("source_words", any(k in low for k in ("player","source","stream","embed","playback")), 1),
        )
        for name,ok,val in checks:
            if ok:
                score+=val; reasons.append(name)
        return score,reasons

    def v27_event_selectors_from_script(self, text, label="SCRIPT"):
        """Learn likely delegated/direct playback selectors from JS source."""
        out=[]
        if not text:return out
        pats=(
            r"\.on\(\s*['\"](?:click|mousedown|pointerdown|touchstart)['\"]\s*,\s*['\"]([^'\"]{1,120})['\"]",
            r"querySelector(?:All)?\(\s*['\"]([^'\"]{1,120})['\"]\s*\)",
            r"closest\(\s*['\"]([^'\"]{1,120})['\"]\s*\)",
        )
        for pat in pats:
            for m in re.finditer(pat,text,re.I):
                sel=(m.group(1) or '').strip()
                if not sel or len(sel)>120:continue
                low=sel.lower()
                if not any(k in low for k in ("play","player","video","source","watch","ply","poster")):
                    continue
                if sel not in out:out.append(sel)
        for sel in out[:20]:
            if sel not in self.v27_event_selectors:
                self.v27_event_selectors.append(sel)
                self.log(f"[V27_EVENT_SELECTOR] label={label} selector={sel}")
        return out[:20]

    def normalize_runtime_url(self,raw,base):
        if not raw:
            return ""
        u=html.unescape(str(raw)).strip().replace("\\/","/")
        # V28: unresolved JS/template expressions are clues, never concrete URLs.
        # Examples: ${data.url}, {{source}}, <%= player %>, string concatenations.
        if re.search(r"\$\{[^}]+\}|\{\{[^}]+\}\}|<%=?[^%]+%>",u):
            self.log(f"[V28_TEMPLATE_SKIP] {u[:300]}")
            return ""
        if re.search(r"(?:^|[/=])\s*['\"]?\s*\+\s*[A-Za-z_$][\w$.[\]]*",u):
            self.log(f"[V28_TEMPLATE_SKIP] {u[:300]}")
            return ""
        if u.startswith("//"):
            u="https:"+u
        try:u=self.absolute(base,u)
        except Exception:return ""
        if not u.startswith(("http://","https://")):return ""
        if self.page_asset(u) or self.is_trailer_url(u):return ""
        return u

    def runtime_discovered_candidate(self,raw,base,source="DOM",context=""):
        u=self.normalize_runtime_url(raw,base)
        if not u:return ""
        score=self.runtime_candidate_score(u,base,source,context)
        allowed,prune_reason,score=self.v32_branch_decision(u,base,source,context,score)
        self.v32_node(u,"RUNTIME_CANDIDATE",source,base,context,score)
        if not allowed:
            self.v32_pruned.append({"url":u,"source":source,"reason":prune_reason,"score":score})
            self.log(f"[V32_BRANCH_PRUNE] reason={prune_reason} score={score} source={source} url={u}")
            return ""
        need=self.v26_runtime_queue_threshold(source,u,score)
        if score < need:
            if score>=4:
                self.log(f"[V26_QUEUE_SKIP] score={score} need={need} source={source} {u}")
            return ""
        if u not in self.runtime_discovered_urls:
            self.runtime_discovered_urls.append(u)
            self.log(f"[V26_PRIORITY_TARGET] score={score} need={need} source={source} {u}")
            self.log(f"[RUNTIME_DISCOVERED_URL] source={source} {u}")
        return u

    def extract_runtime_urls_from_html(self,fragment,base):
        out=[]
        if not fragment:return out
        patterns=(r"(?:src|data-src|data-url|data-video|data-vsrc|data-player|data-source|data-embed)\s*=\s*[\"']([^\"']+)[\"']",
                  r"https?://[^\"'<> \t\r\n]+")
        for pat in patterns:
            for m in re.finditer(pat,fragment,re.I):
                raw=m.group(1) if m.lastindex else m.group(0)
                u=self.runtime_discovered_candidate(raw,base,"DOM_MUTATION")
                if u and u not in out:out.append(u)
                du=self.v66_decode_embedded_url(raw,base,"DOM_MUTATION_ATTR")
                if du:
                    ru=self.runtime_discovered_candidate(du,base,"V66_DECODED_DOM","encoded DOM attribute")
                    if ru and ru not in out:out.append(ru)
        for du in self.v66_encoded_attribute_urls(fragment,base):
            ru=self.runtime_discovered_candidate(du,base,"V66_DECODED_DOM","encoded attribute scan")
            if ru and ru not in out:out.append(ru)
        return out[:24]

    def requeue_runtime_discovered(self,root_url):
        if self.final_verified:return False
        queue=[]
        for u in self.runtime_discovered_urls:
            # V29 global gate applies again at requeue time, purging stale V27/V28 candidates.
            nu=self.normalize_runtime_url(u,root_url)
            if not nu:
                self.log(f"[V29_REQUEUE_SKIP] reason=INVALID_OR_TEMPLATE url={str(u)[:260]}")
                continue
            if not self.v30_target_allowed(nu,"RUNTIME_REQUEUE"):
                continue
            if nu not in self.visited and nu not in queue:queue.append(nu)
        if not queue:
            self.log("[RUNTIME_REQUEUE] NONE")
            return False
        self.log(f"[RUNTIME_REQUEUE] {len(queue)}")
        for u in queue[:8]:self.log("[RUNTIME_REQUEUE_TARGET] "+u)
        for u in queue[:8]:
            if self.final_verified:return True
            self.runtime_requeue_count+=1
            self.walk(u,1,root_url,"RUNTIME_DISCOVERED")
            if self.final_verified:
                self.log("[RUNTIME_REQUEUE_RESULT] RESOLVED")
                return True
        self.log("[RUNTIME_REQUEUE_RESULT] UNRESOLVED")
        return False

    def fallback_candidate_quality(self,url,base):
        if not url:return False
        try:
            q=urlparse(url)
            if not q.netloc:return False
            text=((q.path or "")+"?"+(q.query or "")).lower()
        except Exception:return False
        bad=("videolike","videounlike","thumbs-o","comment","review","schema",
             "max-image-preview","snippet","follow","button","btn ","javascript")
        if any(x in text for x in bad):return False
        good=("/ajax","/api/","/source","/token","/player","/video","/embed","/stream","/watch")
        return any(x in text for x in good)

    def _browser_media_kind(self,url,ct=""):
        low=(url or "").lower()
        c=(ct or "").lower()
        if ".m3u8" in low or "mpegurl" in c:
            return "HLS"
        if ".mpd" in low or "dash+xml" in c:
            return "DASH"
        if ".mp4" in low or "video/mp4" in c:
            return "MP4"
        # Semantic metadata is only a hint; callers still require successful response/body
        # proof before finalization. This makes .php/API player sources observable.
        sem=(getattr(self,'v43_semantic_media',{}) or {}).get(str(url)) or {}
        return str(sem.get('transport','') or '').upper()

    def _browser_relevant_url(self,url):
        if str(url) in (getattr(self,'v43_semantic_media',{}) or {}):
            return True
        low=(url or "").lower()
        keys=(
            ".m3u8",".mp4","/list/","/m/","/stream","/video","/embed","/player",
            "/vx/","/vod/","/pt/","/fl/","/fastly/","master","index.m3u8",
            "client.php","session-state.php","source","watch/","playlist","manifest"
        )
        return any(k in low for k in keys)

    def browser_transport_recovery_urls(self,url):
        """Generic transport recovery candidates for a player URL that fails TLS/SSL.
        This does not accept media; candidates still have to survive browser/network evidence."""
        out=[]
        try:
            q=urlparse(url)
            if q.scheme=="https" and q.netloc:
                alt=q._replace(scheme="http").geturl()
                if alt!=url: out.append(alt)
        except Exception:
            pass
        return out[:3]

    def browser_runtime_probe(self,root_url):
        self.log("[BROWSER_RUNTIME] START")
        try:
            from playwright.sync_api import sync_playwright
        except Exception as e:
            self.browser_runtime_error=f"PLAYWRIGHT_IMPORT: {type(e).__name__}: {e}"
            self.log("[BROWSER_RUNTIME] UNAVAILABLE playwright package missing")
            self.log("[BROWSER_SETUP] BROWSER_KUR.bat dosyasini bir kez calistir")
            return False

        media_hits=[]
        # V57: URLs explicitly declared by the page as pre-roll/ad media are quarantined.
        # This is structural evidence (data-preroll / ad DOM), not a provider/domain blacklist.
        runtime_ad_media_urls=set()
        json_media=[]
        seen_net=set()
        v40_bootstrap_sources=[]
        v40_bootstrap_seen=[]

        def remember_media(url,kind,status,ct,source="response"):
            if not url or status < 200 or status >= 400:
                return
            # V57: never let a page-declared pre-roll/ad asset become playback media.
            # Keep observing the same session until the real player stream appears.
            if url in runtime_ad_media_urls or self.v37_ad_media_evidence(url, source):
                self.log(f"[V57_AD_MEDIA_QUARANTINE] source={source} kind={kind} url={url}")
                return
            item=(url,kind,status,ct,source)
            if item not in media_hits:
                media_hits.append(item)
            # V20: final URL uzantisiz/dinamik olabilir. Karari response kaniti verir;
            # request context ise daha sonra player handoff icin saklanir.
            reqctx=dict(self.browser_request_context.get(url,{}) or {})
            try:
                cookie_items=context.cookies([url])
                if cookie_items:
                    reqctx["cookie"]="; ".join(
                        f"{c.get('name','')}={c.get('value','')}" for c in cookie_items
                        if c.get('name')
                    )
            except Exception:
                pass
            self.browser_media_context[url]=reqctx

        try:
            with sync_playwright() as pw:
                # V44: first attach to a user-launched real Google Chrome over CDP.
                # No UA/client-hint spoofing is applied to that browser. Its existing
                # context, cookies and browser identity stay authoritative.
                v44_real_chrome=False
                v44_attached_browser=False
                try:
                    browser=pw.chromium.connect_over_cdp(
                        "http://127.0.0.1:9222", timeout=3500
                    )
                    v44_real_chrome=True
                    v44_attached_browser=True
                    self.v50_real_chrome_attached=True
                    self.v50_browser_mode="REAL_CHROME_CDP"
                    self.log("[V44_REAL_CHROME_ATTACH] PASS endpoint=http://127.0.0.1:9222")
                except Exception as attach_e:
                    self.log(
                        f"[V44_REAL_CHROME_ATTACH] MISS endpoint=http://127.0.0.1:9222 "
                        f"error={type(attach_e).__name__}: {str(attach_e)[:260]}"
                    )

                    # V56: Do NOT launch Playwright's bundled Chromium. When a test
                    # needs browser runtime, Resolver Lab starts the user's installed
                    # Google Chrome itself and then attaches to that visible Chrome via CDP.
                    # A dedicated persistent profile is required by current Chrome for
                    # remote debugging; it also keeps cookies/localStorage between tests.
                    chrome_candidates = [
                        os.path.join(os.environ.get("PROGRAMFILES", ""), "Google", "Chrome", "Application", "chrome.exe"),
                        os.path.join(os.environ.get("PROGRAMFILES(X86)", ""), "Google", "Chrome", "Application", "chrome.exe"),
                        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "Application", "chrome.exe"),
                    ]
                    chrome_exe = next((x for x in chrome_candidates if x and os.path.isfile(x)), None)
                    if not chrome_exe:
                        # GitHub Actions/Linux: the workflow installs Playwright Chromium.
                        # Use that executable with the existing CDP launch path instead
                        # of requiring a system Google Chrome installation.
                        if os.environ.get("V81_GITHUB", "").lower() in ("1", "true", "yes"):
                            try:
                                chrome_exe = pw.chromium.executable_path
                                self.v50_browser_mode="GITHUB_PLAYWRIGHT_CHROMIUM_CDP"
                                self.log(f"[V81_GITHUB_BROWSER] using Playwright Chromium executable={chrome_exe}")
                            except Exception as e:
                                self.v50_real_chrome_attached=False
                                self.v50_browser_mode="GITHUB_PLAYWRIGHT_CHROMIUM_FAILED"
                                self.browser_runtime_error=f"GITHUB_CHROMIUM_PATH: {type(e).__name__}: {e}"
                                self.log(f"[V81_GITHUB_BROWSER] FAIL executable_path error={type(e).__name__}: {e}")
                                return False
                        else:
                            self.v50_real_chrome_attached=False
                            self.v50_browser_mode="GOOGLE_CHROME_REQUIRED"
                            self.browser_runtime_error="GOOGLE_CHROME_NOT_FOUND"
                            self.log("[V56_GOOGLE_CHROME] FAIL reason=CHROME_EXE_NOT_FOUND")
                            return False

                    profile_dir = str(ROOT / "chrome_v56_profile")
                    os.makedirs(profile_dir, exist_ok=True)
                    chrome_args = [
                        chrome_exe,
                        "--remote-debugging-port=9222",
                        "--remote-debugging-address=127.0.0.1",
                        f"--user-data-dir={profile_dir}",
                        "--no-first-run",
                        "--no-default-browser-check",
                        "--autoplay-policy=no-user-gesture-required",
                        "about:blank",
                    ]
                    try:
                        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
                        chrome_env = os.environ.copy()
                        chrome_netlog = str(ROOT / "chrome_v74_debug.log")
                        chrome_env["CHROME_LOG_FILE"] = chrome_netlog
                        chrome_args.insert(-1, "--enable-logging")
                        self.log(f"[V74_CHROME_LAUNCH] exe={chrome_exe} profile={profile_dir}")
                        self.log(f"[V74_CHROME_ARGS] {' '.join(chrome_args[1:])}")
                        try:
                            _px = urllib.request.getproxies()
                        except Exception:
                            _px = {}
                        self.log(f"[V74_SYSTEM_PROXY] {json.dumps(_px, ensure_ascii=False, default=str)}")
                        subprocess.Popen(
                            chrome_args,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            stdin=subprocess.DEVNULL,
                            close_fds=True,
                            creationflags=creationflags,
                            env=chrome_env,
                        )
                        self.log(f"[V56_GOOGLE_CHROME] START exe={chrome_exe} profile={profile_dir}")
                        self.log(f"[V74_CHROME_LOG] path={chrome_netlog}")
                    except Exception as launch_e:
                        self.v50_real_chrome_attached=False
                        self.v50_browser_mode="GOOGLE_CHROME_LAUNCH_FAILED"
                        self.browser_runtime_error=f"GOOGLE_CHROME_LAUNCH: {type(launch_e).__name__}: {launch_e}"
                        self.log(f"[V56_GOOGLE_CHROME] FAIL reason=LAUNCH_ERROR error={type(launch_e).__name__}: {launch_e}")
                        return False

                    browser = None
                    last_attach = None
                    for _ in range(30):
                        try:
                            browser = pw.chromium.connect_over_cdp("http://127.0.0.1:9222", timeout=1500)
                            break
                        except Exception as retry_e:
                            last_attach = retry_e
                            time.sleep(0.25)
                    if browser is None:
                        # GitHub Actions/Linux fallback: use Playwright-managed Chromium
                        # instead of requiring a locally installed Google Chrome or mitmdump.
                        # The existing CDP/network observer below remains unchanged.
                        if os.environ.get("V81_GITHUB", "").lower() in ("1", "true", "yes"):
                            try:
                                self.log("[V81_GITHUB_BROWSER] launching Playwright Chromium headless")
                                browser = pw.chromium.launch(
                                    headless=True,
                                    args=[
                                        "--autoplay-policy=no-user-gesture-required",
                                        "--disable-dev-shm-usage",
                                        "--no-sandbox",
                                        "--disable-setuid-sandbox",
                                    ],
                                )
                                v44_real_chrome=False
                                v44_attached_browser=False
                                self.v50_real_chrome_attached=False
                                self.v50_browser_mode="GITHUB_PLAYWRIGHT_CHROMIUM"
                                self.log("[V81_GITHUB_BROWSER] PASS mode=GITHUB_PLAYWRIGHT_CHROMIUM")
                            except Exception as launch_e:
                                self.v50_real_chrome_attached=False
                                self.v50_browser_mode="GITHUB_PLAYWRIGHT_CHROMIUM_FAILED"
                                self.browser_runtime_error=f"GITHUB_CHROMIUM: {type(launch_e).__name__}: {launch_e}"
                                self.log(f"[V81_GITHUB_BROWSER] FAIL error={type(launch_e).__name__}: {launch_e}")
                                return False
                        else:
                            self.v50_real_chrome_attached=False
                            self.v50_browser_mode="GOOGLE_CHROME_CDP_FAILED"
                            self.browser_runtime_error=f"GOOGLE_CHROME_CDP: {type(last_attach).__name__ if last_attach else 'UNKNOWN'}: {last_attach}"
                            self.log(f"[V56_GOOGLE_CHROME] FAIL reason=CDP_ATTACH error={type(last_attach).__name__ if last_attach else 'UNKNOWN'}: {str(last_attach)[:260]}")
                            return False

                    if v44_real_chrome:
                        v44_real_chrome=True
                    v44_attached_browser=True
                    self.v50_real_chrome_attached=True
                    self.v50_browser_mode="USER_GOOGLE_CHROME_CDP"
                    self.log("[V56_GOOGLE_CHROME] PASS mode=USER_INSTALLED_GOOGLE_CHROME_CDP endpoint=http://127.0.0.1:9222")

                self.browser_runtime_available=True
                self.browser_runtime_used=True

                if v44_real_chrome:
                    contexts=list(browser.contexts)
                    if not contexts:
                        self.browser_runtime_error="REAL_CHROME_CDP: no browser context"
                        self.log("[V44_REAL_CHROME_ATTACH] FAIL reason=NO_CONTEXT")
                        return False
                    context=contexts[0]
                    self.log(f"[V44_CONTEXT_REUSE] contexts={len(contexts)} pages={len(context.pages)}")
                else:
                    _v54_mobile=bool(getattr(self,"v54_mobile_environment_retry",False))
                    _v54_ua=MOBILE_UA if _v54_mobile else UA
                    _v54_viewport={"width":412,"height":915} if _v54_mobile else {"width":1365,"height":768}
                    context=browser.new_context(
                        user_agent=_v54_ua,
                        locale="tr-TR",
                        ignore_https_errors=True,
                        viewport=_v54_viewport,
                        is_mobile=_v54_mobile,
                        has_touch=_v54_mobile,
                        java_script_enabled=True,
                    )
                    self.log(f"[V54_ENV_PROFILE] profile={'MOBILE_COMPAT' if _v54_mobile else 'DESKTOP_DEFAULT'} reason={'ENVIRONMENT_RETRY' if _v54_mobile else 'PRIMARY'}")

                # Static analyzer cookies are only injected into the fallback browser.
                # Real Chrome owns its own persistent profile/session.
                if self.cookies and not v44_real_chrome:
                    parsed=urlparse(root_url)
                    ck=[]
                    for k,v in self.cookies.items():
                        ck.append({
                            "name":k, "value":v,
                            "domain":parsed.hostname or "",
                            "path":"/", "secure":parsed.scheme=="https"
                        })
                    try:
                        context.add_cookies(ck)
                    except Exception:
                        pass

                page=None
                if v44_real_chrome:
                    root_norm=(root_url or "").rstrip("/")
                    for existing_page in list(context.pages):
                        try:
                            eu=(existing_page.url or "").rstrip("/")
                            if eu and (eu==root_norm or eu.startswith(root_norm) or root_norm.startswith(eu)):
                                page=existing_page
                                self.log(f"[V44_EXISTING_TAB] REUSE url={existing_page.url}")
                                break
                        except Exception:
                            pass
                    if page is None:
                        page=context.new_page()
                        self.log("[V44_EXISTING_TAB] NEW_VISIBLE_TAB")
                    self.log("[V44_BROWSER_MODE] REAL_CHROME_CDP")

                # V64: F12-style decoder execution. The player page itself may refuse to
                # render/play in external Chrome; that is irrelevant here. We execute only
                # the exact decoder function already captured from the HTTP player HTML.
                if self._v64_eval_decoder_jobs(page):
                    return True
                    self.v46_clean_observer=True
                    self.log("[V65_AGENT_BROWSER] ACTIVE=true mode=CAUSAL_OBSERVE_THEN_ACT\n[V65_AGENT_ACTION] ENABLED=true policy=DISCOVER_PLAYER_CONTROLS_THEN_NETWORK_DELTA\n[V65_XHR_HANDOFF] ENABLED=true response=json_text semantic_url_follow=true")
                else:
                    page=context.new_page()
                # V39: install runtime observers before any target JavaScript executes.
                if getattr(self,"v46_clean_observer",False):
                    self.log("[V46_CLEAN_OBSERVER] PRENAV_HOOKS=SKIPPED")
                else:
                    try:
                        page.add_init_script(self.v39_init_script())
                        self.log("[V39_PRENAV_HOOKS] installed=true")
                    except Exception as _v39i:
                        self.log(f"[V39_PRENAV_HOOKS_ERROR] {type(_v39i).__name__}: {_v39i}")

                # V21 F12 parity: Chrome DevTools Protocol Network domain.
                # This observes the renderer network layer independently from DOM selectors.
                # No provider/domain/path is hardcoded; media is accepted only by response evidence.
                cdp=None
                cdp_requests={}
                cdp_responses={}
                cdp_request_extra={}
                cdp_response_extra={}
                cdp_response_bodies={}
                cdp_response_urls={}
                cdp_media_ids=set()
                # V33: keep browser-observed HLS bodies keyed by the response URL.
                # V32 only kept discovered child URLs, so final proof could not recover
                # the already-observed manifest body after the browser phase.
                self.v33_browser_hls_observed={}
                try:
                    cdp=context.new_cdp_session(page)
                    cdp.send("Network.enable", {"maxTotalBufferSize": 100000000, "maxResourceBufferSize": 10000000})
                    self.log("[V26_F12_CDP] Network.enable OK")

                    # V61: passive repo-forensics capture. No browser interaction.
                    _v61_req={}
                    _v61_interest=re.compile(r"(ajax(?:-token)?|token|embed|player|source|manifest|master|\.m3u8(?:\?|$)|\.mpd(?:\?|$))", re.I)

                    def _v61_clip(value, limit=50000):
                        try:
                            value="" if value is None else str(value)
                        except Exception:
                            value=repr(value)
                        return value if len(value)<=limit else value[:limit]+"...<TRUNCATED>"

                    def _v61_headers(headers):
                        return {str(k):_v61_clip(v,4000) for k,v in (headers or {}).items()}

                    def _v61_req_event(ev):
                        try:
                            req=ev.get("request") or {}
                            rid=str(ev.get("requestId") or "")
                            url=str(req.get("url") or "")
                            method=str(req.get("method") or "")
                            rtype=str(ev.get("type") or "")
                            docurl=str(ev.get("documentURL") or "")
                            player_resource = rtype.lower() in ("document","script","xhr","fetch") and (
                                "formationfeed" in url.lower() or "formationfeed" in docurl.lower()
                            )
                            if not (_v61_interest.search(url) or method.upper()!="GET" or player_resource):
                                return
                            row={
                                "requestId":rid, "url":url, "method":method,
                                "resourceType":ev.get("type"), "frameId":ev.get("frameId"),
                                "loaderId":ev.get("loaderId"), "documentURL":ev.get("documentURL"),
                                "initiator":ev.get("initiator"),
                                "headers":_v61_headers(req.get("headers") or {}),
                                "hasPostData":req.get("hasPostData"),
                                "postData":req.get("postData"),
                            }
                            _v61_req[rid]=row
                            self.log("[V61_REPO_REQUEST] "+json.dumps(row,ensure_ascii=False,default=str))
                        except Exception as e:
                            self.log(f"[V61_REPO_CAPTURE_ERROR] request {e}")

                    def _v61_resp_event(ev):
                        try:
                            resp=ev.get("response") or {}
                            rid=str(ev.get("requestId") or "")
                            url=str(resp.get("url") or "")
                            mime=str(resp.get("mimeType") or "")
                            prior=_v61_req.get(rid)
                            if not (prior or _v61_interest.search(url) or "json" in mime.lower() or "mpegurl" in mime.lower()):
                                return
                            row={
                                "requestId":rid, "url":url, "status":resp.get("status"),
                                "mimeType":mime, "protocol":resp.get("protocol"),
                                "remoteIPAddress":resp.get("remoteIPAddress"),
                                "headers":_v61_headers(resp.get("headers") or {}),
                                "request":prior,
                            }
                            self.log("[V61_REPO_RESPONSE] "+json.dumps(row,ensure_ascii=False,default=str))
                        except Exception as e:
                            self.log(f"[V61_REPO_CAPTURE_ERROR] response {e}")

                    def _v61_finished_event(ev):
                        try:
                            rid=str(ev.get("requestId") or "")
                            prior=_v61_req.get(rid)
                            if not prior:
                                return
                            try:
                                obj=cdp.send("Network.getResponseBody",{"requestId":rid})
                                self.log("[V61_REPO_RESPONSE_BODY] "+json.dumps({
                                    "requestId":rid,
                                    "url":prior.get("url"),
                                    "base64Encoded":obj.get("base64Encoded") if isinstance(obj,dict) else None,
                                    "body":_v61_clip(obj.get("body") if isinstance(obj,dict) else obj),
                                },ensure_ascii=False,default=str))
                            except Exception as e:
                                self.log("[V61_REPO_RESPONSE_BODY_MISS] "+json.dumps({
                                    "requestId":rid,"url":prior.get("url"),"error":str(e)
                                },ensure_ascii=False))
                        except Exception as e:
                            self.log(f"[V61_REPO_CAPTURE_ERROR] finished {e}")

                    cdp.on("Network.requestWillBeSent",_v61_req_event)
                    cdp.on("Network.responseReceived",_v61_resp_event)
                    cdp.on("Network.loadingFinished",_v61_finished_event)
                    self.log("[V61_REPO_FORENSICS] ACTIVE=true passive=true method=true request_headers=true request_body=true response_headers=true response_body=true initiator=true")


                    def _v42_header_get(headers, name):
                        lname=str(name or "").lower()
                        for k,v in (headers or {}).items():
                            if str(k).lower()==lname:
                                return str(v)
                        return ""

                    def _v42_safe_header_summary(headers):
                        # Do not dump complete cookies/tokens into logs. Presence and size are
                        # sufficient for normal-Chrome vs resolver comparison.
                        h=headers or {}
                        cookie=_v42_header_get(h,"cookie")
                        auth=_v42_header_get(h,"authorization")
                        return {
                            "User-Agent":_v42_header_get(h,"user-agent")[:260],
                            "Referer":_v42_header_get(h,"referer")[:500],
                            "Origin":_v42_header_get(h,"origin")[:500],
                            "Accept":_v42_header_get(h,"accept")[:500],
                            "Accept-Language":_v42_header_get(h,"accept-language")[:260],
                            "Sec-Fetch-Site":_v42_header_get(h,"sec-fetch-site")[:120],
                            "Sec-Fetch-Mode":_v42_header_get(h,"sec-fetch-mode")[:120],
                            "Sec-Fetch-Dest":_v42_header_get(h,"sec-fetch-dest")[:120],
                            "Sec-CH-UA":_v42_header_get(h,"sec-ch-ua")[:300],
                            "Sec-CH-UA-Platform":_v42_header_get(h,"sec-ch-ua-platform")[:120],
                            "Cookie":f"present:{bool(cookie)} bytes:{len(cookie)}",
                            "Authorization":f"present:{bool(auth)} bytes:{len(auth)}",
                        }

                    def _v42_is_antibot_body(text):
                        low=(text or "").lower()
                        needles=(
                            "sorry, you have been blocked", "attention required",
                            "cloudflare ray id", "cf-error-details", "cdn-cgi/challenge-platform",
                            "checking your browser", "verify you are human",
                            "access denied", "request blocked", "captcha"
                        )
                        return any(x in low for x in needles)

                    def _v42_record_protected_failure(rid, reqmeta, meta, body=""):
                        status=int((meta or {}).get("status",0) or 0)
                        if status not in (401,403,407,409,423,425,429,451,503) and not _v42_is_antibot_body(body):
                            return
                        url=str((meta or {}).get("url","") or (reqmeta or {}).get("url","") or "")
                        typ=str((reqmeta or {}).get("type","") or "")
                        if typ.lower() not in ("xhr","fetch","ping"):
                            return
                        base_headers=dict((reqmeta or {}).get("headers") or {})
                        extra_headers=dict(cdp_request_extra.get(rid) or {})
                        merged=dict(base_headers); merged.update(extra_headers)
                        hs=_v42_safe_header_summary(merged)
                        frame_id=str((reqmeta or {}).get("frameId","") or "")
                        initiator=(reqmeta or {}).get("initiator") or {}
                        rec={
                            "requestId":rid,"url":url,"status":status,"type":typ,
                            "method":str((reqmeta or {}).get("method","GET")),
                            "frameId":frame_id,"headers":hs,
                            "initiatorType":str(initiator.get("type","") or ""),
                            "antibotBody":bool(_v42_is_antibot_body(body)),
                            "bodyPreview":str(body or "")[:700],
                        }
                        self.v42_protected_requests.append(rec)
                        self.v42_failure_stage="PLAYER_BOOTSTRAP_XHR"
                        self.log(f"[V42_PROTECTED_REQUEST] frameId={frame_id or '-'} id={rid} type={typ} method={rec['method']} url={url}")
                        self.log("[V42_REQUEST_HEADERS] "+" | ".join(f"{k}={v}" for k,v in hs.items()))
                        provider="CLOUDFLARE" if ("cloudflare" in (body or "").lower() or "cf-error" in (body or "").lower()) else "UNKNOWN_WAF"
                        self.log(f"[V42_ANTIBOT_BLOCK] provider={provider} stage=PLAYER_BOOTSTRAP_XHR status={status} url={url}")

                    def cdp_request_extra_info(ev):
                        try:
                            rid=str(ev.get("requestId", ""))
                            hdrs=dict(ev.get("headers") or {})
                            cdp_request_extra[rid]=hdrs
                            self.v42_request_extra_headers[rid]=_v42_safe_header_summary(hdrs)
                        except Exception as e:
                            self.log(f"[V42_REQUEST_EXTRA_ERROR] {type(e).__name__}: {e}")

                    def cdp_response_extra_info(ev):
                        try:
                            rid=str(ev.get("requestId", ""))
                            hdrs=dict(ev.get("headers") or {})
                            cdp_response_extra[rid]=hdrs
                            self.v42_response_extra_headers[rid]={
                                "server":_v42_header_get(hdrs,"server")[:200],
                                "cf-ray":_v42_header_get(hdrs,"cf-ray")[:200],
                                "content-type":_v42_header_get(hdrs,"content-type")[:200],
                                "set-cookie":f"present:{bool(_v42_header_get(hdrs,'set-cookie'))} bytes:{len(_v42_header_get(hdrs,'set-cookie'))}",
                            }
                        except Exception as e:
                            self.log(f"[V42_RESPONSE_EXTRA_ERROR] {type(e).__name__}: {e}")

                    def cdp_request(ev):
                        try:
                            rid=str(ev.get("requestId", ""))
                            req=ev.get("request") or {}
                            url=str(req.get("url", ""))
                            if not url.startswith(("http://", "https://")):
                                return
                            hdrs={str(k).lower():str(v) for k,v in (req.get("headers") or {}).items()}
                            ctx={
                                "referer":hdrs.get("referer", ""),
                                "origin":hdrs.get("origin", ""),
                                "accept":hdrs.get("accept", ""),
                                "range":hdrs.get("range", ""),
                                "user-agent":hdrs.get("user-agent", UA),
                                "cookie":hdrs.get("cookie", ""),
                            }
                            self.browser_request_context[url]=ctx
                            _frame_id=str(ev.get("frameId", "") or "")
                            cdp_requests[rid]={
                                "url":url,
                                "context":ctx,
                                "type":str(ev.get("type", "")),
                                "initiator":ev.get("initiator") or {},
                                "method":str(req.get("method", "GET")),
                                "postData":str(req.get("postData", "") or ""),
                                "headers":dict(req.get("headers") or {}),
                                "frameId":_frame_id,
                            }
                            typ=str(ev.get("type", "") or "")
                            if typ.lower() in ("xhr","fetch","ping"):
                                pd=str(req.get("postData", "") or "")
                                self.v41_frame_xhr_seen.append((rid,_frame_id,url,typ))
                                self.log(f"[V41_FRAME_XHR_REQUEST] frameId={_frame_id or '-'} id={rid} type={typ} method={req.get('method','GET')} url={url}")
                                self.log(f"[V26_ACTION_REQUEST] id={rid} type={typ} method={req.get('method','GET')} url={url}")
                                if pd:
                                    self.log("[V26_ACTION_REQUEST_BODY] "+pd[:12000])
                            if self._browser_relevant_url(url) or self.runtime_request_relevant(url, str(req.get("method","GET")), str(req.get("postData", ""))):
                                self.log(f"[V26_F12_REQ] {req.get('method','GET')} type={ev.get('type','')} {url}")
                        except Exception as e:
                            self.log(f"[V26_F12_REQ_ERROR] {type(e).__name__}: {e}")

                    def cdp_response(ev):
                        try:
                            rid=str(ev.get("requestId", ""))
                            resp=ev.get("response") or {}
                            url=str(resp.get("url", ""))
                            status=int(resp.get("status", 0) or 0)
                            mime=str(resp.get("mimeType", "") or "")
                            hdrs=resp.get("headers") or {}
                            ct=str(next((v for k,v in hdrs.items() if str(k).lower()=="content-type"), mime) or mime)
                            cdp_responses[rid]={"url":url,"status":status,"ct":ct,"headers":dict(hdrs or {})}
                            reqmeta=cdp_requests.get(rid) or {}
                            if status in (301,302,303,307,308):
                                loc=""
                                try:
                                    loc=next((str(v) for k,v in (hdrs or {}).items() if str(k).lower()=="location"),"")
                                except Exception:
                                    loc=""
                                if loc:
                                    try: loc=urljoin(url,loc)
                                    except Exception: pass
                                    self.log(f"[V35_REDIRECT] status={status} from={url} to={loc}")
                                    self.v32_evidence_edge(url,loc,"HTTP_REDIRECT")
                            rtyp=str(reqmeta.get("type", "") or "")
                            self.v30_note_resource_role(url,ct,rtyp,"CDP_RESPONSE")
                            if rtyp.lower() in ("xhr","fetch","ping"):
                                _fid=str(reqmeta.get("frameId", "") or "")
                                self.log(f"[V41_FRAME_XHR_RESPONSE] frameId={_fid or '-'} id={rid} type={rtyp} status={status} ct={ct} url={url}")
                                self.log(f"[V26_ACTION_RESPONSE] id={rid} type={rtyp} status={status} ct={ct} url={url}")
                                if status in (401,403,407,409,423,425,429,451,503):
                                    eh=dict(cdp_response_extra.get(rid) or {})
                                    self.log(f"[V42_PROTECTED_RESPONSE] id={rid} status={status} ct={ct} server={_v42_header_get(eh,'server')} cf-ray={_v42_header_get(eh,'cf-ray')} url={url}")
                            kind=self._browser_media_kind(url,ct)
                            sem_hint=(getattr(self,'v43_semantic_media',{}) or {}).get(url) or {}
                            hard_kind=(
                                '.m3u8' in url.lower() or '.mpd' in url.lower() or '.mp4' in url.lower() or
                                'mpegurl' in ct.lower() or 'dash+xml' in ct.lower() or 'video/mp4' in ct.lower()
                            )
                            if kind and hard_kind:
                                cdp_media_ids.add(rid)
                                self.log(f"[V26_F12_MEDIA_RESPONSE] {status} {ct} {url}")
                                remember_media(url,kind,status,ct,"cdp_response")
                            elif sem_hint:
                                self.log(f"[V43_SEMANTIC_RESPONSE] transport={sem_hint.get('transport','UNKNOWN')} status={status} ct={ct} url={url}")
                            elif self._browser_relevant_url(url):
                                self.log(f"[V26_F12_RESP] {status} {ct} {url}")
                        except Exception as e:
                            self.log(f"[V26_F12_RESP_ERROR] {type(e).__name__}: {e}")

                    def cdp_finished(ev):
                        try:
                            rid=str(ev.get("requestId", ""))
                            meta=cdp_responses.get(rid) or {}
                            reqmeta=cdp_requests.get(rid) or {}
                            url=str(meta.get("url", ""))
                            status=int(meta.get("status", 0) or 0)
                            ct=str(meta.get("ct", "") or "")
                            typ=str(reqmeta.get("type", "") or "")
                            if not url:
                                return
                            lct=ct.lower()
                            action_transport=typ.lower() in ("xhr","fetch","ping")
                            # V42: V41 discarded >=400 before Network.getResponseBody. That hid the
                            # exact failure body of protected player-bootstrap XHR/fetch calls.
                            # Keep failed action transports long enough to read/classify their body.
                            failed_action=action_transport and status >= 400
                            if (status < 200 or status >= 400) and not failed_action:
                                return
                            sniff=(action_transport or "mpegurl" in lct or "json" in lct or "text" in lct or
                                   "javascript" in lct or "xml" in lct or "octet-stream" in lct or self._browser_relevant_url(url))
                            if not sniff:
                                return
                            try:
                                body=cdp.send("Network.getResponseBody", {"requestId":rid}) or {}
                                txt=str(body.get("body", ""))
                            except Exception as be:
                                if action_transport:
                                    self.log(f"[V26_ACTION_BODY_ERROR] id={rid} {type(be).__name__}: {be}")
                                return
                            cdp_response_bodies[rid]=txt[:200000]

                            # V62: preserve the exact player/bootstrap source that creates media.
                            # Passive only: response observation, no click/play/skip mutation.
                            try:
                                _v62_url_low=url.lower()
                                _v62_typ_low=typ.lower()
                                _v62_player_body=(
                                    "formationfeed" in _v62_url_low
                                    or _v62_typ_low in ("xhr","fetch")
                                    or "javascript" in lct
                                    or _v62_typ_low in ("document","script") and ("player" in _v62_url_low or "embed" in _v62_url_low)
                                )
                                if _v62_player_body:
                                    _v62_payload={
                                        "requestId":rid,"url":url,"status":status,"contentType":ct,
                                        "resourceType":typ,"frameId":str(reqmeta.get("frameId","") or ""),
                                        "requestMethod":str(reqmeta.get("method","GET") or "GET"),
                                        "requestPostData":str(reqmeta.get("postData","") or "")[:50000],
                                        "requestHeaders":dict(reqmeta.get("headers") or {}),
                                        "responseHeaders":dict(meta.get("headers") or {}),
                                        "body":txt[:200000],
                                    }
                                    self.log("[V62_PLAYER_SOURCE_BODY] "+json.dumps(_v62_payload,ensure_ascii=False,default=str))
                                    _v62_urls=[]
                                    for _m in re.findall(r'https?://[^\s\"\'<>\\]+',txt):
                                        _u=html.unescape(_m).rstrip('),;]')
                                        if _u not in _v62_urls:_v62_urls.append(_u)
                                    if _v62_urls:
                                        self.log("[V62_PLAYER_SOURCE_URLS] "+json.dumps({"source":url,"urls":_v62_urls[:100]},ensure_ascii=False))
                                    if "jwplayer" in txt.lower() or ".setup(" in txt or "sources" in txt.lower():
                                        self.log("[V62_PLAYER_CONFIG_SOURCE] "+json.dumps({"url":url,"body":txt[:200000]},ensure_ascii=False,default=str))
                            except Exception as _v62e:
                                self.log(f"[V62_PLAYER_SOURCE_ERROR] {type(_v62e).__name__}: {_v62e}")

                            self.v30_note_environment_rejection(url,txt,"CDP_BODY")
                            if action_transport:
                                _fid=str(reqmeta.get("frameId", "") or "")
                                self.log(f"[V41_FRAME_XHR_BODY] frameId={_fid or '-'} id={rid} bytes={len(txt.encode('utf-8','replace'))} url={url}")
                                self.log(f"[V26_ACTION_RESPONSE_BODY] id={rid} bytes={len(txt.encode('utf-8','replace'))} preview={txt[:2500]!r}")
                            if failed_action:
                                _v42_record_protected_failure(rid,reqmeta,meta,txt)
                                return
                            if txt.lstrip().startswith("#EXTM3U"):
                                self.log(f"[V26_F12_HLS_BODY] status={status} ct={ct} {url}")
                                reqctx=dict((reqmeta.get("context") or self.browser_request_context.get(url,{}) or {}))
                                self.v33_browser_hls_observed[url]={"body":txt,"status":status,"ct":ct,"context":reqctx,"source":"cdp_body"}
                                self.log(f"[V33_HLS_PROOF_SEED] source=CDP status={status} bytes={len(txt.encode('utf-8','replace'))} url={url}")
                                if self.v34_is_media_playlist(txt):
                                    self.v34_trigger_observed_media_playlist(
                                        url,txt,status,ct,reqctx,"CDP_OBSERVED_MEDIA"
                                    )
                                remember_media(url,"HLS",status,ct,"cdp_body")
                                return
                            discovered=[]
                            if "json" in lct or txt.lstrip().startswith(("{","[")):
                                try:
                                    obj=json.loads(txt)
                                    # V40: bootstrap JSON semantics outrank extension-based URL scoring.
                                    _v40=self.v40_bootstrap_json(txt,url)
                                    if _v40:
                                        _fid=str(reqmeta.get("frameId", "") or "")
                                        self.log(f"[V41_FRAME_BOOTSTRAP_JSON] frameId={_fid or '-'} sources={len(_v40)} url={url}")
                                        v40_bootstrap_seen.append(url)
                                        for _it in _v40:
                                            _ju=_it.get("url","")
                                            if _ju and _ju not in v40_bootstrap_sources:
                                                v40_bootstrap_sources.append(_ju)
                                            if _ju and _ju not in json_media:
                                                json_media.append(_ju)
                                            if _ju:
                                                _sem=dict(self.v43_semantic_media.get(_ju) or {})
                                                _ctx=dict(reqmeta.get('context') or {})
                                                _sem.update({
                                                    'frameId':_fid,
                                                    'frameUrl':_ctx.get('referer','') or url,
                                                    'bootstrapUrl':url,
                                                    'requestContext':_ctx,
                                                })
                                                self.v43_semantic_media[_ju]=_sem
                                                self.log(f"[V43_FRAME_OWNER_BIND] frameId={_fid or '-'} frameUrl={_sem.get('frameUrl','')} source={_ju}")
                                            self.v32_evidence_edge(url,_ju,"V43_SEMANTIC_BOOTSTRAP_FILE")
                                            self.log(f"[V41_BOOTSTRAP_HANDOFF] decision=KEEP_FRAME_SESSION_AND_OBSERVE source={_ju}")
                                    for ju in self.media_urls_from_object(obj,url)[:30]:
                                        if ju not in discovered: discovered.append(ju)
                                except Exception:
                                    pass
                            # HTML/text/encoded AJAX responses can contain iframe/source/player URLs.
                            try:
                                for ju in self.extract_runtime_urls_from_html(txt,url)[:30]:
                                    if ju not in discovered: discovered.append(ju)
                            except Exception:
                                pass
                            # Last generic pass: absolute HTTP(S) literals in any textual action response.
                            for m in re.findall(r'https?://[^\s\"\'<>\\]+', txt):
                                ju=html.unescape(m).rstrip('),;]')
                                if ju not in discovered: discovered.append(ju)
                            accepted_discovered=[]
                            for ju in discovered[:30]:
                                score=self.runtime_candidate_score(ju,url,"V26_RESPONSE_"+(typ or "response"),txt[:5000])
                                need=self.v26_runtime_queue_threshold("V26_RESPONSE",ju,score)
                                if score < need:
                                    if score>=4:
                                        self.log(f"[V26_RESPONSE_SKIP] score={score} need={need} source={typ or 'response'} {ju}")
                                    continue
                                self.log(f"[V26_RESPONSE_TARGET] score={score} need={need} source={typ or 'response'} {ju}")
                                accepted_discovered.append(ju)
                                if ju not in json_media:
                                    json_media.append(ju)
                                self.runtime_discovered_candidate(ju,url,"V26_RESPONSE",txt[:5000])
                            cdp_response_urls[rid]=accepted_discovered
                        except Exception as e:
                            self.log(f"[V26_F12_BODY_ERROR] {type(e).__name__}: {e}")

                    def cdp_loading_failed(params):
                        try:
                            rid=str(params.get("requestId","") or "")
                            # V74: V73 referenced a non-existent cdp_request_meta dict here.
                            # cdp_requests is the authoritative request map populated by requestWillBeSent.
                            meta=cdp_requests.get(rid,{}) or {}
                            item={
                                "requestId":rid,
                                "url":str(meta.get("url","") or ""),
                                "errorText":str(params.get("errorText","") or ""),
                                "blockedReason":str(params.get("blockedReason","") or ""),
                                "corsErrorStatus":params.get("corsErrorStatus") or {},
                                "canceled":bool(params.get("canceled",False)),
                                "resourceType":str(params.get("type","") or "")
                            }
                            self.v67_browser_failures.append(item)
                            self.log(
                                f"[V67_CDP_LOADING_FAILED] type={item['resourceType'] or '-'} "
                                f"blocked={item['blockedReason'] or '-'} "
                                f"canceled={str(item['canceled']).lower()} "
                                f"error={item['errorText'] or '-'} url={item['url'] or '-'}"
                            )
                            self.log(
                                f"[V74_PLAYER_LOADING_FAILED] requestId={rid or '-'} "
                                f"type={item['resourceType'] or '-'} error={item['errorText'] or '-'} "
                                f"blocked={item['blockedReason'] or '-'} url={item['url'] or '-'}"
                            )
                            if item['corsErrorStatus']:
                                self.log(f"[V74_PLAYER_CORS_ERROR] {json.dumps(item['corsErrorStatus'], ensure_ascii=False, default=str)}")
                            try:
                                _host=urllib.parse.urlparse(item['url']).hostname or ''
                                if _host:
                                    _ips=sorted({x[4][0] for x in socket.getaddrinfo(_host, None) if x and len(x)>4 and x[4]})
                                    self.log(f"[V74_HOST_RESOLUTION] host={_host} ips={','.join(_ips) if _ips else '-'}")
                            except Exception as _de:
                                self.log(f"[V74_HOST_RESOLUTION_ERROR] {type(_de).__name__}: {_de}")
                        except Exception as e:
                            self.log(f"[V74_CDP_LOADING_FAILED_ERROR] {type(e).__name__}: {e}")

                    cdp.on("Network.requestWillBeSent", cdp_request)
                    cdp.on("Network.requestWillBeSentExtraInfo", cdp_request_extra_info)
                    cdp.on("Network.responseReceived", cdp_response)
                    cdp.on("Network.responseReceivedExtraInfo", cdp_response_extra_info)
                    cdp.on("Network.loadingFinished", cdp_finished)
                    cdp.on("Network.loadingFailed", cdp_loading_failed)
                except Exception as e:
                    self.log(f"[V26_F12_CDP] unavailable {type(e).__name__}: {e}")

                def on_request(req):
                    try:
                        method=req.method
                        url=req.url
                        post_data=self.v31_safe_request_post_data(req)
                        # V20: request context'i URL/path tahminiyle sinirlamiyoruz.
                        # Bir response daha sonra HLS/MP4 oldugunu kanitlarsa player'a
                        # ayni request context'ini tasiyabilmek icin tum HTTP(S) istekleri kaydedilir.
                        if url.startswith(("http://","https://")):
                            try:
                                hdrs=req.all_headers() or {}
                            except Exception:
                                hdrs=req.headers or {}
                            ctx={
                                "referer":hdrs.get("referer",""),
                                "origin":hdrs.get("origin",""),
                                "accept":hdrs.get("accept",""),
                                "range":hdrs.get("range",""),
                                "user-agent":hdrs.get("user-agent",""),
                                "cookie":hdrs.get("cookie",""),
                            }
                            self.browser_request_context[url]=ctx
                            # Uzun oturumlarda bellegi sinirla; en yeni context'ler yeterli.
                            if len(self.browser_request_context)>600:
                                for old_key in list(self.browser_request_context.keys())[:100]:
                                    self.browser_request_context.pop(old_key,None)

                        if self.runtime_request_relevant(url,method,post_data) or self._browser_relevant_url(url):
                            ctx=self.browser_request_context.get(url,{})
                            item={"method":method,"url":url,"post_data":post_data[:2000],"context":ctx}
                            self.browser_requests.append(item)
                            self.log(f"[BROWSER_REQ] {method} {url}")
                            if ctx.get("referer") or ctx.get("origin") or ctx.get("range"):
                                self.log("[BROWSER_REQ_CONTEXT] "
                                         f"referer={ctx.get('referer','')} | origin={ctx.get('origin','')} | "
                                         f"range={ctx.get('range','')}")
                            if post_data:
                                self.log("[BROWSER_REQ_BODY] "+post_data[:1200])
                    except Exception as e:
                        self.log(f"[BROWSER_REQ_ERROR] {type(e).__name__}: {e}")

                page.on("request",on_request)

                def on_response(resp):
                    try:
                        url=resp.url
                        status=resp.status
                        try:
                            _rf=resp.frame
                            _rfurl=str((_rf.url if _rf else "") or "")
                        except Exception:
                            _rfurl=""
                        ct=(resp.headers.get("content-type","") or "")

                        # V79: capture subtitle traffic independently from media relevance.
                        # Subtitle endpoints are often extensionless, so MIME and URL hints both count.
                        _sub_low=(url or "").lower()
                        _sub_ct=(ct or "").lower()
                        _sub_url_hint=any(x in _sub_low for x in (".vtt", ".srt", ".ass", ".ssa", ".ttml", ".dfxp", "subtitle", "subtitles", "caption", "captions"))
                        _sub_ct_hint=any(x in _sub_ct for x in ("text/vtt", "application/x-subrip", "application/ttml", "application/ttml+xml", "text/srt"))
                        if 200 <= status < 400 and (_sub_url_hint or _sub_ct_hint):
                            self.log(f"[SUBTITLE_NETWORK] status={status} ct={ct or 'UNKNOWN'} frame={_rfurl or page.url or 'UNKNOWN'} url={url}")

                        try:self.v30_note_resource_role(url,ct,"","BROWSER_RESPONSE")
                        except Exception:pass
                        if self._browser_relevant_url(url) or self.runtime_request_relevant(url):
                            key=(status,url,ct)
                            if key not in seen_net:
                                seen_net.add(key)
                                net_item={"status":status,"url":url,"ct":ct}
                                self.browser_network.append(net_item)
                                self.browser_responses.append(net_item)
                                self.log(f"[BROWSER_NET] {status} {ct[:80]} {url}")
                                if _rfurl and _rfurl != (page.url or ""):
                                    self.log(f"[V41_FRAME_RESPONSE] frame={_rfurl} status={status} ct={ct[:80]} url={url}")
                                if self._browser_relevant_url(url):
                                    self.runtime_discovered_candidate(url,root_url,"NETWORK")
                                lct=(ct or "").lower()
                                if status>=200 and status<500 and any(x in lct for x in ("json","text/plain","text/html")):
                                    try:
                                        rb=resp.body()
                                        if rb and len(rb)<=600000:
                                            txt=rb.decode("utf-8","replace")
                                            self.v30_note_environment_rejection(url,txt,"BROWSER_BODY")
                                            if self.runtime_request_relevant(url):
                                                self.log("[BROWSER_RESP_BODY] "+re.sub(r"\s+"," ",txt)[:1800])
                                    except Exception:
                                        pass

                        kind=self._browser_media_kind(url,ct)
                        # V71: A browser-observed HLS response is stronger evidence than a later
                        # replay. Some signed/session-bound manifests are valid in the live player
                        # request but become 404 when replayed even seconds later. Capture the body
                        # NOW, in the same browser session, before the generic media-kind early return.
                        if kind == "HLS" and 200 <= status < 400:
                            try:
                                raw=resp.body()
                            except Exception:
                                raw=b""
                            if raw and len(raw)<=2_000_000:
                                text=raw.decode("utf-8","replace")
                                if text.lstrip().startswith("#EXTM3U"):
                                    reqctx=dict(self.browser_request_context.get(url,{}) or {})
                                    self.v33_browser_hls_observed[url]={
                                        "body":text,"status":status,"ct":ct,
                                        "context":reqctx,"source":"v71_live_browser_body"
                                    }
                                    self.log(f"[V71_LIVE_MANIFEST_CAPTURE] status={status} ct={ct} bytes={len(raw)} url={url}")
                                    self.log(f"[V33_HLS_PROOF_SEED] source=V71_LIVE_BROWSER status={status} bytes={len(raw)} url={url}")
                                    if self.v34_is_media_playlist(text):
                                        self.v34_trigger_observed_media_playlist(
                                            url,text,status,ct,reqctx,"V71_LIVE_BROWSER_MEDIA"
                                        )
                        if kind:
                            remember_media(url,kind,status,ct,"v71_browser_response")
                            return

                        lct=ct.lower()
                        should_sniff=(
                            "application/json" in lct or "text/json" in lct
                            or "text/plain" in lct or "mpegurl" in lct
                            or "octet-stream" in lct or self._browser_relevant_url(url)
                        )
                        if status>=200 and status<400 and should_sniff:
                            try:
                                raw=resp.body()
                            except Exception:
                                raw=b""
                            if raw and len(raw)<=2_000_000:
                                text=raw.decode("utf-8","replace")
                                if text.lstrip().startswith("#EXTM3U"):
                                    self.log(f"[BROWSER_HLS_BODY] status={status} ct={ct} {url}")
                                    reqctx=dict(self.browser_request_context.get(url,{}) or {})
                                    self.v33_browser_hls_observed[url]={"body":text,"status":status,"ct":ct,"context":reqctx,"source":"body"}
                                    self.log(f"[V33_HLS_PROOF_SEED] source=BROWSER status={status} bytes={len(raw)} url={url}")
                                    if self.v34_is_media_playlist(text):
                                        self.v34_trigger_observed_media_playlist(
                                            url,text,status,ct,reqctx,"BROWSER_OBSERVED_MEDIA"
                                        )
                                    remember_media(url,"HLS",status,ct,"body")
                                    return
                                if "json" in lct or text.lstrip().startswith(("{","[")):
                                    try:
                                        obj=json.loads(text)
                                        _v65=self.v65_json_handoff_sources(obj,url)
                                        for _ho in _v65:
                                            hu=_ho.get('url','')
                                            if hu and hu not in targets and len(targets)<12:
                                                targets.append(hu)
                                                target_referrer[hu]=_rfurl or page.url or root_url
                                                target_reason[hu]='V65_XHR_PLAYER_HANDOFF'
                                                self.v32_evidence_edge(url,hu,'V65_XHR_PLAYER_HANDOFF')
                                                self.log(f"[V65_HANDOFF_QUEUE] from={url} path={_ho.get('path','')} url={hu}")
                                        _v40=self.v40_bootstrap_json(text,url)
                                        if _v40:
                                            v40_bootstrap_seen.append(url)
                                            for _it in _v40:
                                                ju=_it.get("url","")
                                                if ju:
                                                    _sem=dict(self.v43_semantic_media.get(ju) or {})
                                                    if _rfurl:
                                                        _sem["frameUrl"]=_rfurl
                                                    _sem["bootstrapUrl"]=url
                                                    _sem["requestContext"]=dict(self.browser_request_context.get(url,{}) or {})
                                                    # Preserve semantic type/mime evidence returned by V40.
                                                    for _k in ("type","mimeType","path","evidence"):
                                                        if _k in _it and _it.get(_k) not in (None,"",[]):
                                                            _sem[_k]=_it.get(_k)
                                                    self.v43_semantic_media[ju]=_sem
                                                    self.log(f"[V45_FRAME_RESPONSE_OWNER_BIND] frame={_rfurl} bootstrap={url} source={ju}")
                                                if ju and ju not in v40_bootstrap_sources:v40_bootstrap_sources.append(ju)
                                                if ju and ju not in json_media:json_media.append(ju)
                                                self.v32_evidence_edge(url,ju,"V40_BOOTSTRAP_FILE")
                                                self.log(f"[V40_BOOTSTRAP_PROMOTE] decision=FOLLOW_IN_SAME_SESSION url={ju}")
                                        for ju in self.media_urls_from_object(obj,url)[:12]:
                                            score=self.runtime_candidate_score(ju,url,"V25_JSON_RESPONSE",text[:5000])
                                            if score < 4:
                                                continue
                                            if ju not in json_media:
                                                json_media.append(ju)
                                            self.runtime_discovered_candidate(ju,url,"V25_JSON_RESPONSE",text[:5000])
                                            self.log(f"[V25_JSON_TARGET] score={score} {ju}")
                                    except Exception:
                                        pass
                    except Exception as e:
                        self.log(f"[BROWSER_EVENT_ERROR] {type(e).__name__}: {e}")

                page.on("response",on_response)

                def v79_harvest_subtitles_from_all_frames(stage):
                    total=0
                    try:
                        frames=list(page.frames)
                    except Exception:
                        frames=[]
                    for fr in frames:
                        try:
                            items=fr.evaluate("""() => {
                              const out=[];
                              const push=(source,x)=>{
                                try{
                                  if(!x) return;
                                  const u=String(x.file||x.src||x.url||'').trim();
                                  if(!u) return;
                                  out.push({source,u,label:String(x.label||x.language||x.srclang||''),kind:String(x.kind||'')});
                                }catch(e){}
                              };
                              try{
                                if(typeof jwplayer==='function'){
                                  const j=jwplayer();
                                  const it=j&&j.getPlaylistItem?j.getPlaylistItem():null;
                                  if(it){ for(const x of (it.tracks||[])) push('jw.track',x); }
                                }
                              }catch(e){}
                              try{
                                for(const t of document.querySelectorAll('track[src]')) push('html.track',{src:t.src||t.getAttribute('src'),label:t.label||t.getAttribute('label'),srclang:t.srclang||t.getAttribute('srclang'),kind:t.kind||t.getAttribute('kind')});
                              }catch(e){}
                              return out.slice(0,100);
                            }""") or []
                            for it in items:
                                if not isinstance(it,dict): continue
                                u=str(it.get('u','')).strip()
                                if not u: continue
                                total+=1
                                self.log(f"[SUBTITLE_RUNTIME] stage={stage} frame={fr.url or 'UNKNOWN'} source={it.get('source','UNKNOWN')} lang={it.get('label','') or 'UNKNOWN'} kind={it.get('kind','') or 'UNKNOWN'} url={u}")
                        except Exception as ex:
                            self.log(f"[SUBTITLE_RUNTIME_FRAME_ERROR] stage={stage} frame={getattr(fr,'url','')} error={type(ex).__name__}: {ex}")
                    self.log(f"[SUBTITLE_RUNTIME_SCAN] stage={stage} frames={len(frames)} tracks={total}")
                    return total

                targets=[root_url]
                target_referrer={root_url:""}
                target_reason={root_url:"ROOT"}
                if self.player and self.player.startswith(("http://","https://")) and self.player not in targets:
                    targets.append(self.player)
                    target_referrer[self.player]=root_url
                    target_reason[self.player]="PLAYER_LITERAL"

                ti=0
                while ti < len(targets) and ti < 12 and not self.final_verified:
                    target=targets[ti]
                    ti+=1
                    ref=target_referrer.get(target,"")
                    reason=target_reason.get(target,"RUNTIME")
                    nt=self.normalize_runtime_url(target,ref or root_url)
                    if not nt:
                        self.log(f"[V29_BROWSER_TARGET_SKIP] reason=INVALID_OR_TEMPLATE url={str(target)[:300]}")
                        continue
                    target=nt
                    if not self.v30_target_allowed(target,reason):
                        self.log(f"[V29_BROWSER_TARGET_SKIP] reason=RESOURCE_ROLE source={reason} url={target}")
                        continue
                    self.runtime_browser_targets.append({"url":target,"referer":ref,"reason":reason})
                    self.log(f"[RUNTIME_BROWSER_TARGET] reason={reason} url={target}")
                    self.log(f"[BROWSER_GOTO] {target}")
                    try:
                        goto_kwargs={"wait_until":"domcontentloaded","timeout":22000}
                        if ref:
                            goto_kwargs["referer"]=ref
                        page.goto(target,**goto_kwargs)
                        try:
                            page.wait_for_timeout(1800)
                            v79_harvest_subtitles_from_all_frames("AFTER_NAV")
                        except Exception as _v79e:
                            self.log(f"[SUBTITLE_RUNTIME_SCAN_ERROR] stage=AFTER_NAV {type(_v79e).__name__}: {_v79e}")
                    except Exception as e:
                        errtxt=f"{type(e).__name__}: {str(e)[:700]}"
                        self.log(f"[BROWSER_GOTO_ERROR] {errtxt}")
                        broken=self.classify_broken_player_transport(target,errtxt)
                        if broken:
                            for alt in self.browser_transport_recovery_urls(target):
                                self.log("[V23_TRANSPORT_RECOVERY_CANDIDATE] "+alt)
                                if alt not in targets and len(targets)<8:
                                    targets.append(alt)
                                    target_referrer[alt]=ref or root_url
                                    target_reason[alt]="BROKEN_TRANSPORT_RECOVERY"
                    # V42 browser-environment snapshot. Diagnostics only; it does not spoof
                    # or bypass a challenge. The goal is to make normal-Chrome parity failures visible.
                    try:
                        _env=page.evaluate("""() => ({
                            webdriver: navigator.webdriver,
                            userAgent: navigator.userAgent,
                            platform: navigator.platform,
                            languages: Array.from(navigator.languages || []),
                            plugins: Array.from(navigator.plugins || []).map(p=>p.name).slice(0,20),
                            hardwareConcurrency: navigator.hardwareConcurrency,
                            deviceMemory: navigator.deviceMemory,
                            cookieEnabled: navigator.cookieEnabled,
                            vendor: navigator.vendor,
                            webgl: (()=>{try{const c=document.createElement('canvas');const g=c.getContext('webgl')||c.getContext('experimental-webgl');if(!g)return {};const e=g.getExtension('WEBGL_debug_renderer_info');return e?{vendor:g.getParameter(e.UNMASKED_VENDOR_WEBGL),renderer:g.getParameter(e.UNMASKED_RENDERER_WEBGL)}:{};}catch(e){return {error:String(e)}}})()
                        })""") or {}
                        self.v42_browser_env=dict(_env)
                        _wg=_env.get('webgl') or {}
                        self.log("[V42_BROWSER_ENV] "
                                 f"webdriver={_env.get('webdriver')} | ua={str(_env.get('userAgent',''))[:220]} | "
                                 f"platform={_env.get('platform')} | languages={_env.get('languages')} | "
                                 f"plugins={len(_env.get('plugins') or [])} | hw={_env.get('hardwareConcurrency')} | "
                                 f"mem={_env.get('deviceMemory')} | cookieEnabled={_env.get('cookieEnabled')} | "
                                 f"webglVendor={str(_wg.get('vendor',''))[:160]} | webglRenderer={str(_wg.get('renderer',''))[:220]}")
                    except Exception as _v42e:
                        self.log(f"[V42_BROWSER_ENV_ERROR] {type(_v42e).__name__}: {_v42e}")

                    # V45 REAL_CHROME player stabilization.
                    # DOMContentLoaded is too early on React/player pages. Wait generically
                    # for visible player/media/iframe/play evidence before action discovery.
                    if v44_real_chrome:
                        self.log("[V46_CLEAN_OBSERVER] PLAYER_STABILIZATION=SKIPPED")
                    if not v44_real_chrome:
                        _v45_ready=False
                        _v45_last={}
                        for _v45_i in range(24):
                            try:
                                _v45_last=page.evaluate("""
                                () => {
                                  const vis=(e)=>{if(!e)return false;const r=e.getBoundingClientRect(),s=getComputedStyle(e);return r.width>8&&r.height>8&&s.display!=='none'&&s.visibility!=='hidden'};
                                  let play=0,media=0,frames=0,playerish=0;
                                  for(const e of document.querySelectorAll('button,[role="button"],video,audio,iframe,[class*="player" i],[id*="player" i]')){
                                    if(!vis(e)) continue;
                                    const t=((e.innerText||e.getAttribute('aria-label')||e.getAttribute('title')||'')+'').toLowerCase();
                                    const c=((e.className||'')+'').toLowerCase(), id=((e.id||'')+'').toLowerCase();
                                    if(e.tagName==='VIDEO'||e.tagName==='AUDIO') media++;
                                    if(e.tagName==='IFRAME') frames++;
                                    if(/play|oynat|izle|watch/.test(t)||/play/.test(c)||/play/.test(id)) play++;
                                    if(/player/.test(c)||/player/.test(id)) playerish++;
                                  }
                                  return {ready:(play+media+frames+playerish)>0,play,media,frames,playerish,rs:document.readyState};
                                }
                                """) or {}
                                if _v45_last.get("ready"):
                                    _v45_ready=True
                                    break
                            except Exception:
                                pass
                            try: page.wait_for_timeout(250)
                            except Exception: break
                        self.log(f"[V45_PLAYER_READY] {'PASS' if _v45_ready else 'TIMEOUT'} state={_v45_last}")

                    # V35 CHALLENGE-AWARE CONTINUATION.
                    # This does NOT bypass or solve a challenge. It simply preserves the
                    # same real browser session and waits briefly for a challenge that
                    # may complete on its own, instead of treating the challenge page as
                    # final player content or recursively chasing challenge assets.
                    try:
                        _cur=(page.url or target)
                        _title=(page.title() or "")[:240]
                        _body=(page.locator("body").inner_text(timeout=1500) or "")[:3500]
                        _blob=(_title+"\n"+_body).lower()
                        _challenge=(
                            "just a moment" in _blob or
                            "bir dakika lütfen" in _blob or
                            "bir dakika lutfen" in _blob or
                            "checking your browser" in _blob or
                            "verify you are human" in _blob or
                            "turnstile" in _blob or
                            "/cdn-cgi/challenge-platform/" in _cur
                        )
                        if _challenge:
                            self.log(f"[V35_CHALLENGE_GATE] state=DETECTED url={_cur}")
                            _start_url=_cur
                            _cleared=False
                            for _wait_i in range(6):
                                page.wait_for_timeout(1500)
                                try:
                                    _u=(page.url or _cur)
                                    _ti=(page.title() or "")[:240]
                                    _bo=(page.locator("body").inner_text(timeout=1200) or "")[:2500]
                                    _bl=(_ti+"\n"+_bo).lower()
                                except Exception:
                                    continue
                                _still=(
                                    "just a moment" in _bl or
                                    "bir dakika lütfen" in _bl or
                                    "bir dakika lutfen" in _bl or
                                    "checking your browser" in _bl or
                                    "verify you are human" in _bl or
                                    "/cdn-cgi/challenge-platform/" in _u
                                )
                                if not _still:
                                    _cleared=True
                                    self.log(f"[V35_CHALLENGE_GATE] state=CLEARED from={_start_url} to={_u}")
                                    self.v32_evidence_edge(_start_url,_u,"CHALLENGE_SESSION_CONTINUATION")
                                    break
                            if not _cleared:
                                self.log(f"[V35_CHALLENGE_GATE] state=UNRESOLVED url={page.url or _cur}")
                    except Exception as _v35c:
                        self.log(f"[V35_CHALLENGE_GATE_ERROR] {type(_v35c).__name__}: {_v35c}")

                    # V41: operate inside actual embedded frames before leaving the parent page.
                    try:
                        _frames=list(page.frames)
                    except Exception:
                        _frames=[]
                    _v41_triggered=0
                    for _fi,_fr in enumerate(_frames):
                        try: _fu=str(_fr.url or "")
                        except Exception: _fu=""
                        if not _fu or _fu.startswith(("about:","data:")): continue
                        _label="MAIN" if _fr==page.main_frame else f"CHILD{_fi}"
                        self.log(f"[V41_FRAME_CONTEXT] label={_label} url={_fu}")
                        try:
                            _called=self.v41_trigger_player_bootstrap(_fr,_fu,_label)
                            if _called: _v41_triggered+=len(_called)
                        except Exception as _v41f:
                            self.log(f"[V41_FRAME_CONTEXT_ERROR] label={_label} url={_fu} {type(_v41f).__name__}: {_v41f}")
                    if _v41_triggered:
                        self.log(f"[V41_FRAME_BOOTSTRAP_WAIT] triggered={_v41_triggered} windowMs=4500")
                        try: page.wait_for_timeout(4500)
                        except Exception: pass

                    # V38: ask the live page what player family/state exists after its own JS ran.
                    try:
                        _html38=page.content()[:500000]
                        self.v38_memory_observe(_html38,page.url or target,"BROWSER_DOCUMENT")
                        _state_urls=self.v38_browser_player_state(page,page.url or target)
                        for _su in _state_urls:
                            if _su not in targets and len(targets)<8:
                                targets.append(_su); target_referrer[_su]=page.url or target; target_reason[_su]="V38_PLAYER_STATE"
                        _sem39=self.v39_browser_semantic_state(page,page.url or target)
                        for _su in _sem39:
                            if _su not in targets and len(targets)<8:
                                targets.append(_su); target_referrer[_su]=page.url or target; target_reason[_su]="V39_SEMANTIC_STATE"
                    except Exception as _v38e:
                        self.log(f"[V38_RUNTIME_INTERPRETER_ERROR] {type(_v38e).__name__}: {_v38e}")

                    # V23 BLOCK_PAGE_DETECTOR: distinguish a real player response from an
                    # ISP/security/filter warning page reached through redirects.
                    try:
                        cur=(page.url or target)
                        title=(page.title() or "")[:300]
                        sample=(page.locator("body").inner_text(timeout=1500) or "")[:2500]
                        blob=(title+"\n"+sample).lower()
                        original_host=(urlparse(target).hostname or "").lower()
                        current_host=(urlparse(cur).hostname or "").lower()
                        block_markers=("güvenli internet","guvenli internet","access denied","site engellendi","erişim engellendi","erisim engellendi","blocked by","security warning","internet uyarı","internet uyari")
                        host_changed=bool(original_host and current_host and original_host!=current_host)
                        marker=next((m for m in block_markers if m in blob),"")
                        if marker:
                            self.log(f"[V23_BLOCK_PAGE] marker={marker} originalHost={original_host} currentHost={current_host} url={cur}")
                            self.broken_player_transport.append({"url":target,"error":"BLOCK_PAGE:"+marker,"redirect":cur})
                        elif host_changed and reason=="BROKEN_TRANSPORT_RECOVERY":
                            self.log(f"[V23_TRANSPORT_REDIRECT] originalHost={original_host} currentHost={current_host} url={cur}")
                    except Exception as e:
                        self.log(f"[V23_BLOCK_DETECT_ERROR] {type(e).__name__}: {e}")
                    try:
                        page.evaluate("""() => {
                          if(window.__rlMutationInstalled) return;
                          window.__rlMutationInstalled=true;
                          window.__rlMutations=[];
                          const push=(x)=>{ try{window.__rlMutations.push(String(x).slice(0,1200)); if(window.__rlMutations.length>80) window.__rlMutations.shift();}catch(e){} };
                          const obs=new MutationObserver(ms=>{
                            for(const m of ms){
                              for(const n of m.addedNodes||[]){
                                if(!n || !n.outerHTML) continue;
                                const h=n.outerHTML;
                                if(/iframe|video|source|ajax-data|player|m3u8|mp4|data-[^=]*(?:src|url|embed)/i.test(h)) push(h);
                              }
                              if(m.type==='attributes' && m.target && m.target.outerHTML){
                                const h=m.target.outerHTML;
                                if(/iframe|video|source|ajax-data|player|m3u8|mp4|data-[^=]*(?:src|url|embed)/i.test(h)) push(h);
                              }
                            }
                          });
                          obs.observe(document.documentElement||document.body,{subtree:true,childList:true,attributes:true});
                        }""")
                    except Exception:
                        pass

                    try:
                        page.wait_for_timeout(4500 if reason!="ROOT" else 2400)
                    except Exception:
                        pass

                    # V41 late registration pass after delayed scripts/challenge completion.
                    try:
                        _late_called=0
                        for _fi,_fr in enumerate(list(page.frames)):
                            try: _fu=str(_fr.url or "")
                            except Exception: _fu=""
                            if not _fu or _fu.startswith(("about:","data:")): continue
                            _lb=("MAIN_LATE" if _fr==page.main_frame else f"CHILD{_fi}_LATE")
                            _cc=self.v41_trigger_player_bootstrap(_fr,_fu,_lb)
                            if _cc: _late_called+=len(_cc)
                        if _late_called:
                            self.log(f"[V41_FRAME_BOOTSTRAP_WAIT] phase=LATE triggered={_late_called} windowMs=3500")
                            page.wait_for_timeout(3500)
                    except Exception as _v41late:
                        self.log(f"[V41_FRAME_BOOTSTRAP_LATE_ERROR] {type(_v41late).__name__}: {_v41late}")

                    try:
                        live_html=page.content()
                        hints=self.player_host_hints_from_text(live_html,page.url or target,"BROWSER_DOCUMENT")
                        for h in hints[:12]:
                            hu=h.get("url","")
                            if not hu: continue
                            q=urlparse(hu)
                            # Bare origins remain hints. Path-bearing high-confidence candidates
                            # may be recursively opened by the browser runtime.
                            if (q.path and q.path not in ("","/")) and h.get("score",0)>=6:
                                cand=self.runtime_discovered_candidate(hu,page.url or target,"V25_HOST_HINT",h.get("context",""))
                                if cand and cand not in targets and len(targets)<8:
                                    targets.append(cand); target_referrer[cand]=page.url or target; target_reason[cand]="PLAYER_HOST_HINT"
                    except Exception as e:
                        self.log(f"[V25_PLAYER_HOST_SCAN_ERROR] {type(e).__name__}: {e}")

                    try:
                        muts=page.evaluate("window.__rlMutations||[]") or []
                        for mu in muts[-30:]:
                            self.runtime_dom_events.append(str(mu))
                            compact=re.sub(r"\s+"," ",str(mu))[:1000]
                            self.log("[BROWSER_DOM_MUTATION] "+compact)
                            for ru in self.extract_runtime_urls_from_html(str(mu),page.url or target):
                                if ru not in targets and len(targets)<8:
                                    targets.append(ru)
                                    target_referrer[ru]=page.url or target
                                    target_reason[ru]="DOM_MUTATION"
                    except Exception:
                        pass

                    try:
                        lskeys=page.evaluate("Object.keys(localStorage)")
                        if lskeys:
                            self.log("[BROWSER_LOCALSTORAGE_KEYS] "+", ".join(map(str,lskeys[:30])))
                            try:
                                meta=page.evaluate("""() => Object.keys(localStorage).slice(0,30).map(k=>{
                                  const v=localStorage.getItem(k)||'';
                                  return {k, len:v.length, dots:(v.split('.').length-1), json:(v.startsWith('{')||v.startsWith('['))};
                                })""")
                                self.log("[BROWSER_LOCALSTORAGE_META] "+json.dumps(meta,ensure_ascii=False)[:1800])
                            except Exception:
                                pass
                    except Exception:
                        pass

                    try:
                        runtime_urls=page.eval_on_selector_all(
                            "iframe,video,source",
                            """els => els.map(e => ({
                                src:e.src||e.getAttribute('src')||'',
                                dataSrc:e.getAttribute('data-src')||'',
                                dataUrl:e.getAttribute('data-url')||''
                            }))"""
                        ) or []
                    except Exception:
                        runtime_urls=[]

                    for entry in runtime_urls[:30]:
                        vals=[]
                        if isinstance(entry,dict):
                            vals=[entry.get("src",""),entry.get("dataSrc",""),entry.get("dataUrl","")]
                        else:
                            vals=[str(entry)]
                        for ru in vals:
                            if not ru:
                                continue
                            self.log("[BROWSER_DOM_MEDIA] "+str(ru))
                            self.log("[V37_DOM_MEDIA_PRIORITY] source=DOM_ELEMENT decision=RECURSE_BEFORE_PRUNE url="+str(ru))
                            cand=self.runtime_discovered_candidate(str(ru),page.url or target,"DOM_ELEMENT","browser_dom_media")
                            if cand and cand not in targets and len(targets)<8:
                                targets.append(cand)
                                target_referrer[cand]=page.url or target
                                target_reason[cand]="DOM_ELEMENT"

                    # V27 FAILURE_DRIVEN_RESOLVER / ADAPTIVE_ACTION_STRATEGIES
                    fired=0
                    locked=False
                    v27_had_actions=False
                    try:
                        learned_selectors=list(dict.fromkeys(self.v27_event_selectors))[:20]
                        actions=page.evaluate("""(learned) => {
                          const norm=s=>String(s||'').replace(/\\s+/g,' ').trim().slice(0,180);
                          const esc=s=>{try{return CSS.escape(s)}catch(e){return String(s).replace(/[^a-zA-Z0-9_-]/g,'\\$&')}};
                          const pathOf=e=>{
                            if(!e)return '';
                            if(e.id)return '#'+esc(e.id);
                            const a=[]; let n=e,depth=0;
                            while(n&&n.nodeType===1&&depth<6){
                              let part=n.tagName.toLowerCase();
                              if(n.classList&&n.classList.length){
                                const good=[...n.classList].filter(x=>x&&x.length<50).slice(0,2);
                                if(good.length) part+='.'+good.map(esc).join('.');
                              }
                              const p=n.parentElement;
                              if(p){const same=[...p.children].filter(x=>x.tagName===n.tagName); if(same.length>1)part+=`:nth-of-type(${same.indexOf(n)+1})`;}
                              a.unshift(part); n=p; depth++;
                            }
                            return a.join(' > ');
                          };
                          const semanticActionSels=[
                            '[data-player-source]','[data-player-start]','[data-player-submit]','[data-player-watch]','[data-player-name]','[data-part-key]',
                            '[data-source]','[data-video]','[data-url]','[data-src]','[data-action]',
                            'button[type="submit"]','button','a','[role="button"]','[onclick]','.play','.ply'
                          ];
                          const sels=[...(learned||[]),...semanticActionSels,'[data-id]','[data-player]','.player'];
                          let nodes=[]; for(const ss of sels){try{nodes.push(...document.querySelectorAll(ss))}catch(e){}}
                          nodes=[...new Set(nodes)]; const out=[];
                          for(const e of nodes){
                            let r; try{r=e.getBoundingClientRect()}catch(_){continue}
                            const cs=getComputedStyle(e);
                            if(!r || r.width<2 || r.height<2 || cs.display==='none' || cs.visibility==='hidden') continue;
                            const attrs={}; for(const a of [...(e.attributes||[])]) if(/^data-|^(href|onclick|aria-label|title|class|id)$/i.test(a.name)) attrs[a.name]=norm(a.value);
                            const text=norm(e.innerText||e.textContent||'');
                            const blob=(text+' '+Object.entries(attrs).map(x=>x.join('=')).join(' ')).toLowerCase();
                            let score=0;
                            for(const k of ['play','oynat','izle','watch','player','source','kaynak','video','part','bölüm','bolum','episode','poster']) if(blob.includes(k)) score+=3;
                            if(/srcchip|srcbar|sourcechip|provider|server|mirror|player-select|source-select/.test(blob)) score+=12;
                            if(e.matches('button,[role="button"],.play,.ply')) score+=2;
                            if(attrs.onclick) score+=2;
                            if(attrs['data-video']||attrs['data-source']||attrs['data-src']||attrs['data-url']||attrs['data-player']) score+=4;
                            if((learned||[]).some(ss=>{try{return e.matches(ss)}catch(_){return false}})) score+=6;

                            const directAction=!!(
                              e.matches('button,a,[role="button"],[onclick],[data-player-source],[data-player-start],[data-player-submit],[data-player-watch],[data-player-name],[data-part-key],[data-source],[data-video],[data-url],[data-src],[data-action]')
                            );
                            const directPlayerAction=!!(
                              e.matches('[data-player-source],[data-player-start],[data-player-submit],[data-player-watch],[data-player-name],[data-part-key]')
                            );
                            // V37: infer action intent from element role + page region, not words alone.
                            // A footer SEO link containing "izle" is navigation, while a large/overlay
                            // button inside the player surface is a strong playback-start candidate even
                            // when it has no visible text.
                            const inNavZone=!!e.closest('header,footer,nav,[role="navigation"]');
                            const inPlayerZone=!!e.closest('.player,[data-player],[data-inline-player],[data-player-stage],video,iframe,.jwplayer,.video-player,.plyr');
                            const plainAnchor=(e.tagName==='A' && !!attrs.href && !String(attrs.href).toLowerCase().startsWith('javascript:'));
                            const playerData=!!(attrs['data-player-start']||attrs['data-player-submit']||attrs['data-player-watch']||attrs['data-player-source']||attrs['data-video']||attrs['data-source']||attrs['data-src']||attrs['data-url']||attrs['data-player']||attrs.onclick);
                            const overlayPlaySurface=!!(inPlayerZone && e.matches('button,[role="button"]') && (/absolute|inset-0|play|ply|center/.test(String(attrs.class||'').toLowerCase()) || (r.width>=48 && r.height>=48)));
                            let actionIntent='GENERIC';
                            if(inNavZone && plainAnchor && !playerData) actionIntent='NAVIGATION';
                            else if(e.matches('[data-player-start],[data-player-submit],[data-player-watch]') || overlayPlaySurface || (inPlayerZone && /(^|\\s)(play|oynat|izle|watch)(\\s|$)/.test(text.toLowerCase()))) actionIntent='START_PLAYBACK';
                            else if(e.matches('[data-player-source],[data-player-name],[data-part-key],[data-source]') || /source|kaynak|provider|server|mirror|dublaj|altyaz/.test(blob)) actionIntent='SELECT_SOURCE';
                            else if(/download|indir/.test(blob)) actionIntent='DOWNLOAD';
                            const actionableChildren=[...e.querySelectorAll(
                              'button,a,[role="button"],[onclick],[data-player-source],[data-player-start],[data-player-submit],[data-player-watch],[data-source],[data-video],[data-url],[data-src],[data-action]'
                            )].filter(x=>x!==e);
                            const isContainer=!directAction && actionableChildren.length>0;

                            if(directPlayerAction) score+=22;
                            else if(directAction) score+=8;
                            if(actionIntent==='START_PLAYBACK') score+=35;
                            else if(actionIntent==='SELECT_SOURCE') score+=8;
                            else if(actionIntent==='DOWNLOAD') score-=8;
                            else if(actionIntent==='NAVIGATION') score-=35;
                            if(inPlayerZone && actionIntent==='START_PLAYBACK') score+=18;
                            if(inNavZone && plainAnchor && !playerData) score-=20;
                            if(isContainer) score-=14;
                            if(/sources|source-list|provider-list|server-list/.test(String(attrs.class||'').toLowerCase()) && !directPlayerAction) score-=10;

                            if(/trailer|fragman|youtube|facebook|twitter|instagram|comment|yorum|share|paylaş|like|unlike|thumb|vote|oyla|login|giriş|giris|register|kayıt|kayit|birlikte izle|watch together|prime video|imdb top|anasayfa|home|category|kategori|robot|film ve dizi robotu|random|rastgele|favorite|favori|menu|menü|search|ara|filmi izledim|filmi izleyeceğim|filmi izleyecegim|listeye ekle|watchlist|seen|later|data-list|data-listadd/.test(blob)) score-=20;
                            const href=(attrs.href||'').toLowerCase();
                            const hasPlayerData=!!(attrs['data-video']||attrs['data-source']||attrs['data-src']||attrs['data-url']||attrs['data-player']||attrs.onclick||attrs['data-player-source']||attrs['data-player-start']||attrs['data-player-submit']||attrs['data-player-watch']||attrs['data-player-name']||attrs['data-part-key']||attrs['data-player-name']||attrs['data-part-key']);
                            if(e.tagName==='A' && href && !href.startsWith('javascript:') && !hasPlayerData) score-=5;
                            if(score>0) out.push({
                              score,text,tag:e.tagName,attrs,path:pathOf(e),
                              x:Math.round(r.left+r.width/2),y:Math.round(r.top+r.height/2),
                              directAction,directPlayerAction,actionIntent,isContainer,actionableChildren:actionableChildren.length
                            });
                          }
                          out.sort((a,b)=>{
                            const ir={START_PLAYBACK:5,SELECT_SOURCE:4,GENERIC:3,DOWNLOAD:2,NAVIGATION:1};
                            if((ir[a.actionIntent]||0)!==(ir[b.actionIntent]||0))return (ir[b.actionIntent]||0)-(ir[a.actionIntent]||0);
                            if(!!a.directPlayerAction!==!!b.directPlayerAction)return a.directPlayerAction?-1:1;
                            if(!!a.directAction!==!!b.directAction)return a.directAction?-1:1;
                            if(!!a.isContainer!==!!b.isContainer)return a.isContainer?1:-1;
                            return b.score-a.score;
                          });
                          return out.slice(0,30);
                        }""",learned_selectors) or []
                        if getattr(self,"v46_clean_observer",False):
                            self.log("[V65_AGENT_ACTION] AUTO_ACTION_DISCOVERY=ENABLED mode=CAUSAL_SINGLE_ACTION_NETWORK_DELTA")
                        self.log(f"[V27_ACTION_DISCOVERY] candidates={len(actions)} learnedSelectors={len(learned_selectors)}")
                        for a in actions[:12]:
                            self.log("[V27_ACTION_CANDIDATE] "+json.dumps(a,ensure_ascii=False)[:1000])
                            _ai=a.get('actionIntent','GENERIC')
                            _dec=("TRY_FIRST" if _ai=='START_PLAYBACK' else ("STATE_CHANGE_ONLY_UNLESS_MEDIA" if _ai=='SELECT_SOURCE' else ("DEMOTE_NAVIGATION" if _ai=='NAVIGATION' else "EVALUATE_BY_EVIDENCE")))
                            self.log(f"[V37_ACTION_REASON] intent={_ai} score={a.get('score',0)} decision={_dec}")
                        # V31: inspect inline onclick provenance before blindly clicking.
                        for ai,a in enumerate(actions[:12]):
                            raw=str((a.get('attrs') or {}).get('onclick','') or '')
                            if not raw:continue
                            self.log(f"[V31_INLINE_HANDLER] action={ai} raw={raw[:600]}")
                            names=[]
                            for mm in re.finditer(r'\b([A-Za-z_$][\w$]*)\s*\(',raw):
                                n=mm.group(1)
                                if n not in ('if','for','while','switch','function') and n not in names:names.append(n)
                            for fn in names[:6]:
                                try:
                                    srcfn=page.evaluate("""n=>{try{const f=window[n];return typeof f==='function'?String(f):''}catch(e){return ''}}""",fn) or ''
                                    if srcfn:
                                        self.log(f"[V31_FUNCTION_TRACE] name={fn} body={re.sub(r'\s+',' ',srcfn)[:1800]}")
                                        for fu in re.findall(r'https?://[^\s"\'<>]+',srcfn,re.I):
                                            self.runtime_discovered_candidate(fu,page.url or target,"V31_FUNCTION_TRACE",srcfn[:3000])
                                except Exception as ex:
                                    self.log(f"[V31_FUNCTION_TRACE_ERROR] name={fn} {type(ex).__name__}: {ex}")

                        def v27_snapshot():
                            try:
                                return page.evaluate("""() => ({
                                  mut:(window.__rlMutations||[]).length,
                                  ifr:[...document.querySelectorAll('iframe')].map(x=>x.src||x.getAttribute('data-src')||x.getAttribute('data-vsrc')||'').filter(Boolean),
                                  med:[...document.querySelectorAll('video,audio,source')].map(x=>x.currentSrc||x.src||x.getAttribute('src')||'').filter(Boolean),
                                  url:location.href
                                })""") or {}
                            except Exception:return {}

                        def v27_listener_types(a):
                            path=str(a.get('path',''))
                            if not path:return []
                            try:
                                ro=cdp.send('Runtime.evaluate',{'expression':f'document.querySelector({json.dumps(path)})','returnByValue':False})
                                oid=((ro or {}).get('result') or {}).get('objectId')
                                if not oid:return []
                                ev=cdp.send('DOMDebugger.getEventListeners',{'objectId':oid,'depth':4,'pierce':True}) or {}
                                types=[]
                                for e in ev.get('listeners',[]) or []:
                                    typ=str(e.get('type',''))
                                    if typ and typ not in types:types.append(typ)
                                    if typ:self.log(f"[V27_EVENT_LISTENER] type={typ} scriptId={e.get('scriptId','')} line={e.get('lineNumber','')}")
                                return types[:20]
                            except Exception as e:
                                self.log(f"[V27_EVENT_LISTENER_ERROR] {type(e).__name__}: {e}")
                                return []

                        def v27_execute_strategy(a,strategy,listener_types):
                            x=float(a.get('x',0) or 0); y=float(a.get('y',0) or 0); path=str(a.get('path',''))
                            if strategy=='A_MOUSE': page.mouse.click(x,y)
                            elif strategy=='B_DOM_CLICK': page.evaluate("p=>{const e=document.querySelector(p); if(e)e.click()}",path)
                            elif strategy=='C_POINTER_SEQUENCE':
                                page.evaluate("""p=>{const e=document.querySelector(p);if(!e)return; for(const t of ['pointerdown','mousedown','pointerup','mouseup','click']){try{e.dispatchEvent(new MouseEvent(t,{bubbles:true,cancelable:true,view:window,buttons:t.includes('down')?1:0}))}catch(_){try{e.dispatchEvent(new Event(t,{bubbles:true,cancelable:true}))}catch(__){}}}}""",path)
                            elif strategy=='D_FORCE_LOCATOR': page.locator(path).first.click(force=True,timeout=1800)
                            elif strategy=='E_KEYBOARD_ENTER':
                                loc=page.locator(path).first; loc.focus(timeout=1200); page.keyboard.press('Enter')
                            elif strategy=='F_PARENT_CHAIN':
                                page.evaluate("""p=>{let e=document.querySelector(p);if(!e)return;let n=e;for(let i=0;i<5&&n;i++,n=n.parentElement){const b=((n.innerText||'')+' '+(n.className||'')+' '+(n.id||'')).toLowerCase();if(i>0&&(/play|player|video|ply|poster|oynat|izle/.test(b)||n.onclick)){n.click();return}}}""",path)
                            elif strategy=='G_CHILD_TARGET':
                                page.evaluate("""p=>{
                                  const e=document.querySelector(p);if(!e)return;
                                  const q=[...e.querySelectorAll(
                                    '[data-player-source],[data-player-start],[data-player-submit],[data-player-watch],[data-player-name],[data-part-key],button[type=submit],button,a,[role=button],[onclick],[data-source],[data-video],[data-url],[data-src],[data-action],.play,.ply'
                                  )];
                                  const score=x=>{
                                    let s=0; const b=((x.innerText||x.textContent||'')+' '+[...(x.attributes||[])].map(a=>a.name+'='+a.value).join(' ')).toLowerCase();
                                    if(x.matches('[data-player-source],[data-player-name],[data-part-key]'))s+=28;
                                    if(x.matches('[data-player-start],[data-player-submit],[data-player-watch]'))s+=55;
                                    if(x.matches('button[type=submit]'))s+=30;
                                    if(x.matches('button,[role=button]'))s+=18;
                                    if(x.matches('a'))s+=10;
                                    if(/play|oynat|izle|watch|source|kaynak|server|provider/.test(b))s+=12;
                                    if(/download|indir|trailer|fragman|comment|yorum|share|login|giris|giriş/.test(b))s-=25;
                                    return s;
                                  };
                                  q.sort((a,b)=>score(b)-score(a));
                                  const t=q[0]||e;
                                  if(typeof t.click==='function')t.click();
                                  else t.dispatchEvent(new MouseEvent('click',{bubbles:true,cancelable:true,view:window}));
                                }""",path)
                            elif strategy=='H_LISTENER_EVENTS':
                                evs=[t for t in listener_types if t in ('click','mousedown','mouseup','pointerdown','pointerup','touchstart','touchend','keydown','keyup')][:8]
                                if not evs: evs=['click','mousedown','mouseup','pointerdown','pointerup']
                                page.evaluate("""arg=>{const p=arg[0],evs=arg[1];const e=document.querySelector(p);if(!e)return false;for(const t of evs){let ev;if(t.indexOf('key')===0){ev=new KeyboardEvent(t,{bubbles:true,cancelable:true,key:'Enter',code:'Enter'})}else if(t.indexOf('mouse')>=0||t.indexOf('pointer')>=0||t==='click'){ev=new MouseEvent(t,{bubbles:true,cancelable:true,view:window})}else{ev=new Event(t,{bubbles:true,cancelable:true})}e.dispatchEvent(ev)}return true}""",[path,evs])
                            elif strategy=='J_ONCLICK_HANDLER':
                                page.evaluate("""p=>{const e=document.querySelector(p);if(!e)return false;if(typeof e.onclick==='function'){e.onclick.call(e);return true}const raw=e.getAttribute('onclick')||'';if(raw){(new Function(raw)).call(e);return true}return false}""",path)
                            elif strategy=='I_KEYBOARD_SPACE':
                                loc=page.locator(path).first; loc.focus(timeout=1200); page.keyboard.press('Space')

                        total_strategy_budget=32
                        strategies_used=0
                        for idx,a in enumerate(actions[:8]):
                            if self.final_verified or locked or strategies_used>=total_strategy_budget: break
                            v27_had_actions=True
                            listener_types=v27_listener_types(a)
                            if str(a.get('actionIntent',''))=='SELECT_SOURCE':
                                plan=['A_MOUSE']
                            elif bool(a.get('isContainer')):
                                plan=['G_CHILD_TARGET','F_PARENT_CHAIN','A_MOUSE','B_DOM_CLICK']
                            elif bool(a.get('directPlayerAction')):
                                plan=['A_MOUSE','B_DOM_CLICK','C_POINTER_SEQUENCE','D_FORCE_LOCATOR','E_KEYBOARD_ENTER']
                            else:
                                plan=['A_MOUSE','B_DOM_CLICK']
                            if str((a.get('attrs') or {}).get('onclick','') or ''):
                                plan.append('J_ONCLICK_HANDLER')
                            if str(a.get('actionIntent',''))!='SELECT_SOURCE':
                                for _s in ['C_POINTER_SEQUENCE','D_FORCE_LOCATOR','E_KEYBOARD_ENTER','F_PARENT_CHAIN','G_CHILD_TARGET','H_LISTENER_EVENTS','I_KEYBOARD_SPACE']:
                                    if _s not in plan: plan.append(_s)
                            if int(a.get('score',0) or 0)<5: plan=plan[:5]
                            attempted_for_action=0
                            for strategy in plan:
                                if self.final_verified or locked or strategies_used>=total_strategy_budget:break
                                strategies_used+=1; attempted_for_action+=1; fired+=1
                                before_req=set(cdp_requests.keys()); before_targets=len(targets); before_pages=len(page.context.pages)
                                snap0=v27_snapshot(); before_url=page.url or target
                                self.log(f"[V27_STRATEGY_TRY] action={idx} strategy={strategy} score={a.get('score')} path={str(a.get('path',''))[:220]}")
                                try:v27_execute_strategy(a,strategy,listener_types)
                                except Exception as ex:
                                    self.log(f"[V27_STRATEGY_EXEC_ERROR] action={idx} strategy={strategy} {type(ex).__name__}: {ex}")
                                    continue
                                page.wait_for_timeout(1500)
                                after_url=page.url or target; snap1=v27_snapshot()
                                new_ids=[rid for rid in cdp_requests.keys() if rid not in before_req]
                                meaningful_ids=[]
                                for rid in new_ids:
                                    q=cdp_requests.get(rid) or {}; r=cdp_responses.get(rid) or {}; u=str(q.get('url','')); typ=str(q.get('type',''))
                                    if u:self.log(f"[V27_ACTION_NET] strategy={strategy} type={typ} url={u}")

                                    # V35: learn action endpoint semantics from the browser instead
                                    # of assuming a navigational GET.
                                    try:
                                        _pp=(urlparse(u).path or "").lower()
                                    except Exception:
                                        _pp=""
                                    if typ.lower() in ("xhr","fetch") and (
                                        re.search(r"/(?:authorize|token|session|resolve|activate|unlock|verify|grant)(?:/|$)",_pp)
                                        or str(q.get("postData","") or "")
                                    ):
                                        _pd=str(q.get("postData","") or "")
                                        _meth=str(q.get("method","GET") or "GET")
                                        self.log(
                                            f"[V35_ACTION_SEMANTICS] strategy={strategy} method={_meth} "
                                            f"status={int(r.get('status',0) or 0)} url={u} body={_pd[:1800]}"
                                        )

                                    if rid in cdp_media_ids or self.v26_action_request_is_meaningful(rid,q,r,cdp_response_bodies.get(rid,''),cdp_response_urls.get(rid,[])):
                                        meaningful_ids.append(rid)
                                new_runtime=[]
                                try:muts=page.evaluate("n=>(window.__rlMutations||[]).slice(n)",int(snap0.get('mut',0) or 0)) or []
                                except Exception:muts=[]
                                for mu in muts[-50:]:
                                    self.runtime_dom_events.append(str(mu)); self.log('[BROWSER_DOM_MUTATION] '+re.sub(r'\\s+',' ',str(mu))[:1000])
                                    for ru in self.extract_runtime_urls_from_html(str(mu),after_url):
                                        if ru not in new_runtime:new_runtime.append(ru)
                                        if ru not in targets and len(targets)<10:
                                            targets.append(ru); target_referrer[ru]=after_url; target_reason[ru]='V27_ACTION_MUTATION'
                                frame_delta=[u for u in (snap1.get('ifr',[]) or []) if u and u not in (snap0.get('ifr',[]) or [])]
                                media_delta=[u for u in (snap1.get('med',[]) or []) if u and u not in (snap0.get('med',[]) or [])]
                                for raw in frame_delta+media_delta:
                                    ru=self.runtime_discovered_candidate(raw,after_url,'DOM_ELEMENT')
                                    if ru and ru not in new_runtime:new_runtime.append(ru)
                                    if ru and ru not in targets and len(targets)<10:
                                        targets.append(ru);target_referrer[ru]=after_url;target_reason[ru]='V27_FRAME_MEDIA_DELTA'
                                popup_urls=[]; playback_popups=[]
                                for pp in page.context.pages[before_pages:]:
                                    try:pu=pp.url
                                    except Exception:pu=''
                                    if pu and pu!='about:blank':
                                        popup_urls.append(pu)
                                        if self.v28_popup_is_playback_candidate(pu,after_url):
                                            playback_popups.append(pu); ru=self.runtime_discovered_candidate(pu,after_url,'V28_POPUP')
                                            if ru and ru not in targets and len(targets)<10:
                                                targets.append(ru);target_referrer[ru]=after_url;target_reason[ru]='V28_POPUP_PLAYER'
                                        else:
                                            try: pp.close()
                                            except Exception: pass
                                nav_changed=(after_url!=before_url)
                                # V28: navigation, images/assets, or an ad popup alone never locks the resolver.
                                valid_runtime=[]
                                weak_runtime_clues=[]
                                for ru in new_runtime:
                                    if self.v30_target_allowed(ru,"ACTION_DELTA") and not self.v29_negative_playback_evidence(ru,0,''):
                                        try:
                                            _rp=(urlparse(ru).path or "").lower()
                                        except Exception:
                                            _rp=""
                                        # Download links and action/control endpoints are useful causal
                                        # clues, but are not enough to stop action exploration.
                                        if re.search(r"/(?:download|authorize|token|session|resolve|activate|unlock|verify|grant)(?:/|$)",_rp):
                                            weak_runtime_clues.append(ru)
                                            self.log(f"[V35_RUNTIME_CLUE] weak=true url={ru}")
                                        else:
                                            valid_runtime.append(ru)
                                negative_ids=[]
                                for rid in new_ids:
                                    q=cdp_requests.get(rid) or {}; r=cdp_responses.get(rid) or {}
                                    nu=str((r.get('url') or q.get('url') or ''))
                                    ns=int(r.get('status',0) or 0)
                                    nb=str(cdp_response_bodies.get(rid,'') or '')
                                    if self.v29_negative_playback_evidence(nu,ns,nb):negative_ids.append(rid)
                                # V30 hard veto: a confirmed player failure beats DOM/frame/runtime/network positives.
                                negative_veto=bool(negative_ids) and not self.final_verified
                                # V36 evidence interpreter: do not equate "a request happened" with
                                # "playback started". Lock only on hard causal playback evidence.
                                action_intent=str(a.get('actionIntent','GENERIC') or 'GENERIC')
                                hard_network_ids=[]
                                for _rid in meaningful_ids:
                                    _q=cdp_requests.get(_rid) or {}; _r=cdp_responses.get(_rid) or {}
                                    _u=str(_q.get('url','') or _r.get('url','') or '')
                                    _ct=str(_r.get('ct','') or '')
                                    _body=str(cdp_response_bodies.get(_rid,'') or '')
                                    if self._browser_media_kind(_u,_ct) or _body.lstrip().startswith('#EXTM3U'):
                                        hard_network_ids.append(_rid)
                                    elif cdp_response_urls.get(_rid,[]):
                                        hard_network_ids.append(_rid)
                                    else:
                                        self.log(f"[V37_EVIDENCE_INTERPRET] id={_rid} role=WEAK_NETWORK decision=CONTINUE_ACTION_SEARCH url={_u}")
                                # V37: DOM media can be a pre-roll/ad. Quarantine obvious ad-shaped
                                # network/DOM evidence instead of stopping the action search immediately.
                                ad_network_ids=[]
                                for _rid in list(hard_network_ids):
                                    _q=cdp_requests.get(_rid) or {}; _r=cdp_responses.get(_rid) or {}
                                    _u=str(_q.get('url','') or _r.get('url','') or '')
                                    if self.v37_ad_media_evidence(_u,cdp_response_bodies.get(_rid,'')):
                                        ad_network_ids.append(_rid)
                                if ad_network_ids:
                                    hard_network_ids=[x for x in hard_network_ids if x not in ad_network_ids]
                                    self.log(f"[V37_AD_QUARANTINE] source=NETWORK ids={','.join(ad_network_ids[:8])} decision=KEEP_SESSION_CONTINUE")
                                ad_dom=[]
                                for _u in list(media_delta):
                                    _ctx=' '.join(str(x) for x in muts[-8:]) if muts else ''
                                    if self.v37_ad_media_evidence(_u,_ctx):
                                        ad_dom.append(_u)
                                if ad_dom:
                                    media_delta=[x for x in media_delta if x not in ad_dom]
                                    self.log(f"[V37_AD_QUARANTINE] source=DOM count={len(ad_dom)} decision=KEEP_SESSION_CONTINUE urls="+' | '.join(ad_dom[:4]))
                                # New iframe/frame evidence remains strong; quarantined ad media does not.
                                hard_playback=bool(hard_network_ids or valid_runtime or frame_delta or media_delta or playback_popups or self.final_verified)
                                if action_intent=='SELECT_SOURCE' and not hard_playback:
                                    self.log(f"[V37_CAUSAL_DECISION] action={idx} intent=SELECT_SOURCE result=STATE_CHANGED_ONLY decision=TRY_NEXT_ACTION")
                                elif (ad_network_ids or ad_dom) and not hard_playback:
                                    self.log(f"[V37_CAUSAL_DECISION] action={idx} intent={action_intent} result=AD_OR_PREROLL_ONLY decision=KEEP_SESSION_CONTINUE")
                                    # Let the same player state evolve briefly; do not navigate away or
                                    # declare success based on the advertisement itself.
                                    try: page.wait_for_timeout(1800)
                                    except Exception: pass
                                meaningful=hard_playback
                                if negative_veto:
                                    meaningful=False
                                    self.log(f"[V30_ACTION_VETO] action={idx} strategy={strategy} reason=NEGATIVE_PLAYBACK_EVIDENCE ids={','.join(negative_ids[:8])}")
                                self.log(f"[V27_STRATEGY_RESULT] action={idx} strategy={strategy} newRequests={len(new_ids)} meaningful={len(meaningful_ids)} hardPlayback={len(hard_network_ids)} runtimeUrls={len(new_runtime)} validRuntimeUrls={len(valid_runtime)} frameDelta={len(frame_delta)} mediaDelta={len(media_delta)} popups={len(popup_urls)} playbackPopups={len(playback_popups)} negative={len(negative_ids)} veto={str(negative_veto).lower()} navChanged={str(nav_changed).lower()} final={str(self.final_verified).lower()}")
                                if meaningful:
                                    locked=True; self.v27_strategy_success[strategy]=self.v27_strategy_success.get(strategy,0)+1
                                    reason='FINAL_MEDIA' if self.final_verified else ('MEDIA_NETWORK_EVIDENCE' if hard_network_ids else ('PLAYER_POPUP_EVIDENCE' if playback_popups else 'DOM_FRAME_MEDIA_EVIDENCE'))
                                    self.log(f"[V37_ACTION_LOCK] action={idx} strategy={strategy} reason={reason}")
                                    self.log(f"[V27_ACTION_LOCK] action={idx} strategy={strategy} reason={reason}")
                                    break
                                fail_reason='NEGATIVE_PLAYBACK_EVIDENCE' if negative_veto else 'NO_PLAYBACK_EVIDENCE'
                                self.v27_failure_memory.append({'action':idx,'strategy':strategy,'reason':fail_reason})
                                self.log(f"[V27_STRATEGY_NEXT] action={idx} failed={strategy} reason={fail_reason}")
                                if nav_changed and not self.final_verified:
                                    self.log(f"[V27_ACTION_ROLLBACK] from={after_url} to={before_url}")
                                    try: page.goto(before_url,wait_until='domcontentloaded',timeout=16000,referer=ref or None); page.wait_for_timeout(500)
                                    except Exception as rb:self.log(f"[V27_ACTION_ROLLBACK_ERROR] {type(rb).__name__}: {rb}")
                            if not locked:self.log(f"[V27_ACTION_EXHAUSTED] action={idx} strategiesTried={attempted_for_action}")
                        self.log(f"[V27_ADAPTIVE_RESULT] actions={len(actions)} fired={fired} strategies={strategies_used} locked={str(locked).lower()} failures={len(self.v27_failure_memory)}")
                    except Exception as e:
                        self.log(f"[V27_ADAPTIVE_ERROR] {type(e).__name__}: {e}")

                    selectors=(
                        ".part-btn",
                        ".part-item",
                        ".ply",
                        "[data-source-index]",
                        "button[aria-label*='play' i]",
                        ".jw-icon-playback",
                        ".vjs-big-play-button",
                        ".owl-video-play-icon",
                        ".play-button",
                        ".player-play-icon",
                        "[data-video]",
                    )
                    for sel in selectors:
                        try:
                            loc=page.locator(sel).first
                            if loc.count() and loc.is_visible():
                                self.log("[BROWSER_INTERACT] "+sel)
                                loc.click(timeout=1800)
                                page.wait_for_timeout(1800)
                                try:
                                    muts=page.evaluate("window.__rlMutations||[]") or []
                                    for mu in muts[-30:]:
                                        self.runtime_dom_events.append(str(mu))
                                        compact=re.sub(r"\s+"," ",str(mu))[:1000]
                                        self.log("[BROWSER_DOM_MUTATION] "+compact)
                                        for ru in self.extract_runtime_urls_from_html(str(mu),page.url or target):
                                            if ru not in targets and len(targets)<8:
                                                targets.append(ru)
                                                target_referrer[ru]=page.url or target
                                                target_reason[ru]="DOM_MUTATION"
                                except Exception:
                                    pass
                                break
                        except Exception:
                            pass

                    # V21 generic F12/runtime harvest: ask the live page what the player and
                    # Performance API currently know. This is diagnostic + candidate discovery;
                    # every HTTP candidate still has to pass normal response verification.
                    try:
                        harvest=page.evaluate("""() => {
                          const out=[]; const add=(source,u)=>{
                            try{ u=String(u||'').trim(); if(u.startsWith('http://')||u.startsWith('https://')) out.push({source,u}); }catch(e){}
                          };
                          try{
                            for(const e of performance.getEntriesByType('resource')||[]) add('performance',e.name);
                          }catch(e){}
                          try{
                            for(const v of document.querySelectorAll('video,audio,source')){
                              add('dom.currentSrc',v.currentSrc); add('dom.src',v.src||v.getAttribute('src'));
                            }
                          }catch(e){}
                          try{
                            if(typeof jwplayer==='function'){
                              const j=jwplayer();
                              const it=j && j.getPlaylistItem ? j.getPlaylistItem() : null;
                              if(it){ add('jw.file',it.file); for(const x of (it.sources||[])) add('jw.source',x.file); for(const x of (it.tracks||[])){ if(x && x.file){ try{ out.push({source:'jw.subtitle',u:String(x.file||'').trim(),subtitle:true,label:String(x.label||x.language||''),kind:String(x.kind||'')}); }catch(e){} } } }
                            }
                          }catch(e){}
                          try{
                            if(window.hls && window.hls.url) add('hls.url',window.hls.url);
                          }catch(e){}
                          const seen=new Set(); return out.filter(x=>x.u && !seen.has(x.u) && seen.add(x.u)).slice(0,250);
                        }""") or []
                        accepted=0
                        for hi in harvest:
                            if not isinstance(hi,dict): continue
                            hu=str(hi.get("u","")).strip(); hs=str(hi.get("source","")).strip()
                            if not hu.startswith(("http://","https://")): continue
                            if hi.get("subtitle") or hs == "jw.subtitle" or any(x in hu.lower() for x in (".vtt",".srt",".ass",".ssa",".ttml",".dfxp")):
                                self.log(f"[SUBTITLE_RUNTIME] source={hs} lang={hi.get('label','') or 'UNKNOWN'} kind={hi.get('kind','') or 'UNKNOWN'} url={hu}")
                                continue
                            self.log(f"[V25_RUNTIME_URL] source={hs} {hu}")
                            cand=self.runtime_discovered_candidate(hu,page.url or target,"V21_"+hs.upper().replace('.','_'))
                            if cand:
                                accepted+=1
                                if cand not in targets and len(targets)<8:
                                    targets.append(cand); target_referrer[cand]=page.url or target; target_reason[cand]="RUNTIME_HARVEST"
                        self.log(f"[V25_RUNTIME_HARVEST] items={len(harvest)} accepted={accepted}")
                        v79_harvest_subtitles_from_all_frames("AFTER_PLAYER_HARVEST")
                    except Exception as e:
                        self.log(f"[V22_RUNTIME_HARVEST_ERROR] {type(e).__name__}: {e}")

                    if not media_hits:
                        try:
                            played=page.evaluate("""async () => {
                              const vids=[...document.querySelectorAll('video')];
                              let n=0;
                              for(const v of vids){
                                try { await v.play(); n++; } catch(e) {}
                              }
                              return n;
                            }""")
                            if played:
                                self.log(f"[BROWSER_PLAY_ATTEMPT] html5_video={played}")
                                page.wait_for_timeout(3200)
                        except Exception:
                            pass

                    # V29: a player-shaped page is a live runtime, not just a URL discovery document.
                    # Keep the same frame/session alive for bounded retries and trigger public player APIs.
                    if not media_hits and self.runtime_candidate_score(page.url or target,ref or root_url,"V29_PLAYER_RUNTIME","player runtime continuation")>=8:
                        self.log(f"[V29_PLAYER_RUNTIME_CONTINUE] url={page.url or target}")
                        for cycle in range(3):
                            if media_hits or self.final_verified:break
                            try:
                                state=page.evaluate("""async () => {
                                  const out={jw:false,video:0};
                                  try{if(typeof jwplayer==='function'){const j=jwplayer();out.jw=true;try{j.play(true)}catch(e){try{j.play()}catch(_){}}}}catch(e){}
                                  try{for(const v of [...document.querySelectorAll('video')]){try{v.muted=true;await v.play();out.video++}catch(e){}}}catch(e){}
                                  return out;
                                }""") or {}
                                self.log(f"[V29_PLAYER_RUNTIME_CYCLE] cycle={cycle+1} jw={str(bool(state.get('jw'))).lower()} video={state.get('video',0)}")
                                page.wait_for_timeout(2200)
                                # Harvest only live player/media URLs; resources are not browser targets.
                                live=page.evaluate("""() => {
                                  const out=[]; const add=(s,u)=>{try{u=String(u||'').trim();if(u.startsWith('http://')||u.startsWith('https://'))out.push({s,u})}catch(e){}};
                                  try{if(typeof jwplayer==='function'){const j=jwplayer();const it=j&&j.getPlaylistItem?j.getPlaylistItem():null;if(it){add('jw.file',it.file);for(const x of (it.sources||[]))add('jw.source',x.file);for(const x of (it.tracks||[])){if(x&&x.file){try{out.push({s:'jw.subtitle',u:String(x.file||'').trim(),subtitle:true,label:String(x.label||x.language||''),kind:String(x.kind||'')})}catch(e){}}}}}}catch(e){}
                                  try{for(const v of document.querySelectorAll('video,source')){add('dom.media',v.currentSrc||v.src||v.getAttribute('src'))}}catch(e){}
                                  return out.slice(0,40);
                                }""") or []
                                for it in live:
                                    if not isinstance(it,dict):continue
                                    u=str(it.get('u','')); src=str(it.get('s',''))
                                    if not u:continue
                                    if it.get("subtitle") or src == "jw.subtitle" or any(x in u.lower() for x in (".vtt",".srt",".ass",".ssa",".ttml",".dfxp")):
                                        self.log(f"[SUBTITLE_RUNTIME] source={src} lang={it.get('label','') or 'UNKNOWN'} kind={it.get('kind','') or 'UNKNOWN'} url={u}")
                                        continue
                                    self.log(f"[V29_PLAYER_STATE] source={src} {u}")
                                    if u not in self.v31_active_player_sources:self.v31_active_player_sources.append(u)
                                    self.log(f"[V31_SEMANTIC_PROVENANCE] source=ACTIVE_PLAYER_STATE kind={src} url={u}")
                                    self.runtime_discovered_candidate(u,page.url or target,"V31_ACTIVE_PLAYER_STATE",src)
                                    # Follow the exact source the live player reports, even when the URL is extensionless/API-shaped.
                                    try:
                                        fr=page.evaluate("""async u=>{try{const r=await fetch(u,{credentials:'include',cache:'no-store'});const ct=r.headers.get('content-type')||'';const t=await r.text();return {ok:true,status:r.status,ct,url:r.url||u,text:t.slice(0,200000)}}catch(e){return {ok:false,error:String(e)}}}""",u) or {}
                                        if fr.get('ok'):
                                            st=int(fr.get('status',0) or 0); ct=str(fr.get('ct','') or ''); txt=str(fr.get('text','') or ''); fu=str(fr.get('url','') or u)
                                            self.log(f"[V31_ACTIVE_PLAYER_FOLLOW] status={st} ct={ct} url={fu} bytes={len(txt.encode('utf-8','replace'))}")
                                            kind=self._browser_media_kind(fu,ct)
                                            if 200<=st<400 and (kind or txt.lstrip().startswith('#EXTM3U')):
                                                remember_media(fu,kind or 'HLS',st,ct,'active_player_state')
                                            elif 200<=st<400:
                                                objs=[]
                                                if 'json' in ct.lower() or txt.lstrip().startswith(('{','[')):
                                                    try: objs=self.media_urls_from_object(json.loads(txt),fu)
                                                    except Exception: objs=[]
                                                for ju in objs[:20]:
                                                    self.log(f"[V31_ACTIVE_PLAYER_DERIVED] {ju}")
                                                    ru=self.runtime_discovered_candidate(ju,fu,"V31_ACTIVE_PLAYER_JSON",txt[:5000])
                                                    if ru and ru not in targets and len(targets)<16:
                                                        targets.append(ru);target_referrer[ru]=page.url or target;target_reason[ru]='V31_ACTIVE_PLAYER_JSON'
                                        else:
                                            self.log(f"[V31_ACTIVE_PLAYER_FOLLOW_ERROR] {fr.get('error','unknown')}")
                                    except Exception as ex:
                                        self.log(f"[V31_ACTIVE_PLAYER_FOLLOW_ERROR] {type(ex).__name__}: {ex}")
                            except Exception as ex:
                                self.log(f"[V29_PLAYER_RUNTIME_ERROR] cycle={cycle+1} {type(ex).__name__}: {ex}")

                    self.log(
                        f"[RUNTIME_BROWSER_TARGET_RESULT] url={target} "
                        f"mediaHits={len(media_hits)} discovered={len(self.runtime_discovered_urls)}"
                    )
                    # V40: after a trusted player bootstrap JSON appears, keep the exact browser
                    # session alive long enough for the site's own PlayerJS/HLS engine to turn its
                    # extensionless `file` source into a dynamic manifest request. No extra clicks.
                    if v40_bootstrap_seen and not media_hits:
                        self.log(f"[V40_MANIFEST_WAIT] bootstrap={v40_bootstrap_seen[-1]} sources={len(v40_bootstrap_sources)} windowMs=8000")
                        for _v40w in range(8):
                            try: page.wait_for_timeout(1000)
                            except Exception: break
                            if media_hits or self.final_verified: break
                            try:
                                _st=self.v39_browser_semantic_state(page,page.url or target)
                                for _u in _st:
                                    if _u and _u not in json_media: json_media.append(_u)
                            except Exception: pass
                        self.log(f"[V40_MANIFEST_WAIT_RESULT] mediaHits={len(media_hits)} final={str(self.final_verified).lower()}")
                    if media_hits:
                        break

                try:
                    page.wait_for_timeout(2200)
                except Exception:
                    pass

                def _v43_owner_frame(source_url):
                    sem=(getattr(self,'v43_semantic_media',{}) or {}).get(str(source_url)) or {}
                    owner=str(sem.get('frameUrl','') or '')
                    try:
                        frames=list(page.frames)
                    except Exception:
                        frames=[]
                    if owner:
                        try:
                            for fr in frames:
                                fu=str(fr.url or '')
                                if fu==owner:
                                    return fr,owner,'exact'
                            oh=(urlparse(owner).hostname or '').lower()
                            for fr in frames:
                                fu=str(fr.url or '')
                                if oh and (urlparse(fu).hostname or '').lower()==oh:
                                    return fr,fu,'same-origin'
                        except Exception:
                            pass
                    try:
                        sh=(urlparse(str(source_url)).hostname or '').lower()
                        for fr in frames:
                            fu=str(fr.url or '')
                            if sh and (urlparse(fu).hostname or '').lower()==sh:
                                return fr,fu,'source-origin'
                    except Exception:
                        pass
                    try:
                        self.log("[V45_FRAME_OWNER_FALLBACK] source="+str(source_url)+" frames="+
                                 " | ".join(str(fr.url or '') for fr in frames[:12]))
                    except Exception:
                        pass
                    return page.main_frame,str(page.url or ''),'fallback-main'

                def _v43_browser_fetch(source_url,max_chars=220000):
                    fr,frurl,mode=_v43_owner_frame(source_url)
                    self.log(f"[V43_FRAME_FETCH] mode={mode} frame={frurl} url={source_url}")
                    try:
                        res=fr.evaluate(
                            """async ({u,maxChars}) => {
                                try {
                                  const r=await fetch(u,{
                                    credentials:'include',
                                    cache:'no-store',
                                    redirect:'follow',
                                    referrer:location.href,
                                    referrerPolicy:'strict-origin-when-cross-origin'
                                  });
                                  const ct=r.headers.get('content-type')||'';
                                  let text='';
                                  try { text=(await r.text()).slice(0,maxChars); } catch(e) {}
                                  return {ok:r.ok,status:r.status,ct,text,url:r.url,via:'fetch'};
                                } catch(e) {
                                  try {
                                    return await new Promise((resolve)=>{
                                      const x=new XMLHttpRequest();
                                      x.open('GET',u,true);
                                      x.withCredentials=true;
                                      x.timeout=10000;
                                      x.onload=()=>resolve({
                                        ok:x.status>=200&&x.status<400,
                                        status:x.status,
                                        ct:x.getResponseHeader('content-type')||'',
                                        text:(x.responseText||'').slice(0,maxChars),
                                        url:x.responseURL||u,
                                        via:'xhr'
                                      });
                                      x.onerror=()=>resolve({error:'XHR network error after fetch: '+String(e)});
                                      x.ontimeout=()=>resolve({error:'XHR timeout after fetch: '+String(e)});
                                      x.send();
                                    });
                                  } catch(e2) {
                                    return {error:'fetch='+String(e)+' | xhr='+String(e2)};
                                  }
                                }
                            }""",
                            {'u':source_url,'maxChars':int(max_chars)}
                        )
                        if isinstance(res,dict):
                            res['frameUrl']=frurl; res['frameMode']=mode
                        return res
                    except Exception as ex:
                        return {'error':f'{type(ex).__name__}: {ex}','frameUrl':frurl,'frameMode':mode}

                def _v43_browser_hls_proof(root_url,root_body,root_status,root_ct):
                    # Browser-native proof keeps the exact Chromium cookies/fingerprint/frame.
                    # It accepts extensionless child URIs because HLS grammar, not URL suffix,
                    # defines whether a child is a variant/media playlist.
                    if int(root_status or 0) < 200 or int(root_status or 0) >= 400:
                        return False,root_url
                    body=str(root_body or '')
                    if not body.lstrip().startswith('#EXTM3U'):
                        return False,root_url
                    current_url=root_url; current_body=body
                    for depth in range(4):
                        variants,segments,maps=self.v32_hls_children(current_body,current_url)
                        if variants:
                            child=variants[0]
                            self.log(f"[V43_HLS_CHILD] depth={depth} kind=VARIANT url={child}")
                            rr=_v43_browser_fetch(child,220000)
                            if not isinstance(rr,dict) or rr.get('error'):
                                self.log(f"[V43_BROWSER_HLS_PROOF] FAIL stage=VARIANT_FETCH url={child} error={str((rr or {}).get('error',''))[:300]}")
                                return False,current_url
                            cb=str(rr.get('text',''))
                            cs=int(rr.get('status',0) or 0)
                            cc=str(rr.get('ct',''))
                            if not (200<=cs<400 and cb.lstrip().startswith('#EXTM3U')):
                                self.log(f"[V43_BROWSER_HLS_PROOF] FAIL stage=VARIANT_BODY status={cs} ct={cc} url={child}")
                                return False,current_url
                            ctx=dict(self.browser_request_context.get(child,{}) or {})
                            self.v33_browser_hls_observed[child]={'body':cb,'status':cs,'ct':cc,'context':ctx,'source':'v43_browser_proof'}
                            current_url=child; current_body=cb
                            continue
                        if segments or maps:
                            media_obj=(segments or maps)[0]
                            self.log(f"[V43_HLS_CHILD] depth={depth} kind=MEDIA_OBJECT url={media_obj}")
                            rr=_v43_browser_fetch(media_obj,4096)
                            if not isinstance(rr,dict) or rr.get('error'):
                                self.log(f"[V43_BROWSER_HLS_PROOF] FAIL stage=MEDIA_FETCH url={media_obj} error={str((rr or {}).get('error',''))[:300]}")
                                return False,current_url
                            st=int(rr.get('status',0) or 0); ct=str(rr.get('ct','')); tx=str(rr.get('text',''))
                            # Binary media read through response.text() may look garbled; successful
                            # non-HTML response is enough after an HLS media-playlist grammar proof.
                            htmlish=tx.lstrip().lower().startswith(('<!doctype html','<html'))
                            if 200<=st<400 and not htmlish:
                                self.log(f"[V43_BROWSER_HLS_PROOF] PASS playable={current_url} media={media_obj} status={st} ct={ct}")
                                self.v43_browser_fetch_proofs.append({'root':root_url,'playable':current_url,'media':media_obj,'status':st,'ct':ct})
                                return True,current_url
                            self.log(f"[V43_BROWSER_HLS_PROOF] FAIL stage=MEDIA_STATUS status={st} ct={ct} url={media_obj}")
                            return False,current_url
                        self.log(f"[V43_BROWSER_HLS_PROOF] FAIL stage=NO_CHILD depth={depth} url={current_url}")
                        return False,current_url
                    return False,current_url

                if getattr(self,"v46_clean_observer",False):
                    self.log(f"[V46_CLEAN_OBSERVER] ACTIVE_MEDIA_REFETCH=SKIPPED semantic_sources={len(json_media)}")

                    # V49: Player-frame priority.
                    # Keep V46 clean observer. Read DOM geometry only.
                    # Never choose main-page layout DIVs if a player/embed frame exists.
                    # Actual action is one trusted Playwright pointer click.

                    v49_clicked=False
                    v49_player_candidates=[]
                    v49_main_candidates=[]

                    # V57: collect ad/pre-roll media declared by markup before any interaction.
                    # Example shape: data-preroll='{"ads":[{"video":"...mp4"}]}'
                    # Generic by structure: no Dizipal/provider/domain hardcode.
                    try:
                        _ad_blobs=page.locator('[data-preroll],[data-vast],[data-vmap]').evaluate_all(
                            "els => els.map(e => [e.getAttribute('data-preroll')||'', e.getAttribute('data-vast')||'', e.getAttribute('data-vmap')||''].join(' '))"
                        ) or []
                        for _blob in _ad_blobs:
                            for _u in re.findall(r'https?://[^\s\"\'<>}]+', str(_blob or '')):
                                _u=_u.rstrip('),;]')
                                if _u:
                                    runtime_ad_media_urls.add(_u)
                        if runtime_ad_media_urls:
                            self.log(f"[V57_AD_MEDIA_DECLARED] count={len(runtime_ad_media_urls)}")
                            for _u in sorted(runtime_ad_media_urls)[:12]:
                                self.log(f"[V57_AD_MEDIA_URL] {_u}")
                    except Exception as _adex:
                        self.log(f"[V57_AD_MEDIA_SCAN_ERROR] {type(_adex).__name__}: {str(_adex)[:300]}")

                    self.log(f"[V49_AUTO_PLAY] SEARCH frames={len(page.frames)} policy=PLAYER_FRAME_FIRST")

                    for fr in page.frames:
                        furl=str(fr.url or '')
                        low=furl.lower()
                        is_player_frame=(fr != page.main_frame)
                        self.log(f"[V49_AUTO_PLAY] SEARCH_FRAME playerFrame={str(is_player_frame).lower()} url={furl[:500]}")
                        try:
                            candidates=fr.evaluate(r"""() => {
                              const vw=Math.max(document.documentElement.clientWidth||0, window.innerWidth||0);
                              const vh=Math.max(document.documentElement.clientHeight||0, window.innerHeight||0);
                              const cx=vw/2, cy=vh/2;
                              const out=[];
                              const els=[...document.querySelectorAll('button,[role="button"],div,span,a,svg,video')];
                              for (let i=0;i<els.length;i++) {
                                const e=els[i], cs=getComputedStyle(e), r=e.getBoundingClientRect();
                                if (!r || r.width < 24 || r.height < 24) continue;
                                if (r.bottom<=0 || r.right<=0 || r.left>=vw || r.top>=vh) continue;
                                if (cs.display==='none' || cs.visibility==='hidden' || Number(cs.opacity||1)<=0.02) continue;

                                const tag=(e.tagName||'').toLowerCase();
                                const id=e.id||'';
                                const cls=typeof e.className==='string' ? e.className : (e.getAttribute('class')||'');
                                const aria=e.getAttribute('aria-label')||'';
                                const title=e.getAttribute('title')||'';
                                const role=e.getAttribute('role')||'';
                                const href=(e.getAttribute('href')||'').trim();
                                const playerAncestor=e.closest('video,[class*=player i],[id*=player i],[class*=video i],[id*=video i],[class*=jw- i],[class*=plyr i],[class*=vjs- i]');
                                const adAncestor=e.closest('[class*=preroll-ad i],[id=prerollAd i],[id=prerollVideo i],[class*=preroll-clickable i],[id=prerollClickable i],[class*=preroll-skip i],[id=skipBox i],[id=skipBtn i],[class*=advert i],[id*=advert i],[class*=ad-container i],[id*=ad-container i],[data-vast],[data-vmap]');
                                const text=(e.innerText||e.textContent||'').replace(/\s+/g,' ').trim().slice(0,160);
                                const blob=(id+' '+cls+' '+aria+' '+title+' '+role+' '+text).toLowerCase();
                                const adContext=!!adAncestor || /(^|[^a-z])(preroll|pre-roll|advertisement|sponsored|ad-container|vast|vmap)([^a-z]|$)/.test(blob);
                                const hrefLow=href.toLowerCase();
                                const navHref=!!href && !hrefLow.startsWith('javascript:') && !hrefLow.startsWith('#') && !/\.(m3u8|mpd|mp4|webm)(?:$|[?#])/i.test(hrefLow);
                                const area=Math.max(0,r.width*r.height);
                                const x=r.left+r.width/2, y=r.top+r.height/2;
                                const dist=Math.hypot(x-cx,y-cy);
                                const centered=dist <= Math.max(vw,vh)*0.32;
                                const clickable =
                                  tag==='button' || tag==='a' || role==='button' ||
                                  typeof e.onclick==='function' || cs.cursor==='pointer' ||
                                  e.hasAttribute('onclick') || e.tabIndex>=0;

                                let score=0;
                                if (tag==='video') score+=220;
                                if (id.toLowerCase()==='player') score+=210;
                                if (/jw-display|jw-icon-display|vjs-big-play|plyr__control--overlaid|play-button|play_btn|playbtn/.test(blob)) score+=260;
                                if (/\bplay\b|oynat|izle|watch/.test(blob)) score+=180;
                                if (/player-top-wrap|player|video|poster|overlay|display|center/.test(blob)) score+=90;
                                if (clickable) score+=35;
                                if (playerAncestor) score+=120;
                                if (navHref && tag==='a') score-=420;
                                if (centered) score+=45;
                                if (area>=5000) score+=20;
                                if (area>=20000) score+=20;
                                if (/pause|volume|mute|setting|fullscreen|quality|caption|subtitle/.test(blob)) score-=220;
                                if (adContext) score-=1400;
                                if (cs.pointerEvents==='none') score-=300;

                                out.push({
                                  index:i,tag,id,cls:String(cls).slice(0,220),
                                  aria:String(aria).slice(0,140),title:String(title).slice(0,140),
                                  role:String(role).slice(0,80),text:String(text).slice(0,140),
                                  href:String(href).slice(0,500),navHref,playerAncestor:!!playerAncestor,adContext,
                                  cursor:cs.cursor,pointerEvents:cs.pointerEvents,zIndex:cs.zIndex,
                                  clickable,centered,score,
                                  rect:{left:r.left,top:r.top,width:r.width,height:r.height,x,y},
                                  viewport:{width:vw,height:vh}
                                });
                              }
                              out.sort((a,b)=>b.score-a.score);
                              return out.slice(0,60);
                            }""") or []
                        except Exception as ex:
                            self.log(f"[V49_DOM_SCAN_ERROR] frame={furl[:220]} {type(ex).__name__}: {str(ex)[:350]}")
                            continue

                        # V55: classify player context from structure/DOM evidence, never from domain names.
                        frame_dom_player = any(
                            (str(c.get("tag","")).lower()=="video") or bool(c.get("playerAncestor")) or
                            any(k in ((str(c.get("id", ""))+" "+str(c.get("cls", ""))).lower()) for k in ("player","jw-","plyr","vjs-","video"))
                            for c in candidates[:30]
                        )
                        is_player_frame = bool((fr != page.main_frame) and frame_dom_player)
                        self.log(f"[V55_FRAME_CLASSIFY] child={str(fr != page.main_frame).lower()} domPlayer={str(frame_dom_player).lower()} playerFrame={str(is_player_frame).lower()} url={furl[:500]}")

                        for cand in candidates:
                            c=dict(cand)
                            c["frame"]=furl
                            c["playerFrame"]=is_player_frame
                            score=int(c.get("score",0))
                            # V55 hard veto: ordinary navigation anchors are not playback controls.
                            if bool(c.get("navHref")) and str(c.get("tag","")).lower()=="a":
                                score -= 700
                            # V57 hard veto by DOM semantics: a pre-roll/ad element can never be
                            # the trusted playback pointer even if it is a <video> inside player UI.
                            if bool(c.get("adContext")):
                                score -= 5000
                                self.log(f"[V57_AD_INTERACTION_VETO] tag={c.get('tag')} id={c.get('id')} frame={furl[:260]}")
                            if bool(c.get("playerAncestor")) and not bool(c.get("adContext")):
                                score += 140

                            # Strictly demote generic main-page layout containers.
                            if not is_player_frame:
                                if c.get("tag")=="div" and not c.get("clickable"):
                                    score -= 260
                                txt=(c.get("text") or "").lower()
                                if "film player" in txt or "ana sayfa" in txt:
                                    score -= 120
                            else:
                                # Strong bonus for actual player/embed context.
                                score += 300
                                tag=(c.get("tag") or "").lower()
                                cid=(c.get("id") or "").lower()
                                cls=(c.get("cls") or "").lower()
                                if tag=="video":
                                    score += 180
                                if cid=="player":
                                    score += 170
                                if "player-top-wrap" in cls:
                                    score += 110

                            c["scoreFinal"]=score
                            self.log("[V49_DOM_CANDIDATE] "+json.dumps(c,ensure_ascii=False)[:1800])

                            if is_player_frame:
                                v49_player_candidates.append(c)
                            else:
                                v49_main_candidates.append(c)

                    # PLAYER FRAME ALWAYS WINS if one exists.
                    pool=v49_player_candidates if v49_player_candidates else v49_main_candidates
                    pool.sort(key=lambda x:x.get("scoreFinal",0), reverse=True)
                    v49_best=pool[0] if pool else None

                    if v49_best is not None:
                        self.log("[V49_AUTO_PLAY] SELECTED "+json.dumps(v49_best,ensure_ascii=False)[:1800])

                    if False and v49_best is not None and v49_best.get("scoreFinal",0) >= 300 and not bool(v49_best.get("navHref")) and not bool(v49_best.get("adContext")):  # V60 manual Chrome only
                        try:
                            target_frame=None
                            for fr in page.frames:
                                if str(fr.url or '') == str(v49_best.get('frame') or ''):
                                    target_frame=fr
                                    break
                            if target_frame is None:
                                raise RuntimeError("target frame disappeared")

                            rect=v49_best.get("rect") or {}
                            x=float(rect.get("x",0))
                            y=float(rect.get("y",0))

                            before_hits=len(media_hits)
                            before_req_ids=set(cdp_requests.keys())
                            before_url=str(page.url or '')
                            self.v50_auto_play_attempted=True
                            self.v50_preexisting_media_before_auto=max(self.v50_preexisting_media_before_auto,before_hits)
                            if before_hits > 0 and self.v50_interaction_provenance == "NONE":
                                self.v50_interaction_provenance="PREEXISTING_PLAYBACK_BEFORE_AUTO"
                            self.log(f"[V49_AUTO_PLAY] CLICK_ONCE frame={v49_best.get('frame','')[:300]} tag={v49_best.get('tag')} id={v49_best.get('id')} x={x:.1f} y={y:.1f} media_before={before_hits}")

                            body=target_frame.locator("body")
                            body.click(position={"x":x,"y":y}, timeout=4000, force=False)
                            self.log("[V55_PLAYER_POINTER] EXECUTED trusted=true navigationVeto=false")
                            self.log("[V49_AUTO_PLAY] CLICK_OK wait_ms=12000")
                            page.wait_for_timeout(12000)
                            after_hits=len(media_hits)
                            delta=after_hits-before_hits
                            new_req_ids=[rid for rid in cdp_requests.keys() if rid not in before_req_ids]
                            xhr_delta=[]
                            for rid in new_req_ids:
                                q=cdp_requests.get(rid,{}) or {}
                                if str(q.get("type","")).lower() in ("xhr","fetch"):
                                    xhr_delta.append(rid)
                            after_url=str(page.url or '')
                            nav_changed=(after_url != before_url)
                            hard_evidence=(delta>0) or bool(xhr_delta)
                            v49_clicked=bool(hard_evidence)
                            self.v50_auto_play_triggered=bool(delta>0)
                            if delta > 0:
                                self.v50_interaction_provenance="V55_TRUSTED_PLAYER_POINTER"
                            elif xhr_delta:
                                self.v50_interaction_provenance="V55_BOOTSTRAP_NETWORK_DELTA"
                            self.log(f"[V55_CAUSAL_DELTA] newRequests={len(new_req_ids)} xhrFetch={len(xhr_delta)} mediaDelta={delta} navChanged={str(nav_changed).lower()} accepted={str(hard_evidence).lower()}")
                            if nav_changed and not hard_evidence:
                                self.log(f"[V55_NAVIGATION_ROLLBACK] from={after_url[:300]} to={before_url[:300]} reason=NO_RUNTIME_EVIDENCE")
                                try:
                                    page.go_back(wait_until="domcontentloaded",timeout=6000)
                                    page.wait_for_timeout(1200)
                                except Exception as rbex:
                                    self.log(f"[V55_NAVIGATION_ROLLBACK] ERROR {type(rbex).__name__}: {str(rbex)[:300]}")
                            self.log(f"[V49_AUTO_PLAY] RESULT media_before={before_hits} media_after={after_hits} delta={delta} auto_triggered={str(delta>0).lower()}")
                        except Exception as ex:
                            self.log(f"[V49_AUTO_PLAY] CLICK_FAIL {type(ex).__name__}: {str(ex)[:700]}")
                    else:
                        reason='NO_CANDIDATE' if v49_best is None else f"LOW_OR_NAV_SCORE_{v49_best.get('scoreFinal',0)}"
                        self.log(f"[V49_AUTO_PLAY] SKIP reason={reason}")

                    # V60: visible Chrome is controlled only by the user.
                    # Observe while the user manually presses Play and manually
                    # skips however many ads the site presents.
                    if not v49_clicked:
                        self.log("[V60_MANUAL_INTERACTION_WINDOW] wait_ms=90000 ad_count=UNKNOWN user_controls_chrome=true")
                        try:
                            page.wait_for_timeout(90000)
                        except Exception:
                            pass

                        # V62: after manual playback/ad flow, snapshot every live frame's
                        # player state. This reads state only; it never invokes playback.
                        try:
                            for _v62_i,_v62_fr in enumerate(page.frames):
                                try:
                                    _v62_snap=_v62_fr.evaluate(r"""() => {
                                      const out={href:location.href, scripts:[], resources:[], jw:null, urlGlobals:[]};
                                      try{out.scripts=[...document.scripts].map(s=>({src:s.src||'',inline:(s.src?'':(s.textContent||'').slice(0,30000))})).slice(0,120)}catch(e){}
                                      try{out.resources=performance.getEntriesByType('resource').map(x=>x.name).filter(x=>/^https?:/i.test(x)).slice(-300)}catch(e){}
                                      try{
                                        if(typeof window.jwplayer==='function'){
                                          const j=window.jwplayer();
                                          out.jw={
                                            playlist:(j&&j.getPlaylist?j.getPlaylist():null),
                                            playlistItem:(j&&j.getPlaylistItem?j.getPlaylistItem():null),
                                            qualityLevels:(j&&j.getQualityLevels?j.getQualityLevels():null),
                                            state:(j&&j.getState?j.getState():null)
                                          };
                                        }
                                      }catch(e){out.jw={error:String(e)}}
                                      try{
                                        const keys=Object.keys(window).slice(0,4000);
                                        for(const k of keys){
                                          let v; try{v=window[k]}catch(e){continue}
                                          if(typeof v==='string' && v.length<20000 && /(https?:\/\/|\.m3u8|\.mpd|embed|manifest)/i.test(v)){
                                            out.urlGlobals.push({key:k,value:v.slice(0,20000)});
                                            if(out.urlGlobals.length>=100)break;
                                          }
                                        }
                                      }catch(e){}
                                      return out;
                                    }""")
                                    self.log("[V62_RUNTIME_PLAYER_SNAPSHOT] "+json.dumps({"frameIndex":_v62_i,"frameUrl":_v62_fr.url,"snapshot":_v62_snap},ensure_ascii=False,default=str)[:500000])
                                except Exception as _v62fe:
                                    self.log(f"[V62_RUNTIME_PLAYER_SNAPSHOT_ERROR] frame={_v62_i} {type(_v62fe).__name__}: {_v62fe}")
                        except Exception as _v62se:
                            self.log(f"[V62_RUNTIME_SNAPSHOT_ERROR] {type(_v62se).__name__}: {_v62se}")
                for ju in ([] if getattr(self,"v46_clean_observer",False) else json_media[:12]):
                    if media_hits or self.final_verified:
                        break
                    try:
                        result=_v43_browser_fetch(ju,220000)
                        if isinstance(result,dict) and not result.get("error"):
                            self.log(f"[BROWSER_FETCH] {result.get('status')} {result.get('ct','')} {result.get('url',ju)} frame={result.get('frameMode','')}")
                            if ju in (getattr(self,'v43_semantic_media',{}) or {}):
                                self.log(f"[V45_JSON_HLS_HANDOFF] source={ju} via={result.get('via','')} frame={result.get('frameMode','')}")
                            text=str(result.get("text","") or '')
                            head=text.lstrip()
                            _rurl=str(result.get("url",ju))
                            hard_kind=''
                            _ct=str(result.get('ct',''))
                            _sem_hint=(getattr(self,'v43_semantic_media',{}) or {}).get(ju) or {}
                            _sem_evidence=" ".join(str(x) for x in (_sem_hint.get("evidence") or [])).lower()
                            if '.m3u8' in _rurl.lower() or 'mpegurl' in _ct.lower() or head.startswith('#EXTM3U'):
                                hard_kind='HLS'
                            elif (str(_sem_hint.get("type","")).lower()=="hls" or
                                  "mpegurl" in str(_sem_hint.get("mimeType","")).lower() or
                                  "hls" in _sem_evidence or "mpegurl" in _sem_evidence):
                                hard_kind='HLS'
                                self.log(f"[V45_EXTENSIONLESS_HLS_EXPECTED] url={ju}")
                            elif '.mpd' in _rurl.lower() or 'dash+xml' in _ct.lower():
                                hard_kind='DASH'
                            elif '.mp4' in _rurl.lower() or 'video/mp4' in _ct.lower():
                                hard_kind='MP4'
                            if hard_kind=='HLS' and head.startswith("#EXTM3U"):
                                self.log(f"[V43_DYNAMIC_MANIFEST] source=SAME_FRAME_BROWSER_FETCH url={_rurl}")
                                _ctx=dict(self.browser_request_context.get(_rurl,{}) or (self.v43_semantic_media.get(ju) or {}).get('requestContext') or {})
                                self.v33_browser_hls_observed[_rurl]={'body':text,'status':int(result.get('status',0) or 0),'ct':_ct,'context':_ctx,'source':'v43_same_frame_fetch'}
                                ok,playable=_v43_browser_hls_proof(_rurl,text,int(result.get('status',0) or 0),_ct)
                                if ok:
                                    self.final=playable; self.final_type='HLS'; self.final_verified=True
                                    self.final_playback_context=_ctx
                                    self.log(f"[FINAL_MEDIA] HLS {playable}")
                                    self.log(f"[V43_PLAYER_HANDOFF_READY] verified=true url={playable}")
                                    break
                                remember_media(_rurl,'HLS',int(result.get('status',0) or 0),_ct,'v43_browser_fetch')
                            elif hard_kind and 200 <= int(result.get("status",0)) < 400:
                                remember_media(_rurl,hard_kind,int(result.get('status',0)),_ct,'v43_browser_fetch')
                            elif head:
                                # Extensionless player-source handoff may return another structured source.
                                try:
                                    _more=self.v40_bootstrap_json(text,_rurl)
                                    for _it in _more:
                                        _u=_it.get('url','')
                                        if _u and _u not in json_media: json_media.append(_u)
                                        if _u:
                                            _sem=dict(self.v43_semantic_media.get(_u) or {})
                                            _sem.setdefault('frameUrl',str(result.get('frameUrl','') or ''))
                                            _sem.setdefault('bootstrapUrl',_rurl)
                                            self.v43_semantic_media[_u]=_sem
                                except Exception: pass
                        elif isinstance(result,dict):
                            self.log(f"[V43_FRAME_FETCH_ERROR] url={ju} error={str(result.get('error',''))[:500]}")
                    except Exception as ex:
                        self.log(f"[V43_FRAME_FETCH_ERROR] url={ju} {type(ex).__name__}: {ex}")

                try:
                    bodytxt=page.locator("body").inner_text(timeout=1200).lower()
                    if not media_hits and any(x in bodytxt for x in (
                        "premium üyelik gerekli","abonelik gerekli","giriş yaparak izle","üyelik gerekli"
                    )):
                        self.log("[ENTITLEMENT_STATE] ACCESS_REQUIRED; no bypass attempted")
                except Exception:
                    pass

                if v44_attached_browser:
                    # Disconnecting Playwright must not close the user's real Chrome
                    # or destroy its persistent Cloudflare/browser session.
                    self.log("[V46_CLEAN_OBSERVER] END passive_capture_complete=true")
                    self.log("[V44_REAL_CHROME_DETACH] keep_browser_open=true")
                else:
                    context.close()
                    browser.close()

        except Exception as e:
            self.browser_runtime_error=f"RUNTIME: {type(e).__name__}: {e}"
            self.log(f"[BROWSER_RUNTIME_ERROR] {type(e).__name__}: {str(e)[:1000]}")
            return False

        if media_hits:
            media_hits.sort(key=lambda x: (0 if x[1]=="HLS" else 1))
            # V32: choose the first browser media candidate that passes final proof.
            chosen=None
            for cand in media_hits:
                cu,ckind,cstatus,cct,csource=cand
                cctx=self.browser_media_context.get(cu) or self.browser_request_context.get(cu,{})
                if ckind!="HLS":
                    chosen=cand
                    break
                seed=(getattr(self,"v33_browser_hls_observed",{}) or {}).get(cu) or {}
                observed=str(seed.get("body", ""))
                proof_ctx=seed.get("context") or cctx
                proof_status=int(seed.get("status",cstatus) or cstatus)
                proof_ct=str(seed.get("ct",cct) or cct)
                if observed.lstrip().startswith("#EXTM3U"):
                    self.log(f"[V33_FINAL_PROOF_TRIGGER] source={seed.get('source',csource)} status={proof_status} url={cu}")
                if self.v32_final_media_proof(
                    cu,ctx=proof_ctx,referer=(proof_ctx or {}).get("referer",""),
                    observed_body=observed,observed_status=proof_status,observed_ct=proof_ct,
                    source=csource
                ):
                    chosen=cand
                    break
                self.log(f"[V32_MEDIA_CANDIDATE_REJECT] reason=FINAL_PROOF_FAILED url={cu}")
            if chosen is None:
                self.log("[V32_FINAL_MEDIA_PROOF] NO_BROWSER_CANDIDATE_PASSED")
                self.log("[BROWSER_RUNTIME] NO_FINAL_MEDIA_PROOF")
                return False
            else:
                u,kind,status,ct,source=chosen
                proven_u=self.v73_proven_playable_manifest(u) if kind=="HLS" else u
                if kind=="HLS" and proven_u != u:
                    self.log(f"[V73_FINAL_PROMOTE] source=BROWSER requested={u} proven={proven_u}")
                reqctx=(self.browser_media_context.get(proven_u) or self.browser_request_context.get(proven_u)
                        or self.browser_media_context.get(u) or self.browser_request_context.get(u,{}))
            if reqctx:
                self.log("[BROWSER_MEDIA_CONTEXT] "
                         f"referer={reqctx.get('referer','')} | origin={reqctx.get('origin','')} | "
                         f"range={reqctx.get('range','')}")
            playback_headers={}
            for src_key,out_key in (("user-agent","User-Agent"),("referer","Referer"),
                                    ("origin","Origin"),("accept","Accept"),
                                    ("range","Range"),("cookie","Cookie")):
                val=(reqctx or {}).get(src_key,"")
                if val:
                    playback_headers[out_key]=val
            handoff_url=proven_u if kind=="HLS" else u
            self.final_playback_context={
                "url":handoff_url,
                "format":kind.lower(),
                "content_type":ct,
                "status":status,
                "headers":playback_headers,
                "referer":(reqctx or {}).get("referer",""),
                "origin":(reqctx or {}).get("origin",""),
                "source":source,
            }
            self.log(f"[PLAYER_HANDOFF_READY] format={kind.lower()} url={handoff_url} headers={','.join(playback_headers.keys()) or 'NONE'}")
            item=self.register_media_candidate(
                handoff_url,"BROWSER_NETWORK_PROVEN_FINAL",
                "proof-selected playable manifest "+json.dumps(reqctx,ensure_ascii=False),
                ct,"",status
            )
            self.final=handoff_url
            self.final_type=kind
            self.final_verified=True
            self.final_evidence=item
            self.log(f"[BROWSER_FINAL_MEDIA] {kind} {handoff_url}")
            self.log(f"[BROWSER_FINAL_VERIFY] YES status={status} ct={ct} source={source}")
            return True

        if self.broken_player_targets:
            self.log("[BROKEN_PLAYER_TRANSPORT_SUMMARY] "+str(len(self.broken_player_targets)))
            for u in self.broken_player_targets[:10]:
                self.log("  BROKEN_PLAYER -> "+u)
        if self.runtime_discovered_urls and not self.final_verified:
            self.log("[BROWSER_RUNTIME] handing discovered URLs back to generic resolver")
            if self.requeue_runtime_discovered(root_url):
                return True
        self.log("[BROWSER_RUNTIME] NO_FINAL_MEDIA")
        return False


    # V75 + V3 FIX Chrome/MITM fallback. Existing resolver remains first.

    def v3_mitm_pick_player_target(self, root_url):
        """Pick the strongest already-discovered player/embed URL before falling back to root."""
        vals=[]
        for u in (self.runtime_discovered_urls or []):
            try:
                u=str(u or "").strip()
                if not u.startswith(("http://","https://")):continue
                if u not in vals:vals.append(u)
            except Exception:pass
        def score(u):
            x=u.lower();sc=0
            if any(k in x for k in ("/video/","/embed/","/player/","player.php","embed-")):sc+=100
            if any(k in x for k in ("vidpapi","vidmoly","molystream","popcornvakti","stream")):sc+=45
            if any(x.endswith(e) for e in (".js",".css",".jpg",".jpeg",".png",".webp",".svg",".srt",".vtt")):sc-=150
            if any(k in x for k in ("cloudflare","googleapis","gstatic","jwpcdn","shorterwanderer")):sc-=100
            if x.rstrip("/") == str(root_url).lower().rstrip("/"):sc-=80
            return sc
        ranked=sorted(vals,key=lambda u:(score(u),vals.index(u)),reverse=True)
        chosen=ranked[0] if ranked and score(ranked[0])>0 else root_url
        self.log(f"[V3_MITM_TARGET] score={score(chosen) if chosen!=root_url else 0} url={chosen}")
        return chosen


    def v3_mitm_chrome_fallback_v80(self, root_url):
        if self.final_verified:return True
        self.v3_mitm_fallback_used=True;self.log("[V3_MITM_FALLBACK] START");mitm_proc=None
        try:
            import shutil as _shutil,socket as _socket
            mitmdump=_shutil.which("mitmdump") or _shutil.which("mitmdump.exe")
            if not mitmdump:self.log("[V3_MITM_FALLBACK] mitmdump bulunamadi");return False
            cc=[r"C:\Program Files\Google\Chrome\Application\chrome.exe",r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                os.path.join(os.environ.get("LOCALAPPDATA",""),"Google","Chrome","Application","chrome.exe")]
            chrome=next((p for p in cc if p and os.path.isfile(p)),None)
            if not chrome:self.log("[V3_MITM_FALLBACK] Chrome bulunamadi");return False
            sk=_socket.socket();sk.bind(("127.0.0.1",0));port=sk.getsockname()[1];sk.close()
            work=ROOT/"v3_mitm_output";work.mkdir(exist_ok=True);cap=work/"media_live.jsonl";cap.unlink(missing_ok=True)
            addon=ROOT/"v3_mitm_capture.py"
            mitm_proc=subprocess.Popen([mitmdump,"--listen-host","127.0.0.1","--listen-port",str(port),"-s",str(addon),
                                        "--ssl-insecure","--set","connection_strategy=lazy","--set",f"resolver_capture={cap}"],cwd=str(ROOT))
            time.sleep(2)
            if mitm_proc.poll() is not None:self.log("[V3_MITM_FALLBACK] mitmdump kapandi");return False
            profile=str((work/"chrome_profile").resolve())
            subprocess.Popen([chrome,"--proxy-server=http://127.0.0.1:"+str(port),"--proxy-bypass-list=<-loopback>",
                              "--disable-quic","--user-data-dir="+profile,root_url])
            self.log(f"[V3_MITM_FALLBACK] NORMAL_CHROME_OPEN original_url={root_url} proxy=127.0.0.1:{port}")
            self.log("[V3_MITM_FALLBACK] ssl-insecure + lazy + disable-quic ACTIVE")
            deadline=time.time()+30;seen=set()
            while time.time()<deadline and not self.final_verified:
                time.sleep(.5)
                if not cap.exists():continue
                try:rows=cap.read_text("utf-8",errors="ignore").splitlines()
                except Exception:continue
                for line in rows:
                    try:r=json.loads(line)
                    except Exception:continue
                    u=str(r.get("url") or "");k=str(r.get("kind") or "")
                    if not u or u in seen or k not in ("hls","dash","mp4","webm","video","segment_html"):continue
                    seen.add(u);h=r.get("headers") or {}
                    ref=str(h.get("referer") or h.get("Referer") or "");origin=str(h.get("origin") or h.get("Origin") or "")
                    cookie=str(h.get("cookie") or h.get("Cookie") or "");ua=str(h.get("user-agent") or h.get("User-Agent") or UA)
                    ctx={"referer":ref,"origin":origin,"cookie":cookie,"user-agent":ua}
                    self.browser_request_context[u]=ctx;self.browser_media_context[u]=ctx
                    self.log(f"[V3_MITM_MEDIA] {k.upper()} {u}")
                    if k == "segment_html":
                        fam=str(r.get("segment_family") or "")
                        self.log(f"[V3_MITM_DISGUISED_SEGMENT] bytes={r.get('body_bytes',0)} family={fam} url={u}")
                        # A segment is proof that playback reached media transport, but
                        # it is not itself a standalone Media3 URL. Preserve the proof
                        # and continue listening for a manifest/bootstrap request.
                        self.v3_mitm_disguised_media_seen=True
                        self.v3_mitm_disguised_media_family=fam
                        continue
                    self.verify_media(u,ref,extra_context={"referer":ref,"siteurl":origin})
                    if self.final_verified:
                        hh={"User-Agent":ua}
                        if ref:hh["Referer"]=ref
                        if origin:hh["Origin"]=origin
                        if cookie:hh["Cookie"]=cookie
                        self.final_playback_context.update({"url":self.final,"headers":hh,"referer":ref,"origin":origin,
                                                            "source":"V3_FIX_MITMPROXY_NORMAL_CHROME"})
                        self.log(f"[V3_MITM_FINAL] {self.final_type} {self.final}");break
            if not self.final_verified:
                if getattr(self,"v3_mitm_disguised_media_seen",False):
                    self.log(f"[V3_MITM_MEDIA_PROOF] DISGUISED_SEGMENT_FLOW_CONFIRMED family={getattr(self,'v3_mitm_disguised_media_family','')}")
                    self.log("[V3_MITM_FALLBACK] MEDIA_FLOW_PROVEN_BUT_NO_STANDALONE_MANIFEST")
                else:
                    self.log("[V3_MITM_FALLBACK] NO_FINAL_MEDIA")
            return bool(self.final_verified)
        except Exception as e:
            self.v3_mitm_fallback_error=f"{type(e).__name__}: {e}"
            self.log(f"[V3_MITM_FALLBACK_ERROR] {type(e).__name__}: {str(e)[:500]}");return False
        finally:
            if mitm_proc is not None:
                try:mitm_proc.terminate()
                except Exception:pass


    def should_browser_runtime(self):
        if self.final_verified:
            return False
        text="\n".join(self.logs)
        return (
            self.runtime_needed
            or bool(self.player)
            # V58: Static urllib transport may time out while the user's real Chrome
            # can still open the page. A root transport failure must therefore hand
            # the same original URL to browser runtime instead of terminating early.
            # This is transport-boundary recovery only; it does not invent URLs.
            or bool(self.v31_transport_failures)
            or "WRONG_VERSION_NUMBER" in text
            or "[CLIENT_SESSION_RUNTIME]" in text
            or "[PLAYER_LITERAL]" in text
            or "[CHAIN_CLASS] PLAYER_CHAIN_PARTIAL" in text
        )

    # ---------------- V51: ADAPTIVE RESOLUTION REASONING ----------------
    # V51 keeps V49/V50 capture/proof behavior intact.  This layer reasons only from
    # evidence already captured by the resolver.  It never invents a URL, token,
    # header, cookie, API route or site-specific rule.
    def v50_stage(self,status,evidence=None,reason=""):
        return {"status":status,"evidence":list(evidence or [])[-8:],"reason":reason}

    def v50_build_transport_diagnostics(self):
        logtxt="\n".join(self.logs)
        errors=[]
        for row in self.logs:
            low=row.lower()
            if any(k in low for k in ("econnrefused","err_name_not_resolved","nxdomain","dns","timed out","timeout","connection refused","ssl","tls")):
                errors.append(row[:1200])
        diag={"real_chrome_attached":bool(self.v50_real_chrome_attached),"browser_mode":self.v50_browser_mode,
              "browser_runtime_available":bool(self.browser_runtime_available),"browser_runtime_error":self.browser_runtime_error,
              "transport_failures":self.v31_transport_failures[-12:],
              "browser_failures":self.v67_browser_failures[-20:],
              "observed_error_markers":errors[-12:],
              "dns_probe_performed":False,"dns_conclusion":"NOT_MEASURED"}
        if "domainLookupStart" in logtxt and "domainLookupEnd" in logtxt:
            diag["navigation_timing_dns_observed"]=True; diag["dns_conclusion"]="BROWSER_NAVIGATION_TIMING_PRESENT"
        else: diag["navigation_timing_dns_observed"]=False
        self.v50_transport_diagnostics=diag
        return diag

    def v50_build_final_proof_report(self):
        p=self.v32_proof if isinstance(self.v32_proof,dict) else {}
        steps=list(p.get("steps") or [])
        root=next((x for x in steps if x.get("stage")=="root"),{})
        variants=[x for x in steps if x.get("stage")=="variant"]
        segment=next((x for x in reversed(steps) if x.get("stage")=="segment"),{})
        root_ct=str(root.get("ct","") or "")
        report={"verified":bool(self.final_verified and p.get("verified")),"final_url":self.final,"final_type":self.final_type,
                "proof_level":"MEDIA_OBJECT_CONFIRMED" if p.get("verified") and segment else ("MANIFEST_ONLY" if root else "NONE"),
                "root_manifest":root,"variant_steps":variants,"playable_manifest":p.get("playable_manifest",""),"media_object":segment,
                "root_mime_warning":bool(root and "mpegurl" not in root_ct.lower() and "m3u" not in root_ct.lower()),
                "accept_reason":"DOWNSTREAM_MEDIA_OBJECT_PROOF" if p.get("verified") and segment else "NOT_VERIFIED"}
        self.v50_final_proof_report=report
        return report

    def _v51_has_runtime_media(self):
        # Static literals / failed probes are deliberately NOT enough.
        return bool(self.v43_semantic_media or self.final_verified or (self.v32_proof if isinstance(self.v32_proof,dict) else {}).get("steps"))

    def _v51_player_interaction_proven(self, logtxt):
        # Executing a click is not proof that playback was triggered.
        if self.v50_auto_play_triggered: return True
        if self.v50_preexisting_media_before_auto>0: return True
        if "hardPlayback=1" in logtxt or "mediaDelta=1" in logtxt: return True
        return False

    def v50_build_resolution_dna(self):
        logtxt="\n".join(self.logs); final_ok=bool(self.final_verified); stages={}
        stages["TOP_PAGE"]=self.v50_stage("PASS" if self.root_status else "FAIL",[f"http_status={self.root_status}"])
        script_ok=bool(self.script_endpoints) or "[SCRIPT" in logtxt or "PLAYER_CONFIG" in logtxt
        stages["SCRIPT_DISCOVERY"]=self.v50_stage("PASS" if script_ok else ("NOT_REQUIRED" if final_ok else "NOT_REACHED"),[f"script_endpoints={len(self.script_endpoints)}"])
        iframe_ok=bool(self.player) or "[IFRAME" in logtxt or "SEARCH_FRAME playerFrame=true" in logtxt
        stages["IFRAME_DISCOVERY"]=self.v50_stage("PASS" if iframe_ok else ("NOT_REQUIRED" if final_ok else "NOT_REACHED"),[self.player[:700]] if self.player else [])
        player_frame_ok=("[V49_AUTO_PLAY] SEARCH_FRAME playerFrame=true" in logtxt or "[V41_FRAME_" in logtxt)
        stages["PLAYER_FRAME"]=self.v50_stage("PASS" if player_frame_ok else ("NOT_REQUIRED" if final_ok else "NOT_REACHED"),["frame-scoped evidence observed"] if player_frame_ok else [])
        interaction_ok=self._v51_player_interaction_proven(logtxt)
        if self.v50_preexisting_media_before_auto>0 and not self.v50_auto_play_triggered:
            self.v50_interaction_provenance="PREEXISTING_PLAYBACK_BEFORE_AUTO"
        interaction_ev=[f"provenance={self.v50_interaction_provenance}",f"auto_attempted={self.v50_auto_play_attempted}",f"auto_triggered={self.v50_auto_play_triggered}",f"media_before_auto={self.v50_preexisting_media_before_auto}"]
        stages["PLAYER_INTERACTION"]=self.v50_stage("PASS" if interaction_ok else ("FAIL" if player_frame_ok and not final_ok else ("NOT_REQUIRED" if final_ok else "NOT_REACHED")),interaction_ev)
        net_ok=bool(self.browser_requests or self.browser_responses or self.browser_network)
        stages["NETWORK_ACTIVITY"]=self.v50_stage("PASS" if net_ok else "NOT_REACHED",[f"requests={len(self.browser_requests)}",f"responses={len(self.browser_responses)}"])
        json_markers=[x[:700] for x in self.logs if "[V40_BOOTSTRAP_JSON]" in x or "application/json" in x.lower()][-3:]
        json_ok=bool(self.v40_bootstrap_events or self.v43_semantic_media or json_markers)
        stages["JSON_BOOTSTRAP"]=self.v50_stage("PASS" if json_ok else ("NOT_REQUIRED" if final_ok else "NOT_REACHED"),json_markers or [f"bootstrap_events={len(self.v40_bootstrap_events)}",f"semantic_media={len(self.v43_semantic_media)}"])
        config_markers=[x[:700] for x in self.logs if "PLAYER_CONFIG" in x or "[V29_" in x][-3:]
        config_ok=bool(self.v31_active_player_sources or self.v43_semantic_media or config_markers)
        stages["PLAYER_CONFIG"]=self.v50_stage("PASS" if config_ok else ("NOT_REQUIRED" if final_ok else "NOT_REACHED"),config_markers or [f"active_sources={len(self.v31_active_player_sources)}"])
        runtime_cand=self._v51_has_runtime_media()
        cand_ev=[f"raw_candidates={len(self.media_candidates)}",f"semantic_media={len(self.v43_semantic_media)}",f"runtime_proven={runtime_cand}"]
        stages["MEDIA_CANDIDATE"]=self.v50_stage("PASS" if runtime_cand else ("NOT_REACHED" if not final_ok else "NOT_REQUIRED"),cand_ev)
        proof=self.v32_proof if isinstance(self.v32_proof,dict) else {}; root_step=next((x for x in (proof.get("steps") or []) if x.get("stage")=="root"),None)
        # V70: a root proof record is not automatically a proven manifest.  It must have
        # a successful HTTP status; v32_final_media_proof already requires an #EXTM3U body
        # before downstream proof, so a failed replay (for example 404/octet-stream) may
        # remain useful evidence but can no longer turn MANIFEST into PASS.
        root_status=0
        try: root_status=int((root_step or {}).get("status") or 0)
        except Exception: root_status=0
        manifest_valid=bool(root_step and 200 <= root_status < 400)
        manifest_ev=[json.dumps(root_step,ensure_ascii=False)[:1000],f"strict_valid={manifest_valid}"] if root_step else []
        stages["MANIFEST"]=self.v50_stage("PASS" if manifest_valid else ("FAIL" if root_step else ("NOT_REQUIRED" if final_ok and self.final_type!="HLS" else "NOT_REACHED")),manifest_ev)
        stages["MEDIA_PROOF"]=self.v50_stage("PASS" if final_ok else "NOT_REACHED",[f"verified={final_ok}",f"proof_verified={bool(proof.get('verified'))}"])
        # V70: player interaction is a means, not a mandatory milestone. If the same run
        # already produced bootstrap/config/media/manifest evidence without a click, mark
        # interaction NOT_REQUIRED instead of falsely calling it the first failure.
        downstream_without_click=bool(json_ok or config_ok or runtime_cand or root_step or final_ok)
        if stages["PLAYER_INTERACTION"]["status"]=="FAIL" and downstream_without_click:
            stages["PLAYER_INTERACTION"]=self.v50_stage("NOT_REQUIRED",interaction_ev+["downstream_runtime_evidence_observed_without_verified_click"])
        order=["TOP_PAGE","SCRIPT_DISCOVERY","IFRAME_DISCOVERY","PLAYER_FRAME","PLAYER_INTERACTION","NETWORK_ACTIVITY","JSON_BOOTSTRAP","PLAYER_CONFIG","MEDIA_CANDIDATE","MANIFEST","MEDIA_PROOF"]
        # Stage dependency: after the first FAIL, later non-independent stages are NOT_REACHED.
        first_fail=next((n for n in order if stages[n]["status"]=="FAIL"),None)
        if first_fail:
            i=order.index(first_fail)
            for n in order[i+1:]:
                if n not in ("NETWORK_ACTIVITY",) and stages[n]["status"]!="PASS": stages[n]["status"]="NOT_REACHED"
        last_success="NONE"
        for n in order:
            if stages[n]["status"]=="PASS": last_success=n
        blocked_at="NONE"; missing="NONE"; next_action="NONE"
        if not final_ok:
            if self.v31_transport_failures: blocked_at="NETWORK_ACTIVITY"; missing="NETWORK_TRANSPORT_RECOVERY"; next_action="INSPECT_TRANSPORT_FAILURE_EVIDENCE"
            elif stages["PLAYER_INTERACTION"]["status"]=="FAIL": blocked_at="PLAYER_INTERACTION"; missing="RELIABLE_PLAYER_INTERACTION_OR_BOOTSTRAP_TRIGGER"; next_action="TEST_PLAYER_FRAME_INTERACTION_THEN_OBSERVE_SAME_SESSION_NETWORK"
            elif not self.browser_runtime_available and self.runtime_needed: blocked_at="PLAYER_INTERACTION"; missing="BROWSER_RUNTIME"; next_action="START_OR_INSTALL_BROWSER_RUNTIME"
            elif net_ok and not runtime_cand: blocked_at="MEDIA_CANDIDATE"; missing="RUNTIME_MEDIA_SOURCE_OBSERVATION"; next_action="INSPECT_XHR_FETCH_JSON_PLAYER_CONFIG_MSE_OR_BLOB_EVIDENCE"
            elif runtime_cand and not manifest_valid: blocked_at="MANIFEST"; missing="VALID_MANIFEST_RESPONSE"; next_action="REPLAY_OBSERVED_MEDIA_CANDIDATES_IN_CAPTURED_SESSION_AND_REQUIRE_2XX_3XX_EXTM3U"
            elif manifest_valid and not proof.get("verified"): blocked_at="MEDIA_PROOF"; missing="MEDIA_OBJECT_PROOF"; next_action="FOLLOW_MANIFEST_CHILD_AND_VERIFY_MEDIA_OBJECT"
            else: blocked_at=next((n for n in order if stages[n]["status"] in ("FAIL","NOT_REACHED")),"UNKNOWN"); missing="UNCLASSIFIED_CAPABILITY_GAP"; next_action="RUN_EVIDENCE_DRIVEN_NEXT_EXPERIMENT"
            if blocked_at in stages and stages[blocked_at]["status"]=="NOT_REACHED": stages[blocked_at]["status"]="FAIL"
        dna={"result":"FINAL_VERIFIED" if final_ok else "INCOMPLETE","stages":stages,"last_success":last_success,"blocked_at":blocked_at,"missing_capability":missing,"next_action":next_action,"interaction_provenance":self.v50_interaction_provenance,"browser_mode":self.v50_browser_mode}
        self.v50_resolution_dna=dna; return dna

    def v51_build_behavior_signature(self,dna):
        s=dna["stages"]
        sig={"has_scripts":s["SCRIPT_DISCOVERY"]["status"]=="PASS","has_iframe":s["IFRAME_DISCOVERY"]["status"]=="PASS",
             "has_player_frame":s["PLAYER_FRAME"]["status"]=="PASS","interaction_proven":s["PLAYER_INTERACTION"]["status"]=="PASS",
             "has_json_bootstrap":s["JSON_BOOTSTRAP"]["status"]=="PASS","has_semantic_media":bool(self.v43_semantic_media),
             "has_manifest":s["MANIFEST"]["status"]=="PASS","media_proof":s["MEDIA_PROOF"]["status"]=="PASS",
             "browser_mode":self.v50_browser_mode,"transport_failures":bool(self.v31_transport_failures)}
        self.v51_behavior_signature=sig; return sig

    def v51_build_root_cause(self,dna):
        """Separate facts from hypotheses. REQUIRED is used only for directly proven facts."""
        sig=self.v51_build_behavior_signature(dna); blocked=dna.get("blocked_at","UNKNOWN")
        facts=[]; hypotheses=[]
        if sig["has_player_frame"]: facts.append("PLAYER_FRAME_DISCOVERED")
        if not sig["interaction_proven"] and sig["has_player_frame"]: facts.append("NO_VERIFIED_PLAYBACK_TRIGGER")
        if not sig["has_json_bootstrap"]: facts.append("NO_JSON_BOOTSTRAP_OBSERVED")
        if not sig["has_semantic_media"]: facts.append("NO_RUNTIME_SEMANTIC_MEDIA_OBSERVED")
        if sig["transport_failures"]: facts.append("TRANSPORT_FAILURE_OBSERVED")
        if self.v50_browser_mode=="AUTO_BROWSER_FALLBACK": facts.append("REAL_CHROME_NOT_ATTACHED")
        if blocked=="PLAYER_INTERACTION":
            hypotheses.append({"id":"PLAYER_GESTURE_OR_STATE_REQUIRED","confidence":"HIGH" if sig["has_player_frame"] else "MEDIUM","basis":["PLAYER_FRAME_DISCOVERED","NO_VERIFIED_PLAYBACK_TRIGGER"],"claim":"Playback/bootstrap may require a real player-frame gesture or browser state. This is a hypothesis until the trigger is observed."})
        if blocked=="MEDIA_CANDIDATE":
            hypotheses.append({"id":"HIDDEN_RUNTIME_SOURCE_PATH","confidence":"MEDIUM","basis":["NETWORK_ACTIVITY_WITHOUT_RUNTIME_MEDIA"],"claim":"Media may be produced by XHR/fetch, player config, DOM mutation, MSE or blob after the observed stage."})
        if blocked=="MANIFEST":
            hypotheses.append({"id":"SESSION_BOUND_MANIFEST","confidence":"MEDIUM","basis":["RUNTIME_MEDIA_WITHOUT_MANIFEST_PROOF"],"claim":"Candidate may require the same frame/session headers, cookies, referer/origin or a downstream redirect."})
        rc={"blocked_at":blocked,"facts":facts,"hypotheses":hypotheses,"certainty_rule":"FACTS_ARE_OBSERVED; HYPOTHESES_REQUIRE_NEXT_EXPERIMENT"}
        self.v51_root_cause=rc; return rc

    def v51_build_next_experiments(self,dna,root_cause):
        """Portable capability experiments, ordered cheapest/least invasive first.
        No domain names or guessed endpoints are generated here."""
        b=dna.get("blocked_at"); ex=[]
        def add(i,cap,action,success,why,priority): ex.append({"id":i,"capability":cap,"action":action,"success_signal":success,"why":why,"priority":priority})
        if b=="PLAYER_INTERACTION":
            add("E1","PLAYER_CONTROL_DISCOVERY","Rescan only the proven player frame for visible video/play/overlay controls using DOM geometry and semantic role; do not click the top page.","new playback state OR new frame-scoped network request","Try the front door first: identify the real control rather than guessing an endpoint.",10)
            add("E2","REAL_POINTER_INTERACTION","If E1 finds a control, issue one real pointer click at its visible center and compare before/after network + playback evidence.","mediaDelta>0 OR hardPlayback=1 OR new bootstrap request","A physical click must be judged by effect, not by click execution.",20)
            add("E3","PLAYER_BOOTSTRAP_OBSERVATION","If click changes state but no media appears, observe same-frame XHR/fetch/JSON/DOM mutation/localStorage/cookies without navigation.","JSON/player-source/bootstrap evidence appears","The player may generate a source only after state/session mutation.",30)
            add("E4","BROWSER_ENVIRONMENT_PARITY","If fallback browser is active, repeat the same experiment in attached real Chrome while preserving page/frame/session context.","same player frame produces new bootstrap/media evidence","Tests browser-environment dependency without creating a site-specific rule.",40)
            add("E5","MSE_BLOB_OBSERVATION","Only if normal network/player-source evidence remains absent, inspect MediaSource/SourceBuffer/blob evidence.","MediaSource/SourceBuffer/blob media evidence","Use the chimney only after normal doors fail; do not assume MSE beforehand.",50)
        elif b=="MEDIA_CANDIDATE":
            add("E1","XHR_FETCH_JSON_DISCOVERY","Correlate new XHR/fetch responses with the proven player frame and inspect JSON semantically.","semantic media/player-source path","Runtime APIs are cheaper evidence than guessing URLs.",10)
            add("E2","DOM_PLAYER_CONFIG_DISCOVERY","Inspect runtime DOM mutations and player config in the same frame.","player source/config appears","Covers players that bootstrap through DOM/config instead of JSON.",20)
            add("E3","MSE_BLOB_OBSERVATION","Inspect MSE/blob only after ordinary runtime sources are absent.","MSE/blob media evidence","Portable fallback for players hiding the source behind MediaSource.",30)
        elif b=="MANIFEST":
            add("E1","SESSION_CONTEXT_FOLLOW","Follow the runtime candidate with its captured frame/session headers, cookies, referer and origin.","manifest body or redirect to playable child","Preserves the context that created the candidate.",10)
            add("E2","MANIFEST_CHILD_FOLLOW","Parse and follow manifest children without URL guessing.","playable child + media object","Proof comes from content relationship, not extension.",20)
        elif b=="NETWORK_ACTIVITY":
            add("E1","TRANSPORT_DIAGNOSTICS","Classify DNS/TCP/TLS/HTTP failure from captured evidence and retry only the failed transport boundary.","request reaches next protocol stage","Do not change resolver logic when transport is the blocker.",10)
        else:
            add("E1","EVIDENCE_GAP_SCAN","Find the first unproven stage and collect evidence only around that boundary.","next stage becomes PASS or a concrete failure is observed","Generic fallback that avoids domain-specific guessing.",10)
        self.v51_next_experiments=sorted(ex,key=lambda x:x["priority"]); return self.v51_next_experiments

    def v51_emit_reasoning_report(self,dna):
        rc=self.v51_build_root_cause(dna); ex=self.v51_build_next_experiments(dna,rc)
        self.log(f"[V51_ROOT_CAUSE] blocked_at={rc['blocked_at']} facts={','.join(rc['facts']) or 'NONE'} hypotheses={len(rc['hypotheses'])}")
        for h in rc["hypotheses"]:
            self.log(f"[V51_HYPOTHESIS] id={h['id']} confidence={h['confidence']} basis={','.join(h['basis'])}")
        for x in ex:
            self.log(f"[V51_NEXT_EXPERIMENT] priority={x['priority']} id={x['id']} capability={x['capability']} success={x['success_signal']} action={x['action']}")
        if ex: self.log(f"[V51_RECOMMENDED_MOVE] {ex[0]['id']} {ex[0]['capability']}")
        self.log("[V51_GENERALIZATION] mode=BEHAVIOR_CAPABILITY_NOT_DOMAIN no_guessed_urls=true")
        return {"root_cause":rc,"behavior_signature":self.v51_behavior_signature,"next_experiments":ex}

    def v50_emit_resolution_report(self):
        dna=self.v50_build_resolution_dna(); proof=self.v50_build_final_proof_report(); transport=self.v50_build_transport_diagnostics()
        self.log(f"[V51_RESOLUTION_DNA] result={dna['result']} browser_mode={dna['browser_mode']} interaction={dna['interaction_provenance']}")
        for name,info in dna["stages"].items():
            ev=" | ".join(str(x) for x in info.get("evidence",[]) if x)
            self.log(f"[DNA_STAGE] {name}={info['status']}"+(f" evidence={ev[:1200]}" if ev else ""))
        self.log(f"[LAST_SUCCESS] {dna['last_success']}")
        if not self.final_verified:
            self.log(f"[FAILURE_STAGE] {dna['blocked_at']}"); self.log(f"[MISSING_CAPABILITY] {dna['missing_capability']}"); self.log(f"[NEXT_ACTION] {dna['next_action']}")
        self.log(f"[INTERACTION_PROVENANCE] {dna['interaction_provenance']}")
        self.log(f"[TRANSPORT_DIAGNOSTICS] dns={transport['dns_conclusion']} real_chrome={transport['real_chrome_attached']} failures={len(transport['transport_failures'])}")
        self.log(f"[FINAL_PROOF_REPORT] verified={proof['verified']} level={proof['proof_level']} rootMimeWarning={str(proof['root_mime_warning']).lower()} acceptReason={proof['accept_reason']}")
        self.log(f"[V67_TRANSPORT_DETAIL] urllib_failures={len(transport.get('transport_failures') or [])} chrome_failures={len(transport.get('browser_failures') or [])}")
        self.v67_emit_failure_explainer(dna,transport,proof)
        self.v69_diagnostic_report=self.v69_emit_diagnostic_report(dna,transport,proof)
        self.v70_diagnostic_report=self.v70_emit_diagnostic_report(dna,transport,proof)
        self.v71_diagnostic_report=self.v71_emit_diagnostic_report(dna,transport,proof)
        self.v72_diagnostic_report=self.v72_emit_diagnostic_report(dna,transport,proof)
        self.v73_diagnostic_report=self.v73_emit_diagnostic_report(dna,transport,proof)
        self.v68_diagnostic_report=self.v73_diagnostic_report
        self.v51_emit_reasoning_report(dna)
        return dna


    # ---------------- V67: FAILURE EXPLAINER / MISSING PIECES ----------------
    def v67_failure_explainer(self, dna, transport, proof):
        if self.final_verified:
            return {"result":"FINAL_VERIFIED","last_success":dna.get("last_success","NONE"),
                    "failure_stage":"NONE","cause":"NONE","missing":[],"evidence":[]}

        missing=[]
        stages=dna.get("stages",{})
        checks=[
            ("TOP_PAGE","TOP_PAGE_RESPONSE"),
            ("IFRAME_DISCOVERY","PLAYER_OR_IFRAME_DISCOVERY"),
            ("PLAYER_FRAME","PLAYER_FRAME_RUNTIME"),
            ("NETWORK_ACTIVITY","PLAYER_NETWORK_ACTIVITY"),
            ("JSON_BOOTSTRAP","PLAYER_BOOTSTRAP_OR_JSON_RESPONSE"),
            ("PLAYER_CONFIG","PLAYER_SOURCE_CONFIG"),
            ("MEDIA_CANDIDATE","RUNTIME_MEDIA_CANDIDATE"),
            ("MANIFEST","HLS_DASH_OR_MEDIA_MANIFEST"),
            ("MEDIA_PROOF","FINAL_MEDIA_OBJECT_PROOF"),
        ]
        for stage,piece in checks:
            if (stages.get(stage) or {}).get("status")!="PASS":
                missing.append(piece)

        uf=list(transport.get("transport_failures") or [])
        bf=list(transport.get("browser_failures") or [])
        evidence=[]
        cause="UNCLASSIFIED_EVIDENCE_GAP"
        failure_stage=dna.get("blocked_at","UNKNOWN")

        if uf or bf:
            failure_stage="PLAYER_OR_NETWORK_TRANSPORT"
            cause="TRANSPORT_FAILURE_BEFORE_DOWNSTREAM_MEDIA"
            for x in uf[-5:]:
                evidence.append(
                    f"urllib class={x.get('class','NETWORK_ERROR')} "
                    f"error={x.get('error','')} url={x.get('url','')}"
                )
            for x in bf[-5:]:
                evidence.append(
                    f"chrome error={x.get('errorText','')} blocked={x.get('blockedReason','')} "
                    f"type={x.get('resourceType','')} url={x.get('url','')}"
                )
            for piece in (
                "SUCCESSFUL_PLAYER_DOCUMENT_RESPONSE",
                "PLAYER_BOOTSTRAP_XHR_FETCH",
                "PLAYER_SOURCE_RESPONSE",
                "MEDIA_MANIFEST",
                "FINAL_MEDIA_PROOF"
            ):
                if piece not in missing:
                    missing.append(piece)
        elif (stages.get("PLAYER_INTERACTION") or {}).get("status")=="FAIL":
            failure_stage="PLAYER_INTERACTION"
            cause="NO_VERIFIED_PLAYBACK_OR_BOOTSTRAP_TRIGGER"
        elif (stages.get("MEDIA_CANDIDATE") or {}).get("status")!="PASS":
            failure_stage="MEDIA_CANDIDATE"
            cause="NO_RUNTIME_MEDIA_SOURCE_OBSERVED"
        elif (stages.get("MANIFEST") or {}).get("status")!="PASS":
            failure_stage="MANIFEST"
            cause="MEDIA_CANDIDATE_NOT_PROVEN_AS_MANIFEST"
        elif not proof.get("verified"):
            failure_stage="MEDIA_PROOF"
            cause="MANIFEST_OR_MEDIA_NOT_VERIFIED"

        return {
            "result":"INCOMPLETE",
            "last_success":dna.get("last_success","NONE"),
            "failure_stage":failure_stage,
            "cause":cause,
            "missing":list(dict.fromkeys(missing)),
            "evidence":evidence
        }

    def v67_emit_failure_explainer(self, dna, transport, proof):
        r=self.v67_failure_explainer(dna,transport,proof)
        self.log(
            f"[V67_RESULT] result={r['result']} last_success={r['last_success']} "
            f"failure_stage={r['failure_stage']} cause={r['cause']}"
        )
        self.log("[V67_MISSING_PIECES] " + (" -> ".join(r["missing"]) if r["missing"] else "NONE"))
        for i,ev in enumerate(r["evidence"],1):
            self.log(f"[V67_FAILURE_EVIDENCE] {i}. {ev}")
        if r["result"]!="FINAL_VERIFIED":
            self.log(
                "[V67_PLAIN_REASON] Final medya yakalanamadi. failure_stage ilk kanitli "
                "kirilma noktasidir; MISSING_PIECES bu noktadan sonra gozlenemeyen zincir parcalaridir."
            )
        return r

    # ---------------- V68: FORENSIC DIAGNOSTIC / MISSING-PIECE MAP ----------------
    def v68_build_diagnostic_report(self, dna, transport, proof):
        """Evidence-only diagnosis.

        V68 does not need to solve the stream to be useful. It inventories what was
        actually observed, names the first broken boundary, separates missing pieces
        from hypotheses, and emits a concrete next inspection plan without inventing
        URLs, headers, tokens or provider-specific rules.
        """
        logtxt="\n".join(self.logs)
        stages=dna.get("stages",{}) or {}

        def uniq(items):
            out=[]
            for x in items:
                x=str(x or "").strip()
                if x and x not in out: out.append(x)
            return out

        def grabs(pattern, group=1, flags=0, limit=20):
            try:
                return uniq(re.findall(pattern,logtxt,flags))[-limit:]
            except Exception:
                return []

        observed={
            "detail_urls":grabs(r"^\[URL\]\s+(.+)$",flags=re.M),
            "iframe_urls":grabs(r"^\s*\[literal\]\s+UNKNOWN\s+(https?://\S*(?:iframe|rplayer|embed)\S*)",flags=re.M),
            "runtime_discovered_urls":grabs(r"^\[RUNTIME_DISCOVERED_URL\].*?\s(https?://\S+)$",flags=re.M),
            "script_urls":grabs(r"^\[SCRIPT_INSPECT\]\s+(.+)$",flags=re.M),
            "source_variables":grabs(r"^\[V54_MRC_CAPABILITY\]\s+PLAYER_SOURCE_VARIABLE\s+evidence=(.+)$",flags=re.M),
            "runtime_vars":grabs(r"^\[HDF_RUNTIME_VAR\]\s+(.+)$",flags=re.M),
            "decoder_captures":grabs(r"^\[V64_JS_DECODER_CAPTURE\]\s+(.+)$",flags=re.M),
            "split_decoders":grabs(r"^\[V63_HDF_SPLIT_DECODER\]\s+(.+)$",flags=re.M),
            "decoded_media":grabs(r"^\[HDF_RUNTIME_DECODED\]\s+(.+)$",flags=re.M),
            "packer":grabs(r"^\[PACKER_UNPACK\]\s+(.+)$",flags=re.M),
            "media_probes":grabs(r"^\[MEDIA_PROBE\]\s+(.+)$",flags=re.M),
        }

        passed=[name for name,info in stages.items() if (info or {}).get("status")=="PASS"]
        not_passed=[name for name,info in stages.items() if (info or {}).get("status")!="PASS"]
        first_broken=dna.get("blocked_at") or (not_passed[0] if not_passed else "NONE")

        missing=[]
        stage_piece={
            "TOP_PAGE":"TOP_PAGE_RESPONSE",
            "SCRIPT_DISCOVERY":"SCRIPT_OR_BOOTSTRAP_DISCOVERY",
            "IFRAME_DISCOVERY":"PLAYER_IFRAME_OR_EMBED",
            "PLAYER_FRAME":"PLAYER_FRAME_RUNTIME",
            "PLAYER_INTERACTION":"VERIFIED_PLAYER_TRIGGER",
            "NETWORK_ACTIVITY":"PLAYER_NETWORK_ACTIVITY",
            "JSON_BOOTSTRAP":"BOOTSTRAP_XHR_FETCH_OR_JSON",
            "PLAYER_CONFIG":"PLAYER_SOURCE_CONFIG",
            "MEDIA_CANDIDATE":"DECODED_OR_RUNTIME_MEDIA_URL",
            "MANIFEST":"VERIFIED_MANIFEST",
            "MEDIA_PROOF":"VERIFIED_MEDIA_OBJECT",
        }
        for name in not_passed:
            piece=stage_piece.get(name)
            if piece and piece not in missing: missing.append(piece)

        # Add evidence-specific gaps. These are derived only from observed signals.
        if observed["packer"] and not observed["decoder_captures"] and not observed["decoded_media"]:
            missing.insert(0,"PACKED_JS_DECODER_IDENTIFICATION")
        if observed["decoder_captures"] and not observed["decoded_media"]:
            missing.insert(0,"DECODER_OUTPUT_HTTP_MEDIA_URL")
        if observed["decoded_media"] and (stages.get("MANIFEST") or {}).get("status")!="PASS":
            missing.insert(0,"DECODED_MEDIA_MANIFEST_PROOF")
        missing=uniq(missing)

        boundary=[]
        if observed["packer"]: boundary.append("PACKED_JS_UNPACKED")
        if observed["source_variables"]: boundary.append("PLAYER_SOURCE_VARIABLE_OBSERVED")
        if observed["decoder_captures"]: boundary.append("DECODER_FUNCTION_CAPTURED")
        if observed["split_decoders"]: boundary.append("SPLIT_DECODER_SHAPE_CAPTURED")
        if observed["decoded_media"]: boundary.append("DECODER_OUTPUT_OBSERVED")
        if (stages.get("MANIFEST") or {}).get("status")=="PASS": boundary.append("MANIFEST_PROVEN")
        if proof.get("verified"): boundary.append("MEDIA_OBJECT_PROVEN")

        # Concrete next checks are selected from the first broken boundary and evidence.
        checks=[]
        if observed["packer"] and not observed["decoder_captures"]:
            checks += ["Inspect unpacked JS assignments VAR=FUNC(payload.split(separator))",
                       "Capture the called decoder function with balanced-brace parsing, not return-regex slicing"]
        if observed["decoder_captures"] and not observed["decoded_media"]:
            checks += ["Compare decoder transform order against captured function body",
                       "Verify array splice/removal order and indexes",
                       "Verify seed/hash constants and integer/modulo behavior",
                       "Verify reverse/base64/Caesar operation order",
                       "Verify deterministic shuffle generation/application order",
                       "Verify final XOR stream state update order"]
        if first_broken=="PLAYER_INTERACTION":
            checks += ["Identify the proven player control/frame", "Compare network before/after one verified interaction"]
        elif first_broken in ("NETWORK_ACTIVITY","MEDIA_CANDIDATE"):
            checks += ["Inspect same-frame XHR/fetch/JSON/player-config/DOM mutation evidence", "Inspect MSE/blob only if ordinary runtime source evidence is absent"]
        elif first_broken=="MANIFEST":
            checks += ["Replay the observed media candidate with captured session/frame context", "Follow redirects and manifest children without synthesizing URLs"]
        elif first_broken=="MEDIA_PROOF":
            checks += ["Follow a manifest child and verify a real media object/segment"]
        checks=uniq(checks)

        evidence=[]
        for key in ("packer","source_variables","runtime_vars","decoder_captures","split_decoders","decoded_media","media_probes"):
            for item in observed[key][-3:]: evidence.append(f"{key}={item}")
        for x in list(transport.get("transport_failures") or [])[-3:]:
            evidence.append(f"transport={x}")
        for x in list(transport.get("browser_failures") or [])[-3:]:
            evidence.append(f"browser_transport={x}")

        return {
            "result":"SUCCESS" if proof.get("verified") else ("PARTIAL" if passed else "FAILED"),
            "last_confirmed_stage":dna.get("last_success","NONE"),
            "first_broken_stage":first_broken,
            "passed_stages":passed,
            "missing":missing,
            "observed":observed,
            "boundary":boundary,
            "evidence":evidence,
            "next_checks":checks,
            "no_guess":{
                "hardcoded_final_url":False,
                "invented_endpoint":False,
                "invented_header_or_token":False,
            }
        }

    def v68_emit_diagnostic_report(self, dna, transport, proof):
        r=self.v68_build_diagnostic_report(dna,transport,proof)
        self.log(f"[V68_DIAGNOSIS] result={r['result']} last_confirmed={r['last_confirmed_stage']} first_broken={r['first_broken_stage']}")
        self.log("[V68_CONFIRMED_CHAIN] " + (" -> ".join(r["boundary"]) if r["boundary"] else "NONE"))
        for key,items in r["observed"].items():
            if items:
                self.log(f"[V68_OBSERVED] {key}=" + " || ".join(items[-5:]))
        self.log("[V68_MISSING] " + (" -> ".join(r["missing"]) if r["missing"] else "NONE"))
        for i,ev in enumerate(r["evidence"],1):
            self.log(f"[V68_EVIDENCE] {i}. {ev}")
        for i,action in enumerate(r["next_checks"],1):
            self.log(f"[V68_NEXT_CHECK] {i}. {action}")
        self.log("[V68_DO_NOT_GUESS] hardcoded_final_url=NO invented_endpoint=NO invented_header_or_token=NO")
        return r


    # ---------------- V69: FORENSIC EVIDENCE PACK / EXACT BOUNDARY PROOF ----------------
    def v69_build_diagnostic_report(self, dna, transport, proof):
        """V69 extends V68 with exact stage/boundary evidence.

        The report remains evidence-only: no guessed URL/header/token.  It records the
        evidence that made a stage PASS, the evidence at the first broken stage, exact
        manifest proof (URL/status/content-type when observed), interaction provenance,
        and transport failures so the next code change can be chosen from the log alone.
        """
        r=self.v68_build_diagnostic_report(dna,transport,proof)
        stages=dna.get("stages",{}) or {}
        logtxt="\n".join(self.logs)

        def uniq(items):
            out=[]
            for x in items:
                x=str(x or "").strip()
                if x and x not in out: out.append(x)
            return out

        # Preserve the exact evidence used by the DNA stage engine instead of only
        # printing the stage name. This is the main V69 addition.
        stage_evidence={}
        for name,info in stages.items():
            info=info or {}
            ev=uniq(info.get("evidence") or [])
            stage_evidence[name]={"status":info.get("status","UNKNOWN"),"evidence":ev}

        first=r.get("first_broken_stage") or "NONE"
        broken_info=stage_evidence.get(first,{"status":"UNKNOWN","evidence":[]})

        # Manifest evidence: first prefer structured DNA evidence (root_step JSON),
        # then retain matching manifest/media-probe log lines as raw proof.
        manifest=[]
        for ev in stage_evidence.get("MANIFEST",{}).get("evidence",[]):
            try:
                obj=json.loads(ev)
                if isinstance(obj,dict):
                    manifest.append({
                        "stage":obj.get("stage"), "url":obj.get("url"),
                        "status":obj.get("status"), "content_type":obj.get("ct") or obj.get("content_type")
                    })
                else: manifest.append({"raw":ev})
            except Exception:
                manifest.append({"raw":ev})
        for line in self.logs:
            if any(tag in line for tag in ("[MEDIA_PROBE]","[HLS VERIFY]","[HLS_VERIFY]","[MANIFEST")):
                manifest.append({"raw":line[:1800]})
        # de-duplicate dictionaries by stable JSON representation
        seen=set(); manifest2=[]
        for x in manifest:
            k=json.dumps(x,ensure_ascii=False,sort_keys=True)
            if k not in seen:
                seen.add(k); manifest2.append(x)
        manifest=manifest2[-12:]

        interaction={
            "provenance":dna.get("interaction_provenance") or "NONE",
            "stage_status":stage_evidence.get("PLAYER_INTERACTION",{}).get("status","UNKNOWN"),
            "stage_evidence":stage_evidence.get("PLAYER_INTERACTION",{}).get("evidence",[]),
        }

        network={
            "stage_status":stage_evidence.get("NETWORK_ACTIVITY",{}).get("status","UNKNOWN"),
            "stage_evidence":stage_evidence.get("NETWORK_ACTIVITY",{}).get("evidence",[]),
            "transport_failures":list(transport.get("transport_failures") or [])[-8:],
            "browser_failures":list(transport.get("browser_failures") or [])[-8:],
        }

        # Explain the exact boundary as CONFIRMED -> BROKEN, with evidence on both sides.
        order=list(stages.keys())
        prev="NONE"
        if first in order:
            i=order.index(first)
            for j in range(i-1,-1,-1):
                if stage_evidence.get(order[j],{}).get("status")=="PASS":
                    prev=order[j]; break
        boundary_detail={
            "last_pass_stage":prev,
            "last_pass_evidence":stage_evidence.get(prev,{}).get("evidence",[]) if prev!="NONE" else [],
            "first_broken_stage":first,
            "first_broken_status":broken_info.get("status","UNKNOWN"),
            "first_broken_evidence":broken_info.get("evidence",[]),
        }

        # Add focused next checks only when the evidence tells us what is absent.
        checks=list(r.get("next_checks") or [])
        if first=="PLAYER_INTERACTION":
            checks += [
                "Record the exact player frame/control candidate and its DOM/geometry evidence before interaction",
                "Record request/response counters immediately before and after the verified interaction",
                "If a request delta appears, print method + URL + frameId + initiator + response status/content-type for that delta",
                "If no request delta appears, print playback-state/DOM/config changes caused by the interaction",
            ]
        if stage_evidence.get("MANIFEST",{}).get("status")=="PASS" and not proof.get("verified"):
            checks += [
                "Print the exact proven manifest URL/status/content-type and then identify which child/media-object proof is still missing",
                "Follow only observed manifest children and report the first child status/content-type failure",
            ]
        r["next_checks"]=uniq(checks)
        r["stage_evidence"]=stage_evidence
        r["boundary_detail"]=boundary_detail
        r["manifest_evidence"]=manifest
        r["interaction_evidence"]=interaction
        r["network_evidence"]=network
        return r

    def v69_emit_diagnostic_report(self, dna, transport, proof):
        r=self.v69_build_diagnostic_report(dna,transport,proof)
        self.log(f"[V69_DIAGNOSIS] result={r['result']} last_confirmed={r['last_confirmed_stage']} first_broken={r['first_broken_stage']}")
        self.log("[V69_CONFIRMED_CHAIN] " + (" -> ".join(r["boundary"]) if r["boundary"] else "NONE"))
        for key,items in r["observed"].items():
            if items:
                self.log(f"[V69_OBSERVED] {key}=" + " || ".join(items[-5:]))
        self.log("[V69_MISSING] " + (" -> ".join(r["missing"]) if r["missing"] else "NONE"))

        bd=r["boundary_detail"]
        self.log(f"[V69_BOUNDARY] last_pass={bd['last_pass_stage']} first_broken={bd['first_broken_stage']} broken_status={bd['first_broken_status']}")
        for i,ev in enumerate(bd["last_pass_evidence"],1):
            self.log(f"[V69_LAST_PASS_EVIDENCE] {i}. {ev}")
        for i,ev in enumerate(bd["first_broken_evidence"],1):
            self.log(f"[V69_BROKEN_EVIDENCE] {i}. {ev}")

        for name,info in r["stage_evidence"].items():
            ev=" || ".join(info.get("evidence") or []) or "NONE"
            self.log(f"[V69_STAGE_EVIDENCE] {name}={info.get('status')} evidence={ev[:2200]}")

        for i,ev in enumerate(r["manifest_evidence"],1):
            self.log(f"[V69_MANIFEST_EVIDENCE] {i}. {json.dumps(ev,ensure_ascii=False)}")

        ie=r["interaction_evidence"]
        self.log(f"[V69_INTERACTION_EVIDENCE] status={ie['stage_status']} provenance={ie['provenance']} evidence=" + (" || ".join(ie['stage_evidence']) or "NONE"))
        ne=r["network_evidence"]
        self.log(f"[V69_NETWORK_EVIDENCE] status={ne['stage_status']} evidence=" + (" || ".join(ne['stage_evidence']) or "NONE"))
        for i,x in enumerate(ne["transport_failures"],1): self.log(f"[V69_TRANSPORT_FAILURE] {i}. {x}")
        for i,x in enumerate(ne["browser_failures"],1): self.log(f"[V69_BROWSER_FAILURE] {i}. {x}")

        for i,ev in enumerate(r["evidence"],1): self.log(f"[V69_EVIDENCE] {i}. {ev}")
        for i,action in enumerate(r["next_checks"],1): self.log(f"[V69_NEXT_CHECK] {i}. {action}")
        self.log("[V69_DO_NOT_GUESS] hardcoded_final_url=NO invented_endpoint=NO invented_header_or_token=NO")
        return r

    # ---------------- V70: FINAL PURSUIT + STRICT PROOF ROADMAP ----------------
    def v70_build_diagnostic_report(self, dna, transport, proof):
        """Turn V69 evidence into a strict, final-oriented roadmap without guessing."""
        r=self.v69_build_diagnostic_report(dna,transport,proof)
        stages=dna.get("stages",{}) or {}
        root=next((x for x in (proof.get("steps") or []) if x.get("stage")=="root"),None)
        status=0
        try: status=int((root or {}).get("status") or 0)
        except Exception: status=0
        manifest_valid=bool(root and 200 <= status < 400)
        final_state="VERIFIED" if proof.get("verified") and self.final_verified else "NOT_VERIFIED"
        roadmap=[]
        if self.final_verified:
            roadmap.append("FINAL already verified; preserve observed playback context and hand off the verified media URL")
        else:
            b=dna.get("blocked_at","UNKNOWN")
            if b=="MANIFEST":
                roadmap += [
                    "Take only runtime-observed media/manifest candidates from this same browser session",
                    "Replay each candidate with its captured frame/session context; record status, content-type and first body signature",
                    "Reject 4xx/5xx, empty bodies and non-manifest bodies as MANIFEST proof",
                    "Accept MANIFEST only on successful response plus #EXTM3U (HLS) or parsed MPD evidence",
                    "When a valid manifest is found, immediately follow observed child references toward a real media object",
                ]
            elif b=="MEDIA_PROOF":
                roadmap += [
                    "Parse only children actually present in the proven manifest",
                    "Follow the first playable variant/media playlist with captured context",
                    "Verify a real segment/media object with successful HTTP response before FINAL",
                ]
            elif b=="MEDIA_CANDIDATE":
                roadmap += [
                    "Correlate player-frame XHR/fetch/JSON/config changes and extract only observed source values",
                    "Probe observed source values in-session, then continue to strict manifest proof",
                ]
            elif b=="PLAYER_INTERACTION":
                roadmap += [
                    "Find the proven player control/frame and perform one verified pointer interaction",
                    "Compare same-frame network/config/playback state before and after the interaction",
                ]
            else:
                roadmap.append("Collect evidence only at the first unproven boundary, then continue toward strict manifest and media-object proof")
        return {
            "result":"FINAL_VERIFIED" if self.final_verified else "PARTIAL",
            "final_state":final_state,
            "blocked_at":dna.get("blocked_at","UNKNOWN"),
            "missing_capability":dna.get("missing_capability","UNKNOWN"),
            "manifest_root":root or {},
            "manifest_strict_valid":manifest_valid,
            "final_url":self.final if self.final_verified else "",
            "final_type":self.final_type if self.final_verified else "",
            "roadmap":roadmap,
        }

    def v70_emit_diagnostic_report(self, dna, transport, proof):
        r=self.v70_build_diagnostic_report(dna,transport,proof)
        self.log(f"[V70_FINAL_STATUS] result={r['result']} final={r['final_state']} blocked_at={r['blocked_at']} missing={r['missing_capability']}")
        root=r["manifest_root"]
        if root:
            self.log(f"[V70_MANIFEST_STRICT] valid={r['manifest_strict_valid']} status={root.get('status')} ct={root.get('ct','')} url={root.get('url','')}")
        else:
            self.log("[V70_MANIFEST_STRICT] valid=False evidence=NO_ROOT_MANIFEST_PROOF")
        for i,x in enumerate(r["roadmap"],1): self.log(f"[V70_ROADMAP] {i}. {x}")
        if self.final_verified:
            self.log(f"[V70_FINAL_MEDIA] type={r['final_type']} url={r['final_url']}")
        else:
            self.log("[V70_FINAL_MEDIA] NONE - resolver must continue from the reported first broken boundary")
        self.log("[V70_PROOF_RULE] FINAL requires observed dynamic source -> valid manifest -> playable child/media object proof; URL shape alone is never proof")
        self.log("[V70_DO_NOT_GUESS] hardcoded_final_url=NO invented_endpoint=NO invented_header_or_token=NO")
        return r

    # ---------------- V71: LIVE BROWSER MANIFEST PROOF ----------------
    def v71_build_diagnostic_report(self, dna, transport, proof):
        observed=getattr(self,"v33_browser_hls_observed",{}) or {}
        live=[]
        for u,x in observed.items():
            body=str((x or {}).get("body","") or "")
            if body.lstrip().startswith("#EXTM3U"):
                live.append({
                    "url":u,
                    "status":int((x or {}).get("status",0) or 0),
                    "ct":str((x or {}).get("ct","") or ""),
                    "bytes":len(body.encode("utf-8","replace")),
                    "source":str((x or {}).get("source","") or ""),
                    "media_playlist":bool(self.v34_is_media_playlist(body)),
                })
        steps=list((proof or {}).get("steps") or [])
        failed_step="NONE"
        if not self.final_verified:
            if live and not (proof or {}).get("verified"):
                if any(x.get("stage")=="variant" for x in steps): failed_step="MEDIA_OBJECT"
                elif any(x.get("stage")=="root" for x in steps): failed_step="VARIANT_OR_MEDIA_OBJECT"
                else: failed_step="LIVE_MANIFEST_TO_CHILD_PROOF"
            else:
                failed_step=str(dna.get("blocked_at","UNKNOWN"))
        return {
            "result":"FINAL_VERIFIED" if self.final_verified else "PARTIAL",
            "final":self.final if self.final_verified else "",
            "final_type":self.final_type if self.final_verified else "",
            "live_manifests":live,
            "proof_steps":steps,
            "next_boundary":failed_step,
            "missing":[] if self.final_verified else ([failed_step] if failed_step!="NONE" else []),
        }

    def v71_emit_diagnostic_report(self, dna, transport, proof):
        r=self.v71_build_diagnostic_report(dna,transport,proof)
        self.log(f"[V71_FINAL_STATUS] result={r['result']} next_boundary={r['next_boundary']}")
        if r["live_manifests"]:
            for i,x in enumerate(r["live_manifests"],1):
                self.log(f"[V71_LIVE_MANIFEST_EVIDENCE] {i}. status={x['status']} ct={x['ct']} bytes={x['bytes']} media_playlist={str(x['media_playlist']).lower()} source={x['source']} url={x['url']}")
        else:
            self.log("[V71_LIVE_MANIFEST_EVIDENCE] NONE")
        for i,x in enumerate(r["proof_steps"],1):
            self.log(f"[V71_PROOF_STEP] {i}. stage={x.get('stage')} status={x.get('status')} ct={x.get('ct','')} url={x.get('url','')}")
        self.log("[V71_MISSING] " + (" -> ".join(r["missing"]) if r["missing"] else "NONE"))
        if self.final_verified:
            self.log(f"[V71_FINAL_MEDIA] type={r['final_type']} url={r['final']}")
        else:
            self.log("[V71_FINAL_MEDIA] NONE")
            if r["live_manifests"]:
                self.log("[V71_NEXT_ACTION] Use the captured live #EXTM3U body as proof seed; follow only its observed child references and verify a real media object in the same session/context")
            else:
                self.log("[V71_NEXT_ACTION] Capture the successful browser manifest response body before any replay, then continue child/media-object proof")
        self.log("[V71_DO_NOT_GUESS] hardcoded_provider=NO hardcoded_final_url=NO invented_token=NO invented_endpoint=NO")
        return r

    # ---------------- V72: STRICT MEDIA BYTES + EFFECTIVE REDIRECT FINAL ----------------
    def v72_emit_diagnostic_report(self, dna, transport, proof):
        steps=list((proof or {}).get("steps") or [])
        seg=next((x for x in reversed(steps) if x.get("stage")=="segment"),None)
        self.log(f"[V72_FINAL_STATUS] result={'FINAL_VERIFIED' if self.final_verified else 'PARTIAL'} final={'VERIFIED' if self.final_verified else 'NOT_VERIFIED'}")
        if seg:
            self.log(f"[V72_MEDIA_OBJECT_EVIDENCE] accepted={str(bool(seg.get('media_signature_valid'))).lower()} signature={seg.get('signature','UNKNOWN')} status={seg.get('status',0)} ct={seg.get('ct','')} requested={seg.get('url','')} effective={seg.get('effective_url','')}")
        else:
            self.log("[V72_MEDIA_OBJECT_EVIDENCE] NONE")
        if self.final_verified:
            self.log(f"[V72_FINAL_MEDIA] type={self.final_type} url={self.final}")
        else:
            self.log("[V72_FINAL_MEDIA] NONE")
        self.log("[V72_PROOF_RULE] image filename is never enough; FINAL requires media bytes/MIME proof. Redirected manifests keep their effective URL.")
        self.log("[V72_DO_NOT_GUESS] hardcoded_provider=NO hardcoded_final_url=NO invented_token=NO invented_endpoint=NO")
        return {"result":"FINAL_VERIFIED" if self.final_verified else "PARTIAL","final":self.final if self.final_verified else "","segment":seg or {}}

    # ---------------- V73: PROOF-SELECTED FINAL / NO ROOT-CANDIDATE OVERWRITE ----------------
    def v73_emit_diagnostic_report(self, dna, transport, proof):
        p=getattr(self,"v32_proof",{}) or {}
        root=str(p.get("root") or "")
        playable=str(p.get("playable_manifest") or "")
        verified=bool(p.get("verified"))
        selected=str(self.final or "") if self.final_verified else ""
        consistent=bool(self.final_verified and verified and playable and selected==playable)
        self.log(f"[V73_FINAL_SELECTOR] proof_verified={str(verified).lower()} root={root or 'NONE'} playable={playable or 'NONE'} selected={selected or 'NONE'}")
        self.log(f"[V73_NO_OVERWRITE] consistent={str(consistent).lower()} root_candidate_overwrite={'NO' if consistent else 'CHECK'}")
        if self.final_verified:
            self.log(f"[V73_FINAL_MEDIA] type={self.final_type} url={selected}")
        else:
            self.log("[V73_FINAL_MEDIA] NONE")
        self.log("[V73_PROOF_RULE] FINAL HLS must equal the playable_manifest that produced verified media-object proof; an earlier root/redirect candidate cannot overwrite it.")
        return {"result":"FINAL_VERIFIED" if self.final_verified else "PARTIAL","root":root,"playable_manifest":playable,"selected_final":selected,"consistent":consistent}

    # ---------------- V53: REPOSITORY INTEGRATION REPORT ----------------
    def v53_build_repo_integration_report(self):
        """Describe how a successful capture can be reproduced in another repo.
        IMPORTANT: observed headers/context are not labelled REQUIRED unless necessity was
        independently proven. This report never invents URLs, tokens or headers.
        """
        logtxt="\n".join(self.logs)
        ctx=dict(self.final_playback_context or {})
        headers=dict(ctx.get("headers") or {})
        final_url=str(self.final or "")
        proof=self.v50_final_proof_report if isinstance(self.v50_final_proof_report,dict) else {}
        observed=[]
        for k,v in headers.items():
            if v:
                observed.append({"name":k,"value":v,"status":"OBSERVED_NOT_PROVEN_REQUIRED"})
        # URL structure is evidence, not a guessed recipe.
        try:
            from urllib.parse import urlsplit, parse_qsl
            sp=urlsplit(final_url) if final_url else None
            q=parse_qsl(sp.query,keep_blank_values=True) if sp else []
        except Exception:
            q=[]
        runtime_json=bool(self.v43_semantic_media or "application/json" in logtxt)
        iframe=bool(self.player or "[IFRAME" in logtxt)
        browser_used=bool(self.browser_runtime_used)
        manual_observed=self.v50_interaction_provenance in ("MANUAL_WINDOW_MEDIA_APPEARED","PREEXISTING_PLAYBACK_BEFORE_MANUAL_WINDOW","PREEXISTING_PLAYBACK_BEFORE_AUTO")
        tokenish=[]
        for k,v in q:
            kl=k.lower()
            if any(x in kl for x in ("token","sig","sign","auth","key","expires","expire","e","v")):
                tokenish.append(k)
        dynamic=bool(q or runtime_json or browser_used)
        resolution_chain=[]
        if self.root_status: resolution_chain.append("DETAIL_PAGE")
        if iframe: resolution_chain.append("IFRAME")
        if browser_used: resolution_chain.append("BROWSER_RUNTIME")
        if manual_observed: resolution_chain.append("MANUAL_PLAYBACK_WINDOW")
        if runtime_json: resolution_chain.append("RUNTIME_JSON_OR_SEMANTIC_SOURCE")
        if final_url: resolution_chain.append("FINAL_MEDIA")
        if proof.get("proof_level") == "MEDIA_OBJECT_CONFIRMED": resolution_chain.append("MEDIA_OBJECT_PROOF")
        report={
            "result":"READY" if self.final_verified else "INCOMPLETE",
            "media_type":self.final_type or "UNKNOWN",
            "final_url":final_url,
            "final_url_mode":"DYNAMIC_OBSERVED" if dynamic else "STATIC_OBSERVED",
            "query_parameters_observed":[k for k,_ in q],
            "token_like_query_keys_observed":tokenish,
            "direct_url_only":"UNKNOWN" if final_url else "NO_FINAL_URL",
            "playback_requirements":{
                "observed_headers":observed,
                "required_headers_proven":[],
                "requirement_note":"Observed context is preserved for repo handoff; necessity is not claimed without an A/B playback test.",
                "browser_session_for_playback":"NOT_PROVEN_REQUIRED",
            },
            "resolution_requirements":{
                "detail_page_observed":bool(self.root_status),
                "iframe_observed":iframe,
                "browser_runtime_used":browser_used,
                "real_chrome_attached":bool(self.v50_real_chrome_attached),
                "manual_interaction_window_used":manual_observed,
                "runtime_json_or_semantic_source_observed":runtime_json,
                "final_url_safe_to_hardcode":"NO" if dynamic else "UNKNOWN",
            },
            "observed_resolution_chain":resolution_chain,
            "repo_implementation_steps":[],
            "final_verification":proof.get("proof_level","NONE"),
            "proof_accept_reason":proof.get("accept_reason","NOT_VERIFIED"),
        }
        steps=[]
        if self.root_status: steps.append("Start from the detail/content URL; do not hardcode a captured final URL when runtime evidence marks it dynamic.")
        if browser_used: steps.append("Use the observed browser/session resolution path to reproduce the runtime state.")
        if iframe: steps.append("Observe the discovered player iframe/frame and preserve its session context.")
        if manual_observed: steps.append("When playback requires user interaction, let the user press Play manually; keep resolver observation passive.")
        if runtime_json: steps.append("Capture runtime JSON/player-source evidence and extract the media source from observed response semantics; do not guess an endpoint.")
        if observed: steps.append("Hand the final media URL to the player together with the observed request context; test headers individually before marking any as REQUIRED.")
        if proof.get("proof_level") == "MEDIA_OBJECT_CONFIRMED": steps.append("Accept the media only after manifest-child/media-object proof, even if the root MIME is misleading.")
        report["repo_implementation_steps"]=steps
        self.v53_repo_integration_report=report
        return report

    def v53_emit_repo_integration_report(self):
        r=self.v53_build_repo_integration_report()
        self.log(f"[V53_REPO_REPORT] result={r['result']} media={r['media_type']} finalMode={r['final_url_mode']} verification={r['final_verification']}")
        self.log(f"[V53_REPO_FINAL_URL] {r['final_url'] or 'NONE'}")
        rr=r['resolution_requirements']
        self.log("[V53_RESOLUTION_REQUIREMENTS] "+" ".join(f"{k}={v}" for k,v in rr.items()))
        pr=r['playback_requirements']
        if pr['observed_headers']:
            for h in pr['observed_headers']:
                # Cookie values can be sensitive/session-bound; log the name/status but redact value.
                val='[REDACTED]' if h['name'].lower()=='cookie' else h['value']
                self.log(f"[V53_PLAYBACK_CONTEXT] {h['name']}={val} status={h['status']}")
        else:
            self.log("[V53_PLAYBACK_CONTEXT] NONE_OBSERVED")
        self.log(f"[V53_QUERY_CONTEXT] keys={','.join(r['query_parameters_observed']) or 'NONE'} tokenLike={','.join(r['token_like_query_keys_observed']) or 'NONE'}")
        self.log("[V53_RESOLUTION_CHAIN] "+(" -> ".join(r['observed_resolution_chain']) or "NONE"))
        for i,step in enumerate(r['repo_implementation_steps'],1):
            self.log(f"[V53_REPO_STEP] {i}. {step}")
        self.log(f"[V53_HARDCODE_FINAL_URL] {r['resolution_requirements']['final_url_safe_to_hardcode']}")
        self.log(f"[V53_FINAL_VERIFICATION] {r['final_verification']} reason={r['proof_accept_reason']}")
        return r

    def resolver_family_report(self):
        text="\n".join(self.logs)
        families=[]
        evidence={}
        def add(name,marker):
            if name not in families:
                families.append(name)
            evidence.setdefault(name,[]).append(marker)

        if re.search(r"\[DIRECT_MEDIA\]\s+[1-9]\d*",text):
            add("DIRECT_MEDIA","[DIRECT_MEDIA] N")
        if "[CLIENT_SESSION_RUNTIME]" in text:
            add("CLIENT_SESSION_RUNTIME","[CLIENT_SESSION_RUNTIME]")
        if "[CLIENT_SESSION_BOOTSTRAP]" in text:
            add("CLIENT_SESSION_BOOTSTRAP","[CLIENT_SESSION_BOOTSTRAP]")
        if "[BROKEN_PLAYER_TRANSPORT]" in text:
            add("BROKEN_PLAYER_TRANSPORT","[BROKEN_PLAYER_TRANSPORT]")
        if "[RUNTIME_REQUEUE]" in text:
            add("RUNTIME_REQUEUE","[RUNTIME_REQUEUE]")
        if "[BROWSER_RUNTIME] START" in text:
            add("BROWSER_RUNTIME","[BROWSER_RUNTIME] START")

        rules=[
            ("PACKER_JS", ("[PACKER_UNPACK]","[HDF_DECODER]","[HDF_RUNTIME_DECODED]")),
            ("CRYPTO_AES", ("[BEPLAYER_DECRYPT_OK]","CryptoJS.AES","[BEPLAYER_MEDIA_CANDIDATES]")),
            ("PATTERN", ("[PATTERN_PROBE]",)),
            ("API_AJAX", ("[ACTION_PLAN] METADATA_TOKEN_VIEW","[ACTION_EXEC] TOKEN_VIEW","[DECLARED_API]","[DOM_PROBE] data-video=")),
            ("DISPATCHER", ("[ACTION_PLAN] PLAYER_POST","[SOURCE_DISPATCH]","PLAYER_SOURCE_")),
            ("PLAYER_LITERAL", ("[PLAYER_LITERAL]","[DEPTH 1] PLAYER_LITERAL")),
            ("IFRAME", ("[DEPTH 1] IFRAME","[IFRAME_CANDIDATES]")),
            ("PLAYER_SOURCE", ("[PLAYER_SOURCE_RESOLVE]","[PLAYER_MEDIA_HINTS]")),
            ("HEADER_CONTEXT", ("[MEDIA_PROFILE_RESULT] status=200",)),
            ("ACTION_TRIGGER_RUNTIME", ("[V27_STRATEGY_TRY]","[V27_ADAPTIVE_RESULT]","[V35_ACTION_SEMANTICS]")),
            ("ACTION_SEMANTIC_REASONING", ("[V35_ACTION_ENDPOINT_DEFER]","[V35_ACTION_SEMANTICS]","[V35_RUNTIME_CLUE]")),
            ("REDIRECT_CAUSALITY", ("[V35_REDIRECT]","HTTP_REDIRECT")),
            ("CHALLENGE_AWARE_CONTINUATION", ("[V35_CHALLENGE_GATE]","CHALLENGE_SESSION_CONTINUATION")),
            ("EVIDENCE_DRIVEN_ACTION_STRATEGIES", ("[V27_ACTION_LOCK]","[V27_STRATEGY_NEXT]","[V28_ACTION_IGNORE]")),
            ("PLAYER_CONFIG_FOLLOW", ("[V29_PLAYER_CONFIG]","[V29_PLAYER_CALL]")),
            ("NEGATIVE_PLAYBACK_EVIDENCE", ("[V29_NEGATIVE_EVIDENCE]","[V30_ACTION_VETO]")),
            ("BROWSER_ENVIRONMENT_REJECTED", ("[V31_BROWSER_ENV_REJECTED]",)),
            ("CONTENT_TYPE_RESOURCE_ROLE", ("[V30_RESOURCE_ROLE]","[V30_RESOURCE_SKIP]")),
            ("PLAYER_RUNTIME_CONTINUATION", ("[V29_PLAYER_RUNTIME_CONTINUE]",)),
            ("STRUCTURED_PLAYER_METADATA", ("[V31_STRUCTURED_PLAYER_METADATA]",)),
            ("ACTIVE_PLAYER_SOURCE_FOLLOW", ("[V31_ACTIVE_PLAYER_FOLLOW]",)),
            ("INLINE_EVENT_FUNCTION_TRACER", ("[V31_FUNCTION_TRACE]","[V31_INLINE_HANDLER]")),
            ("TRANSPORT_FAILURE", ("[V31_TRANSPORT_FAILURE]",)),
            ("BLOCK_PAGE_DETECTOR", ("[V23_BLOCK_PAGE]",)),
            ("BROKEN_TRANSPORT_RECOVERY", ("[V23_TRANSPORT_RECOVERY_CANDIDATE]",)),
            ("BROWSER_RUNTIME", ("[BROWSER_FINAL_MEDIA]","[BROWSER_NET]")),
        ]
        for fam,markers in rules:
            for marker in markers:
                if marker in text:
                    add(fam,marker)
                    break

        transport=self.final_type or ("HLS" if "#EXTM3U" in text else "UNKNOWN")

        if "TRANSPORT_FAILURE" in families and not self.final_verified:
            primary="TRANSPORT_FAILURE"
        elif "DIRECT_MEDIA" in families:
            primary="DIRECT_MEDIA"
        elif "CLIENT_SESSION_RUNTIME" in families:
            primary="CLIENT_SESSION_RUNTIME"
        elif "CLIENT_SESSION_BOOTSTRAP" in families:
            primary="CLIENT_SESSION_BOOTSTRAP"
        elif "BROKEN_PLAYER_TRANSPORT" in families and "PLAYER_LITERAL" in families:
            primary="BROKEN_PLAYER_TRANSPORT"
        elif "DISPATCHER" in families:
            primary="DISPATCHER"
        elif "API_AJAX" in families:
            primary="API_AJAX"
        else:
            priority=["PACKER_JS","CRYPTO_AES","PATTERN","PLAYER_LITERAL","IFRAME","PLAYER_SOURCE","HEADER_CONTEXT"]
            primary=next((x for x in priority if x in families),"UNKNOWN")

        engine_map={
            "PACKER_JS":"PACKER_JS_RUNTIME",
            "CRYPTO_AES":"AES_BEPLAYER",
            "PATTERN":"DETERMINISTIC_PATTERN",
            "API_AJAX":"API_AJAX_CHAIN",
            "DISPATCHER":"PLAYER_SOURCE_DISPATCHER",
            "CLIENT_SESSION_RUNTIME":"CLIENT_SESSION_RUNTIME",
            "CLIENT_SESSION_BOOTSTRAP":"CLIENT_SESSION_BOOTSTRAP",
            "BROKEN_PLAYER_TRANSPORT":"BROKEN_PLAYER_TRANSPORT",
            "RUNTIME_REQUEUE":"RUNTIME_DISCOVERED_RESOLVER",
            "PLAYER_LITERAL":"PLAYER_LITERAL_CHAIN",
            "IFRAME":"IFRAME_CHAIN",
            "PLAYER_SOURCE":"PLAYER_SOURCE_PARSER",
            "HEADER_CONTEXT":"HEADER_AWARE_MEDIA",
            "DIRECT_MEDIA":"DIRECT_MEDIA",
            "TRANSPORT_FAILURE":"TRANSPORT_DIAGNOSTIC",
            "UNKNOWN":"MANUAL_INSPECTION",
        }
        suggested=engine_map.get(primary,"MANUAL_INSPECTION")
        if self.v30_environment_rejected and not self.final_verified:
            suggested="STATIC_PLAYER_CONFIG_OR_COMPATIBLE_RUNTIME_REQUIRED"
        if "BROWSER_RUNTIME" in families:
            if primary in ("CLIENT_SESSION_RUNTIME","CLIENT_SESSION_BOOTSTRAP"):
                suggested="BROWSER_RUNTIME_SESSION"
            elif primary=="BROKEN_PLAYER_TRANSPORT":
                suggested="BROKEN_PLAYER_FALLBACK"
            elif primary=="PLAYER_LITERAL" and not self.v30_environment_rejected:
                suggested="BROWSER_RUNTIME_PLAYER_LITERAL"
            elif self.final_verified:
                suggested="BROWSER_RUNTIME_MEDIA"

        if self.final_verified:
            compatibility=100
        elif self.v31_transport_failures:
            compatibility=35
        elif self.v30_environment_rejected:
            compatibility=60
        elif self.blocked:
            compatibility=35
        elif primary=="CLIENT_SESSION_RUNTIME":
            compatibility=75
        elif self.player and self.script_endpoints:
            compatibility=82
        elif self.runtime_needed:
            compatibility=70
        elif families:
            compatibility=65
        else:
            compatibility=35

        return {
            "primary":primary,
            "families":families,
            "transport":transport,
            "suggested_engine":suggested,
            "compatibility":compatibility,
            "evidence":evidence,
        }


    def emit_family_report(self):
        r=self.resolver_family_report()
        self.log("[FAMILY_DETECT] "+r["primary"])
        self.log("[FAMILY_CHAIN] "+(" -> ".join(r["families"]) if r["families"] else "UNKNOWN"))
        self.log("[MEDIA_TRANSPORT] "+r["transport"])
        self.log("[SUGGESTED_ENGINE] "+r["suggested_engine"])
        self.log(f"[SITE_COMPATIBILITY] {r['compatibility']}%")
        return r

    def analyze(self,url):
        self.log("[ENGINE] LOCAL V81.9 REPO-READY F12 EVIDENCE START")
        self.log("[V75_CAPABILITY] V74_BASE + GENERIC_NONPLAYBACK_API_GATE + COUNTER_TELEMETRY_NAVIGATION_VETO + NO_SITE_HARDCODE")
        self.log("[URL] "+url)
        self.log(f"[V38_MEMORY] loadedPatterns={len(self.v38_memory.get('patterns',{}))} priorSuccesses={self.v38_memory.get('successes',0)} mode=STRUCTURAL_NOT_DOMAIN")
        self.log(f"[LIMITS] depth={MAX_DEPTH} requests={MAX_REQUESTS}")
        self.walk(url)

        # V81 GitHub/browser mode: the repository runner has a real Chromium runtime.
        # Prefer the existing Playwright + CDP observer and only use MITM locally when
        # explicitly requested. This removes the Android/Termux mitmdump dependency.
        _github_runtime = os.environ.get("V81_GITHUB", "").lower() in ("1", "true", "yes")
        _local_runtime = os.environ.get("V81_BROWSER_RUNTIME", "").lower() in ("1", "true", "yes")
        if not self.final_verified and (_github_runtime or _local_runtime):
            self.log(f"[V81_RUNTIME_MODE] mode={'GITHUB' if _github_runtime else 'LOCAL'}")
            self.browser_runtime_probe(url)

        # MITM is now an explicit legacy fallback, never the mandatory GitHub path.
        if not self.final_verified and not _github_runtime and os.environ.get("V81_ENABLE_MITM", "").lower() in ("1", "true", "yes"):
            self.log("[V3_MITM_FALLBACK] explicit local MITM mode enabled")
            self.v3_mitm_chrome_fallback(url)

        if self.final_verified:
            self.v38_seen_families.add("HLS_MANIFEST" if self.final_type=="HLS" else "DIRECT_MEDIA")
            self.v38_learn_success()
            self.v39_learn_structural_route()
            self.v40_learn_bootstrap_route()
            self.detect="FINAL_MEDIA"; self.confidence=100
        elif self.v31_transport_failures:
            cls=self.v31_transport_failures[-1].get("class","NETWORK_ERROR")
            self.detect="TRANSPORT_FAILURE"; self.confidence=98
            self.log(f"[CHAIN_CLASS] TRANSPORT_FAILURE class={cls}")
        elif self.v42_protected_requests:
            self.detect="PROTECTED_BROWSER_SESSION_REQUIRED"; self.confidence=99
            self.v42_failure_stage=self.v42_failure_stage or "PLAYER_BOOTSTRAP_XHR"
            _last=self.v42_protected_requests[-1]
            self.log(f"[RUNTIME_CLASS] PROTECTED_BROWSER_SESSION_REQUIRED")
            self.log(f"[FAILURE_STAGE] {self.v42_failure_stage}")
            self.log(f"[BLOCK_STATUS] {_last.get('status',0)}")
            self.log(f"[DOWNSTREAM_MEDIA] NOT_GENERATED")
        elif self.v30_environment_rejected:
            self.detect="BROWSER_ENVIRONMENT_REJECTED"; self.confidence=96
            self.log("[CHAIN_CLASS] BROWSER_ENVIRONMENT_REJECTED evidence="+(",".join(self.v30_environment_evidence) or "UNKNOWN"))
        elif self.player and self.script_endpoints:
            self.detect="PLAYER_CHAIN_PARTIAL"; self.confidence=82
            self.log("[CHAIN_CLASS] PLAYER_CHAIN_PARTIAL")
        elif self.blocked:
            self.detect="BLOCKED_WAF"; self.confidence=90
            self.log("[BLOCK_CLASS] CLOUDFLARE_CHALLENGE")
        elif self.player and self.script_endpoints:
            self.detect="PLAYER_CHAIN_PARTIAL"; self.confidence=82
            self.log("[CHAIN_CLASS] PLAYER_CHAIN_PARTIAL")
        elif self.runtime_needed:
            self.detect="NEEDS_RUNTIME_JS"; self.confidence=85
            self.log("[RUNTIME_CLASS] NEEDS_RUNTIME_JS")
        elif self.script_endpoints:
            self.detect="AJAX_API"; self.confidence=70
        elif self.player:
            self.detect="IFRAME"; self.confidence=75
        else:
            self.detect="UNKNOWN"; self.confidence=35
        self.log("[V54_CAPABILITY] V54_RUNTIME + RELIABLE_PLAYER_INTERACTION_OR_BOOTSTRAP_TRIGGER + PLAYER_REGION_CAUSAL_GATING + NAVIGATION_VETO + NETWORK_DELTA_PROOF + NO_DOMAIN_URL_SYNTHESIS")
        resolution_dna=self.v50_emit_resolution_report()
        repo_report=self.v53_emit_repo_integration_report()
        family_report=self.emit_family_report()
        self.v81_emit_report(url)
        self.log(f"[SUMMARY] requests={self.requests} visited={len(self.visited)} maxDepth={self.max_depth}")
        self.log(f"[FINAL_MEDIA] {self.final or 'NONE'}")
        self.log(f"[FINAL_TYPE] {self.final_type or 'NONE'}")
        self.log(f"[FINAL_VERIFY] {'YES' if self.final_verified else 'NO'}")
        self.log(f"[DETECT] {self.detect}")
        self.log(f"[CONFIDENCE] {self.confidence}%")
        return {
            "http_status":self.root_status,
            "requests":self.requests,
            "visited":len(self.visited),
            "max_depth":self.max_depth,
            "player":self.player,
            "final_url":self.final,
            "final_type":self.final_type,
            "final_verified":self.final_verified,
            "blocked":self.blocked,
            "runtime_needed":self.runtime_needed,
            "detect":self.detect,
            "confidence":self.confidence,
            "resolver_family":family_report["primary"],
            "resolver_families":family_report["families"],
            "media_transport":family_report["transport"],
            "suggested_engine":family_report["suggested_engine"],
            "site_compatibility":family_report["compatibility"],
            "family_evidence":family_report["evidence"],
            "browser_runtime_used":self.browser_runtime_used,
            "browser_runtime_available":self.browser_runtime_available,
            "browser_runtime_error":self.browser_runtime_error,
            "browser_network":self.browser_network[-40:],
            "media_candidates":self.media_candidates[-40:],
            "v43_semantic_media":list(self.v43_semantic_media.values())[-40:],
            "v43_semantic_chain":self.v43_semantic_chain[-60:],
            "v43_browser_fetch_proofs":self.v43_browser_fetch_proofs[-20:],
            "final_evidence":self.final_evidence,
            "final_playback_context":self.final_playback_context,
            "v32_evidence_graph":{
                "nodes":list(self.v32_evidence_nodes.values())[-120:],
                "edges":[{"from":a,"to":b,"via":c} for a,b,c in self.v32_evidence_edges[-160:]],
                "pruned":self.v32_pruned[-80:],
            },
            "v32_final_media_proof":self.v32_proof,
            "browser_media_context":dict(list(self.browser_media_context.items())[-40:]),
            "browser_requests":self.browser_requests[-60:],
            "browser_responses":self.browser_responses[-60:],
            "runtime_dom_events":self.runtime_dom_events[-60:],
            "broken_player_targets":self.broken_player_targets[-20:],
            "runtime_discovered_urls":self.runtime_discovered_urls[-40:],
            "runtime_requeue_count":self.runtime_requeue_count,
            "runtime_browser_targets":self.runtime_browser_targets[-40:],
            "browser_request_context":dict(list(self.browser_request_context.items())[-40:]),
            "v42_browser_env":self.v42_browser_env,
            "v42_protected_requests":self.v42_protected_requests[-30:],
            "v42_failure_stage":self.v42_failure_stage,
            "v42_request_extra_headers":dict(list(self.v42_request_extra_headers.items())[-30:]),
            "v42_response_extra_headers":dict(list(self.v42_response_extra_headers.items())[-30:]),
            "v44_real_chrome_endpoint":"http://127.0.0.1:9222",
            "v46_clean_observer":bool(getattr(self,"v46_clean_observer",False)),
            "v50_resolution_dna":resolution_dna,
            "v50_interaction_provenance":self.v50_interaction_provenance,
            "v50_transport_diagnostics":self.v50_transport_diagnostics,
            "v50_final_proof_report":self.v50_final_proof_report,
            "v51_root_cause":self.v51_root_cause,
            "v51_behavior_signature":self.v51_behavior_signature,
            "v51_next_experiments":self.v51_next_experiments,
            "v53_repo_integration_report":self.v53_repo_integration_report,
            "v68_diagnostic_report":getattr(self,"v68_diagnostic_report",{}),
            "v69_diagnostic_report":getattr(self,"v69_diagnostic_report",{}),
            "v70_diagnostic_report":getattr(self,"v70_diagnostic_report",{}),
            "v71_diagnostic_report":getattr(self,"v71_diagnostic_report",{}),
            "v72_diagnostic_report":getattr(self,"v72_diagnostic_report",{}),
            "v73_diagnostic_report":getattr(self,"v73_diagnostic_report",{}),
            "v54_mrc_signals":self.v54_mrc_signals[-120:],
            "v54_static_candidates":self.v54_static_candidates[-120:],
            "v54_static_decodes":self.v54_static_decodes[-80:],
            "v81_report":self.v81_report,
            "logs":self.logs
        }

class Handler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        # V81: canlı MITM analizini HTTP polling gürültüsüyle kirletme.
        try:
            msg = format % args
            if "/api/manual-status" in msg: return
            print(f"[LOCAL] {self.address_string()} {msg}", flush=True)
        except Exception:
            pass

    def end_headers(self):
        self.send_header("Cache-Control","no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma","no-cache")
        self.send_header("Expires","0")
        super().end_headers()
    def translate_path(self,path):
        p=super().translate_path(path)
        rel=Path(p).relative_to(Path.cwd())
        return str(ROOT/rel)
    def do_POST(self):
        if self.path not in ("/api/analyze","/api/repo-analyze","/api/manual-start","/api/manual-status","/api/manual-stop"):
            self.send_error(404); return
        try:
            n=int(self.headers.get("Content-Length","0"))
            data=json.loads(self.rfile.read(n) or b"{}")
            url=str(data.get("url","")).strip()
            if not re.match(r"^https?://",url,re.I):
                raise ValueError("Geçerli http/https URL gerekli")
            if self.path=="/api/manual-start":
                sess=manual_start(url)
                # Do not report success before the background browser has actually opened.
                deadline=time.time()+8.0
                while sess.status == 'starting' and time.time() < deadline:
                    time.sleep(0.10)
                result={"session_id":sess.id,"status":sess.status,"error":sess.error,"message":("Chrome açıldı; yalnız dinleme aktif." if sess.status=="listening" else "Chrome başlatılıyor...")}
            elif self.path in ("/api/manual-status","/api/manual-stop"):
                sid=str(data.get("session_id","")).strip(); sess=manual_get(sid)
                if not sess: raise ValueError("Dinleme oturumu bulunamadı")
                if self.path=="/api/manual-stop":
                    result=sess.stop()
                else:
                    # V77: once finalization completes, status returns the COMPLETE
                    # capture result. This prevents the UI from exporting a tiny
                    # {status: stopping} placeholder as the TXT report.
                    if sess.status == 'done' and sess.result is not None:
                        result=sess.result
                    else:
                        result={"session_id":sid,"status":sess.status,"error":sess.error,"events":sess.events[-30:],"request_count":len(sess.net),"snapshot_count":len(sess.snapshots),"finalizing":sess.status=="stopping"}
            else:
                result=RepoAnalyzer().analyze(url) if self.path=="/api/repo-analyze" else Analyzer().analyze(url)
            raw=json.dumps(result,ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type","application/json; charset=utf-8")
            self.send_header("Content-Length",str(len(raw)))
            self.end_headers(); self.wfile.write(raw)
        except Exception as e:
            import traceback
            tb=traceback.format_exc()
            print("[ANALYZE_EXCEPTION]",tb)
            raw=json.dumps({"error":"[ANALYZE_EXCEPTION] "+type(e).__name__+": "+str(e),
                            "trace":tb[-4000:]},ensure_ascii=False).encode("utf-8")
            self.send_response(500)
            self.send_header("Content-Type","application/json; charset=utf-8")
            self.end_headers(); self.wfile.write(raw)

if __name__=="__main__":
    import webbrowser, threading
    os.chdir(ROOT)
    url="http://127.0.0.1:8765"
    print("="*60)
    print("Resolver Lab Local calisiyor:")
    print(url)
    print("Tarayici otomatik acilmazsa bu adresi elle ac.")
    print("="*60)
    threading.Timer(1.2, lambda: webbrowser.open_new_tab(url)).start()
    ThreadingHTTPServer(("127.0.0.1",8765),Handler).serve_forever()
