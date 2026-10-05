import json,time,re
from pathlib import Path
from urllib.parse import urlparse,parse_qsl
from mitmproxy import http,ctx


# --- Resolver Lab: CMD + kalici canli analiz logu ---
import builtins as _builtins
from datetime import datetime as _dt
from pathlib import Path as _Path

_ORIGINAL_PRINT = _builtins.print
_LIVE_LOG_PATH = _Path(__file__).resolve().parent / "CANLI_ANALIZ_LOG.txt"

def _live_print(*args, **kwargs):
    # CMD
    _ORIGINAL_PRINT(*args, **kwargs)
    # Dosya: print'in sep/end davranisini koru, renk/özel file argümanını taşıma.
    try:
        sep = kwargs.get("sep", " ")
        end = kwargs.get("end", "\n")
        text = sep.join(str(x) for x in args) + end
        with _LIVE_LOG_PATH.open("a", encoding="utf-8", errors="replace", newline="") as _f:
            _f.write(text)
            _f.flush()
    except Exception as _e:
        _ORIGINAL_PRINT("[LOG-YAZMA-HATASI]", repr(_e))

print = _live_print
print("\\n" + "=" * 72)
print("[OTURUM]", _dt.now().strftime("%Y-%m-%d %H:%M:%S"))
print("[LOG]", str(_LIVE_LOG_PATH))
print("=" * 72)
# --- /Resolver Lab ---


SUB_EXT_RE = re.compile(r"\.(?:vtt|srt|ass|ssa|ttml|dfxp)(?:$|[?#])", re.I)
SUB_URL_RE = re.compile(r"(?:subtitle|subtitles|caption|captions|closedcaption|timedtext)", re.I)
SUB_CT_RE = re.compile(r"(?:text/vtt|application/(?:x-subrip|ttml\+xml)|text/(?:srt|plain))", re.I)

def subtitle_kind(u, ct=""):
    low=(u or "").lower()
    m=re.search(r"\.(vtt|srt|ass|ssa|ttml|dfxp)(?:$|[?#])", low)
    if m: return m.group(1).upper()
    if "vtt" in (ct or "").lower(): return "VTT"
    if "subrip" in (ct or "").lower(): return "SRT"
    if "ttml" in (ct or "").lower(): return "TTML"
    return "SUBTITLE"

def subtitle_hint(u, headers=None):
    blob=(u or "")+" "+" ".join(f"{k}:{v}" for k,v in (headers or {}).items())
    m=re.search(r"(?:^|[?&/_-])(?:lang|language|locale)[=/_-]?(tr|tur|tr-tr)(?:$|[&#/_-])",blob,re.I)
    if m or re.search(r"(?:turkce|türkçe|turkish)",blob,re.I): return "tr"
    return "unknown"

def load(loader): loader.add_option('manual_capture',str,'','manual capture jsonl')
def wr(x):
    p=Path(ctx.options.manual_capture); p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('a',encoding='utf-8') as f:f.write(json.dumps(x,ensure_ascii=False,default=str)+'\n');f.flush()
def out(tag,msg): print(f'[{tag}] {msg}',flush=True)
def classify(method,u,dest,post=''):
    pu=urlparse(u); path=pu.path.lower(); q=dict(parse_qsl(pu.query,keep_blank_values=True)); keys={k.lower() for k in q}
    low=(u+' '+post).lower()
    if re.search(r'\.m3u8(?:$|\?)|\.mpd(?:$|\?)|\.m4s(?:$|\?)|\.ts(?:$|\?)|\.mp4(?:$|\?)',u,re.I): return 'MEDIA'
    if dest=='iframe' or re.search(r'/(embed|player)/',path,re.I): return 'IFRAME'
    if keys & {'s','q','query','search','searchterm','keyword','term','ara'} or re.search(r'(^|[&{\" ])(s|q|query|search|searchterm|keyword|term|ara)[=\":]',post,re.I): return 'ARAMA'
    if keys & {'page','paged','p','currentpage'} or re.search(r'/(page|sayfa)[/-]?\d+',path,re.I): return 'SAYFALAMA'
    if method.upper()!='GET': return 'POST'
    if dest=='document': return 'SAYFA'
    if re.search(r'/(api|ajax|search|load|filter|query)',path,re.I): return 'API'
    return ''
def request(flow:http.HTTPFlow):
    try:
        u=flow.request.pretty_url; h={str(k).lower():str(v) for k,v in flow.request.headers.items()}; dest=h.get('sec-fetch-dest','')
        api=flow.request.method.upper()!='GET' or bool(re.search(r'/(api|ajax|search|load|filter|page|query)',urlparse(u).path,re.I))
        post=''
        try: post=flow.request.get_text(strict=False)[:20000] if flow.request.raw_content else ''
        except Exception: pass
        is_sub=bool(SUB_EXT_RE.search(u) or SUB_URL_RE.search(u))
        wr({'kind':'request','ts':time.time(),'method':flow.request.method,'url':u,'document':dest in ('document','iframe'),'api_like':api,'post_data':post,'headers':h,'subtitle':is_sub})
        if is_sub:
            out('SUBTITLE_NETWORK',f'REQUEST lang={subtitle_hint(u,h)} type={subtitle_kind(u)} url={u}')
        tag=classify(flow.request.method,u,dest,post)
        if tag:
            out(tag,f'{flow.request.method} {u}')
            if post: out('BODY',post[:4000])
    except Exception as e: out('MITM_REQUEST_ERROR',repr(e))
def response(flow:http.HTTPFlow):
    try:
        u=flow.request.pretty_url; ct=(flow.response.headers.get('content-type','') or '').lower(); h={str(k).lower():str(v) for k,v in flow.request.headers.items()}; dest=h.get('sec-fetch-dest','')
        textual=('text/html' in ct or 'json' in ct or 'javascript' in ct or 'text/plain' in ct)
        text=''
        if textual and len(flow.response.raw_content or b'')<=2500000:
            try:text=flow.response.get_text(strict=False)
            except Exception:pass
        rh={str(k).lower():str(v) for k,v in flow.response.headers.items()}
        is_sub=bool(SUB_EXT_RE.search(u) or SUB_URL_RE.search(u) or SUB_CT_RE.search(ct))
        wr({'kind':'response','ts':time.time(),'method':flow.request.method,'url':u,'status':flow.response.status_code,'content_type':ct,'document':dest in ('document','iframe'),'text':text,'subtitle':is_sub,'response_headers':rh})
        if is_sub:
            out('SUBTITLE_NETWORK',f'RESPONSE status={flow.response.status_code} lang={subtitle_hint(u,rh)} type={subtitle_kind(u,ct)} ct={ct or "-"} url={u}')
        # HTML/JS/JSON icinde acik altyazi URL'leri varsa ayrica raporla.
        if text:
            seen=set()
            for m in re.finditer(r'''https?://[^\s"'<>]+?\.(?:vtt|srt|ass|ssa|ttml|dfxp)(?:\?[^\s"'<>]*)?''',text,re.I):
                su=m.group(0).replace('\\/','/').replace('&amp;','&')
                if su not in seen:
                    seen.add(su); out('SUBTITLE_TRACK',f'lang={subtitle_hint(su)} type={subtitle_kind(su)} url={su}')
                    wr({'kind':'subtitle_track','ts':time.time(),'url':su,'language':subtitle_hint(su),'subtitle_type':subtitle_kind(su),'source':u})
        tag=classify(flow.request.method,u,dest,'')
        if tag in ('SAYFA','ARAMA','SAYFALAMA','POST','API','IFRAME','MEDIA'):
            out('CEVAP',f'{flow.response.status_code} {ct or "-"} <- {u}')
    except Exception as e: out('MITM_RESPONSE_ERROR',repr(e))
