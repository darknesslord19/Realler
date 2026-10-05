"""V81 MITM capture addon (analysis path).

V80 davranisi korunur: medya satirlari ("hls","dash","mp4","webm","video","segment_html")
ayni formatta yazilir; server.py'deki medya dinleyicisi aynen calisir.

V81 eki: F12 > Network gibi TAM kayit ("kind":"net"):
  - document / iframe / xhr / fetch / script / media / subtitle istekleri
  - method, url, sec-fetch-dest, istek header'lari (referer/origin/cookie/x-*/auth...),
    POST govdesi, status, content-type, onemli cevap header'lari
  - metin cevaplarin govdesi (HTML/JS/JSON/M3U8/VTT) -> server tarafinda
    "final URL hangi cevabin icinden cikti" (provenance) aramasi icin.
Resim/font/css ve bilinen analitik hostlari kaydedilmez.
"""
import json, time, re
from pathlib import Path
from urllib.parse import urlparse
from mitmproxy import http, ctx


def load(loader):
    loader.add_option("resolver_capture", str, "", "Resolver V3 capture")


def _write(r):
    out = Path(ctx.options.resolver_capture); out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8") as f:
        f.write(json.dumps(r, ensure_ascii=True, default=str) + "\n"); f.flush()


NOISE_HOSTS = ("usersync", "/pixel", "cms?uid", "ad.turn.com", "1rx.io", "/api/adx/", "analytics.yahoo",
               "ambientdsp", "advolve", "deepintent", "ingage.tech", "id5-sync", "openx", "stackadapt", "iprom",
               "iqzonertb", "aniview", "dotomi", "chromewebstore", "gvt1.com", "opera.com/sync", "t.adx.",
               "connatix", "adform", "criteo", "fwmrm", "3lift", "adsrvr", "bidgx", "pubmatic",
               "rubiconproject", "amazon-adsystem", "adnxs", "taboola", "outbrain", "clientservices.googleapis",
               "google-analytics", "googletagmanager", "doubleclick", "googlesyndication",
               "facebook.com", "facebook.net", "cloudflareinsights", "hotjar", "yandex.ru/metrika",
               "mc.yandex", "clarity.ms", "gstatic.com", "fonts.googleapis", "optimizationguide-pa",
               "content-autofill.googleapis", "android.clients.google.com", "update.googleapis",
               "safebrowsing", "accounts.google.com", "clients2.google", "edgedl.me.gvt1")
STATIC_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".woff", ".woff2",
              ".ttf", ".otf", ".css", ".avif", ".map")
SUB_EXT_RE = re.compile(r"\.(?:vtt|srt|ass|ssa|ttml|dfxp)(?:$|[?#])", re.I)
SUB_CT_RE = re.compile(r"(?:text/vtt|x-subrip|ttml\+xml|application/x-ass)", re.I)
KEEP_REQ_HEADERS = ("referer", "origin", "cookie", "user-agent", "x-requested-with", "authorization",
                    "content-type", "accept", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "range")
KEEP_RESP_HEADERS = ("location", "set-cookie", "access-control-allow-origin", "content-length",
                     "content-type", "cache-control")
MAX_TEXT = 600_000


def _media_kind(p, ct):
    if p.endswith(".m3u8") or "mpegurl" in ct: return "hls"
    if p.endswith(".mpd") or "dash+xml" in ct: return "dash"
    if p.endswith(".mp4") or "video/mp4" in ct: return "mp4"
    if p.endswith(".webm") or "video/webm" in ct: return "webm"
    if ct.startswith("video/"): return "video"
    return ""


def _v81_net_row(flow, ct, k):
    """Full F12-like row. Returns None for noise."""
    u = flow.request.pretty_url
    q = urlparse(u); host = (q.netloc or "").lower(); p = (q.path or "").lower()
    if any(n in host or n in u.lower() for n in NOISE_HOSTS): return None
    reqh = {str(a).lower(): str(b) for a, b in flow.request.headers.items()}
    dest = reqh.get("sec-fetch-dest", "")
    is_sub = bool(SUB_EXT_RE.search(u) or SUB_CT_RE.search(ct))
    if p.endswith(STATIC_EXT) and not is_sub and not k:
        # disguised segments (.jpg/.png served as video) are kept by MIME
        if not (ct.startswith("video/") or "mp2t" in ct or "octet-stream" in ct):
            return None
    if dest in ("image", "font", "style") and not k and not is_sub:
        return None
    textual = any(x in ct for x in ("text/", "json", "javascript", "mpegurl", "xml", "vtt", "subrip")) \
        or p.endswith((".m3u8", ".vtt", ".srt", ".js", ".json"))
    raw = flow.response.raw_content or b""
    text = ""
    if textual and len(raw) <= 3_000_000 and k not in ("mp4", "webm", "video"):
        try: text = flow.response.get_text(strict=False) or ""
        except Exception: text = ""
    post = ""
    try:
        if flow.request.raw_content: post = flow.request.get_text(strict=False)[:6000]
    except Exception: post = ""
    resph = {str(a).lower(): str(b) for a, b in flow.response.headers.items()}
    return {
        "kind": "net", "ts": time.time(), "method": flow.request.method, "url": u,
        "dest": dest or ("subtitle" if is_sub else ""), "status": flow.response.status_code,
        "content_type": ct, "media_kind": k, "subtitle": is_sub,
        "req_headers": {a: reqh[a] for a in reqh if a in KEEP_REQ_HEADERS or a.startswith("x-")},
        "resp_headers": {a: resph[a] for a in resph if a in KEEP_RESP_HEADERS},
        "post": post, "bytes": len(raw),
        "text": text[:MAX_TEXT], "text_truncated": len(text) > MAX_TEXT,
        "head_hex": raw[:16].hex() if not text else "",
    }


def request(flow: http.HTTPFlow):
    """V81: Chrome profil onbellegi 304 dondurup govdeyi gizlemesin -> kosullu header'lari sil."""
    try:
        for h in ("if-none-match", "if-modified-since", "if-match", "if-range"):
            if h in flow.request.headers:
                del flow.request.headers[h]
    except Exception as e:
        print("[V81 REQUEST HOOK ERROR]", repr(e), flush=True)


def response(flow: http.HTTPFlow):
    try:
        u = flow.request.pretty_url
        q = urlparse(u); p = (q.path or "").lower(); ct = (flow.response.headers.get("content-type", "") or "").lower(); host = (q.netloc or "").lower()

        # ---- V81: full network row (independent from V80 media logic) ----
        try:
            row = _v81_net_row(flow, ct, _media_kind(p, ct))
            if row is not None:
                _write(row)
                if row["subtitle"]:
                    print("[V81 SUBTITLE]", row["status"], ct or "-", u, flush=True)
        except Exception as e:
            print("[V81 NET CAPTURE ERROR]", repr(e), flush=True)

        # ---- V80 media logic (unchanged) ----
        if "jwpltx.com" in host and not p.endswith(".m3u8"): return
        k = _media_kind(p, ct)

        # Some players deliberately serve sequential video chunks with an HTML-looking
        # extension. Do not promote one chunk to a final playable URL; record it as
        # transport/media evidence so the resolver can keep the proven chain.
        disguised = False; family = ""
        if not k and flow.response.status_code in (200, 206):
            m = re.search(r"(?i)(/cdn/(?:down|stream)/[^?#]+?/video/[^?#]+?/)([^/?#]+?)(?:_(\d+))?\.html$", q.path or "")
            if m:
                reqh = {str(a).lower(): str(b) for a, b in flow.request.headers.items()}
                fetch_dest = reqh.get("sec-fetch-dest", "").lower()
                rng = reqh.get("range", "")
                clen = flow.response.headers.get("content-length", "") or ""
                bodylen = len(flow.response.raw_content or b"")
                if fetch_dest in ("video", "empty") or rng or bodylen >= 1024 or (clen.isdigit() and int(clen) >= 1024):
                    disguised = True; k = "segment_html"
                    family = f"{q.scheme}://{q.netloc}{m.group(1)}"
        if not k: return
        r = {"ts": time.time(), "kind": k, "url": u, "status": flow.response.status_code, "content_type": ct,
             "headers": {str(a): str(b) for a, b in flow.request.headers.items()}}
        if disguised:
            r["disguised_media"] = True; r["segment_family"] = family; r["body_bytes"] = len(flow.response.raw_content or b"")
        _write(r)
        print("[V3 MEDIA]", k, u, flush=True)
    except Exception as e:
        print("[V3 CAPTURE ERROR]", repr(e), flush=True)
