# -*- coding: utf-8 -*-
"""
V81 REPO-READY EVIDENCE LAYER
=============================
Amac: Tek analiz logu ile eklenti (CS3 repo) yazilabilsin. F12 > Network mantigi:
  1) Her istek/cevap kaydedilir (statik urllib + MITM Chrome) -> self.v81_net
  2) Final medya URL'si hangi cevabin icinden cikti? (PROVENANCE) geriye dogru izlenir
     -> detay sayfasi -> ajax -> iframe -> (packer/base64/json) -> m3u8
  3) ${var} sablonlu ajax istekleri sayfadaki data-* / JS degiskenleriyle cozulup cagrilir
  4) Altyazi: HTML <track>, tracks:[...], Playerjs "[Dil]url", subtitle/caption alanlari,
     duz .vtt/.srt, packer icinden, HLS #EXT-X-MEDIA TYPE=SUBTITLES, MITM ag trafigi
  5) Reklam HLS'i (kisa sureli / ad-path) final secilmez, ayri listelenir
  6) Oynatma header'lari tek tek cikarilarak test edilir -> REQUIRED / OPTIONAL
  7) Sonunda tek blok: [V81_VERDICT] + [V81_REPO_RECIPE] + [V81_REPO_JSON]
     Basarisizsa: [V81_STOPPED_AT] + [V81_MISSING] (hangi parca eksik, neden)

V80 cozum zinciri degistirilmez; bu katman sadece ekler.
"""
import re, json, time, html, base64, ssl, os, subprocess, hashlib, itertools
import urllib.request, urllib.error
from urllib.parse import urlparse, urljoin, parse_qsl, unquote

V81_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
          "AppleWebKit/537.36 (KHTML, like Gecko) "
          "Chrome/153.0.0.0 Safari/537.36")

SUB_EXT = ("vtt", "srt", "ass", "ssa", "ttml", "dfxp")
SUB_EXT_RX = r"(?:vtt|srt|ass|ssa|ttml|dfxp)"
THUMB_WORDS = ("thumb", "sprite", "preview", "storyboard", "seek")
PACKER_RX = re.compile(
    r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[rd]\s*\)\s*\{.*?\}\s*\(\s*(['\"])(.*?)\1\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(['\"])(.*?)\5\.split\s*\(\s*['\"]\|['\"]\s*\)",
    re.S)


def _clean_text(v):
    """Kontrol/NUL/binary karakterleri temizler (UI logu bu karakterlerde kesiliyordu)."""
    t = str(v or "")
    bad = sum(1 for ch in t[:400] if (ord(ch) < 32 and ch not in "\r\n\t") or 0xFFFD == ord(ch))
    if t and bad > max(2, len(t[:400]) * 0.05):
        return f"[binary {len(t)} karakter]"
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ufffd]", "?", t)


AD_TRACKER_HOSTS = ("connatix", "adform", "criteo", "fwmrm", "3lift", "adsrvr", "bidgx", "doubleclick",
                    "googlesyndication", "taboola", "outbrain", "pubmatic", "rubiconproject", "openx",
                    "amazon-adsystem", "adnxs", "smartadserver", "teads", "yandex", "clientservices.googleapis",
                    "www.google.com/async", "entitlements.jwplayer", "cdn-cgi/rum", "cdn-cgi/speculation",
                    "jwpltx", "scorecardresearch", "moatads", "imasdk", "sync?", "user-sync", "usync", "cookie?redirect",
                    "usersync", "/pixel", "pixel?", "/cm/", "cms?uid", "match.", "ad.turn.com", "1rx.io", "/api/adx/",
                    "analytics.yahoo", "ambientdsp", "advolve", "deepintent", "ingage.tech", "id5-sync", "openx",
                    "stackadapt", "iprom", "iqzonertb", "aniview", "dotomi", "challenge-platform", "chromewebstore",
                    "gvt1.com", "googleapis.com/chromewebstore", "devtools-detector", "/cdn-cgi/", "opera.com/sync",
                    "t.adx.", "adsystem", "bidswitch", "casalemedia", "sharethrough", "smaato", "yieldmo")


def _is_noise_url(u):
    lu = str(u or "").lower()
    return any(h in lu for h in AD_TRACKER_HOSTS)


def _short(v, n=220):
    v = re.sub(r"\s+", " ", _clean_text(v)).strip()
    return v if len(v) <= n else v[:n] + "…"


def _unescape(text):
    t = str(text or "")
    return (t.replace("\\/", "/").replace("\\u0026", "&").replace("\\u003d", "=")
             .replace("\\u002F", "/").replace("\\x26", "&").replace("&amp;", "&"))


def _lang_of(*parts):
    blob = " ".join(str(p or "") for p in parts).lower()
    if re.search(r"(?:^|[^a-z])(tr|tur|tr-tr|turkce|türkçe|turkish|türk)(?:[^a-z]|$)", blob): return "tr"
    if re.search(r"(?:^|[^a-z])(en|eng|en-us|english|ingilizce|İngilizce)(?:[^a-z]|$)", blob): return "en"
    m = re.search(r"(?:^|[^a-z])(de|fr|es|it|ar|ru|ja|ko|pt|nl|pl)(?:[^a-z]|$)", blob)
    return m.group(1) if m else "unknown"


def _base_n(n, base):
    chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if base <= 10 or base > 62: return str(n)
    s = ""
    while True:
        s = chars[n % base] + s; n //= base
        if n == 0: break
    return s


def quiet_unpack(text):
    """Dean Edwards packer'i sessizce acar (log basmaz). Liste dondurur."""
    out = []
    for m in PACKER_RX.finditer(str(text or "")):
        try:
            payload = m.group(2); base = int(m.group(3)); count = int(m.group(4)); words = m.group(6).split("|")
            payload = payload.replace("\\'", "'").replace('\\"', '"').replace("\\\\", "\\")
            table = {}
            for i in range(min(count, len(words))):
                if words[i]: table[_base_n(i, base)] = words[i]
            out.append(re.sub(r"\b\w+\b", lambda mm: table.get(mm.group(0), mm.group(0)), payload))
        except Exception:
            pass
    return out



def _aes_cbc(cipher, key, iv):
    """AES-CBC cozer; once 'cryptography', yoksa server.py'deki saf-Python AES."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return d.update(cipher) + d.finalize()
    except ImportError:
        pass
    import sys as _sys
    for nm in ("__main__", "server"):
        m = _sys.modules.get(nm)
        if m is not None and hasattr(m, "_aes_cbc_decrypt"):
            return m._aes_cbc_decrypt(cipher, key, iv)
    return b""


def _unpad_ok(p):
    if not p: return None
    n = p[-1]
    if 1 <= n <= 16 and p[-n:] == bytes([n]) * n:
        body = p[:-n]
        try:
            txt = body.decode("utf-8")
        except Exception:
            return None
        if sum(ch.isprintable() for ch in txt) >= len(txt) * 0.95:
            return txt
    return None


def _b64(v):
    try:
        v = str(v).strip()
        return base64.b64decode(v + "=" * (-len(v) % 4))
    except Exception:
        return None


class V81Mixin:
    # ------------------------------------------------------------------ state
    def v81_init(self):
        self.v81_net = []            # unified rows (STATIC + MITM)
        self.v81_subs = {}           # url -> info
        self.v81_sub_sources = set() # scanned source categories
        self.v81_templates = []
        self.v81_template_done = set()
        self.v81_params = []         # resolved template variables
        self.v81_missing = []
        self.v81_ads = []
        self.v81_media_referer = {}
        self.v81_hls_info = {}
        self.v81_unpack_cache = {}
        self.v81_root_url = ""
        self.v81_mitm_used = False
        self.v81_report = {}
        self.v81_template_calls = {}
        self.v81_mitm_text_queue = []
        self.v81_force_media = set()
        self.v81_hls_queue = []
        self.v81_hls_tried = set()
        self.v81_media_rejects = []
        self.v81_frame_scan = []
        self.v81_t0 = time.time()

    def v81_missing_add(self, code, detail):
        item = f"{code}: {detail}"
        if item not in self.v81_missing:
            self.v81_missing.append(item)
            self.log(f"[V81_MISSING_PIECE] {item}")

    # ------------------------------------------------------- network recording
    def v81_record(self, src, method, url, req_headers=None, post="", status=0, ct="", text="",
                   eff_url="", dest="", resp_headers=None, nbytes=None, ts=None, media_kind=""):
        try:
            rh = {str(k).lower(): str(v) for k, v in (req_headers or {}).items()}
            if not dest:
                lct = (ct or "").lower()
                if rh.get("x-requested-with") or rh.get("sec-fetch-dest") == "empty": dest = "xhr"
                elif "javascript" in lct or urlparse(url).path.lower().endswith(".js"): dest = "script"
                elif "mpegurl" in lct or "video/" in lct: dest = "media"
                elif "html" in lct: dest = "document"
            row = {"src": src, "ts": ts or time.time(), "method": (method or "GET").upper(), "url": url,
                   "eff_url": eff_url or url, "dest": dest, "status": int(status or 0), "ct": ct or "",
                   "req_headers": rh, "post": post or "", "text": text or "",
                   "resp_headers": {str(k).lower(): str(v) for k, v in (resp_headers or {}).items()},
                   "bytes": nbytes if nbytes is not None else len(text or ""), "media_kind": media_kind}
            self.v81_net.append(row)
            return row
        except Exception as e:
            self.log(f"[V81_RECORD_ERROR] {type(e).__name__}: {e}")
            return None

    def v81_record_static(self, url, method, headers, data, res):
        """server.fetch() kancasi."""
        if res is None:
            self.v81_record("STATIC", method, url, headers, "", 0, "", "")
            return
        post = ""
        if data is not None:
            try:
                from urllib.parse import urlencode
                post = urlencode(data) if isinstance(data, dict) else str(data)
            except Exception:
                post = str(data)
        self.v81_record("STATIC", method, url, headers, post, res.get("status", 0), res.get("ct", ""),
                        res.get("body", ""), eff_url=res.get("url", url), resp_headers=res.get("headers", {}))

    # -------------------------------------------------------------- subtitles
    def v81_sub_add(self, url, base, label="", lang="", kind="", fmt="", source="", via=""):
        raw = _unescape(url).strip().strip("'\"")
        if not raw or raw.startswith(("data:", "blob:", "javascript:")): return
        if re.search(r"[(){}\s;<>\[\],]|&&|===|\|\||\.length", raw): return  # JS kodu / liste parcasi, URL degil
        if raw.count("http") > 1 or re.search(r"(?:^|/)\.(?:vtt|srt|ass|ssa|ttml|dfxp)(?:$|[?#])", raw, re.I): return
        if re.search(r"\$\{|\{\{|\+\s*\w", raw): return
        try: u = urljoin(base or "", raw)
        except Exception: u = raw
        if not u.startswith(("http://", "https://")): return
        low = u.lower()
        k = (kind or "").lower()
        if k in ("thumbnails", "chapters", "metadata") or any(w in low for w in THUMB_WORDS):
            return
        if not fmt:
            m = re.search(r"\.(" + SUB_EXT_RX + r")(?:$|[?#])", low)
            fmt = m.group(1).upper() if m else ("HLS_SUBTITLE" if ".m3u8" in low else "UNKNOWN")
        info = self.v81_subs.get(u)
        if info is None:
            info = {"url": u, "label": label or "", "lang": lang or _lang_of(label, u), "kind": kind or "",
                    "format": fmt, "sources": [], "found_in": base or "", "valid": None}
            self.v81_subs[u] = info
            self.log(f"[V81_SUBTITLE_FOUND] lang={info['lang']} label={label or '-'} format={fmt} source={source} via={via or '-'} found_in={base or '-'} url={u}")
        else:
            if label and not info["label"]: info["label"] = label
            if info["lang"] == "unknown" and (label or lang): info["lang"] = lang or _lang_of(label, u)
        if source and source not in info["sources"]: info["sources"].append(source)

    def v81_scan_subtitles(self, text, base, source="TEXT", via=""):
        t = _unescape(text)
        if not t: return 0
        self.v81_sub_sources.add(source)
        before = len(self.v81_subs)
        # A) HTML <track>
        for m in re.finditer(r"<track\b[^>]*>", t, re.I):
            tag = m.group(0)
            def attr(n):
                mm = re.search(n + r"\s*=\s*([\"'])(.*?)\1", tag, re.I)
                return mm.group(2) if mm else ""
            src = attr("src") or attr("data-src")
            if src: self.v81_sub_add(src, base, attr("label"), _lang_of(attr("srclang"), attr("label")), attr("kind"), "", source, via or "HTML_TRACK")
        # B) JS/JSON objeleri: {file:"..", label:"..", kind:"captions"}
        for m in re.finditer(r"\{[^{}]{0,900}\}", t):
            o = m.group(0)
            fm = re.search(r"[\"']?(?:file|src|url|path)[\"']?\s*:\s*[\"']([^\"']+)[\"']", o, re.I)
            if not fm: continue
            km = re.search(r"[\"']?kind[\"']?\s*:\s*[\"']([^\"']+)[\"']", o, re.I)
            kind = km.group(1) if km else ""
            f = fm.group(1)
            if not (re.search(r"\." + SUB_EXT_RX + r"(?:$|[?#])", f, re.I) or kind.lower() in ("captions", "subtitles", "subtitle", "caption")):
                continue
            lm = re.search(r"[\"']?(?:label|name|title)[\"']?\s*:\s*[\"']([^\"']*)[\"']", o, re.I)
            gm = re.search(r"[\"']?(?:srclang|language|lang)[\"']?\s*:\s*[\"']([^\"']*)[\"']", o, re.I)
            self.v81_sub_add(f, base, lm.group(1) if lm else "", _lang_of(gm.group(1) if gm else "", lm.group(1) if lm else ""), kind, "", source, via or "JS_OBJECT")
        # C) anahtar = deger (Playerjs "[Turkce]url,[English]url" dahil)
        for m in re.finditer(r"[\"']?(?:subtitles?|captions?|altyazi|altyazılar|sub|subs|tracks?|cc)[\"']?\s*[:=]\s*([\"'])(.*?)\1", t, re.I | re.S):
            val = m.group(2)
            if len(val) > 4000: continue
            parts = [(lb, uu) for lb, uu in re.findall(r"\[([^\]]{1,40})\]\s*([^,\[\s]+)", val)
                     if re.match(r"(?:https?:)?//|/", uu) and not re.search(r"[(){};]|&&|===", uu)]
            if parts:
                for lab, uu in parts: self.v81_sub_add(uu, base, lab, _lang_of(lab, uu), "captions", "", source, via or "PLAYERJS_LIST")
            else:
                for uu in re.split(r"[,\s]+", val):
                    if re.search(r"\." + SUB_EXT_RX + r"(?:$|[?#])", uu, re.I) or uu.startswith(("http", "/")):
                        if re.search(r"\.(?:jpg|png|webp|js|css|m3u8|mp4)(?:$|[?#])", uu, re.I): continue
                        self.v81_sub_add(uu, base, "", "", "captions", "", source, via or "KEY_VALUE")
        # D) duz URL / tirnakli goreli yol
        for m in re.finditer(r"https?://[^\s\"'<>()]+?\." + SUB_EXT_RX + r"(?:\?[^\s\"'<>()]*)?(?=[\s\"'<>(),]|$)", t, re.I):
            self.v81_sub_add(m.group(0), base, "", "", "", "", source, via or "PLAIN_URL")
        for m in re.finditer(r"[\"']((?:\.{0,2}/)?[^\"'\s<>]{1,300}\." + SUB_EXT_RX + r"(?:\?[^\"'\s<>]*)?)[\"']", t, re.I):
            self.v81_sub_add(m.group(1), base, "", "", "", "", source, via or "RELATIVE_PATH")
        # E) HLS
        if t.lstrip().startswith("#EXTM3U"):
            for m in re.finditer(r"#EXT-X-MEDIA:([^\n]+)", t):
                a = m.group(1)
                if "TYPE=SUBTITLES" not in a.upper(): continue
                uri = re.search(r'URI="([^"]+)"', a); lg = re.search(r'LANGUAGE="([^"]+)"', a); nm = re.search(r'NAME="([^"]+)"', a)
                if uri: self.v81_sub_add(uri.group(1), base, nm.group(1) if nm else "", _lang_of(lg.group(1) if lg else "", nm.group(1) if nm else ""), "captions", "HLS_SUBTITLE", source, "HLS_EXT_X_MEDIA")
        # F) packer icindekiler
        if "eval(function(p,a,c,k,e" in t.replace(" ", ""):
            for up in quiet_unpack(t):
                self.v81_sub_sources.add("PACKER")
                self.v81_scan_subtitles(up, base, "PACKER", "PACKER_UNPACK")
        return len(self.v81_subs) - before

    # ------------------------------------------------------- template resolver
    def v81_note_templates(self, ctxs, body, base, label):
        for c in ctxs or []:
            raw = str(c.get("raw") or "")
            data = str(c.get("data") or "")
            is_var_data = bool(data) and bool(re.search(r"[{,]\s*[\w$\"']+\s*:\s*(?![\"'\d])[A-Za-z_$][\w$.()'\"\[\]-]*", data))
            if "${" not in raw and "${" not in data and not ((c.get("method") or "").upper() == "POST" and data) and not is_var_data: continue
            if _is_noise_url(raw): continue
            key = (raw, data, base)
            if key in self.v81_template_done: continue
            self.v81_templates.append({"ctx": c, "script": body, "base": base, "label": label})
            self.log(f"[V81_TEMPLATE_FOUND] {c.get('method')} {raw} data={_short(data, 120) or '-'} in={label}")

    def v81_attr_lookup(self, attr, page, elem_id=""):
        a = re.escape(attr)
        if elem_id:
            for m in re.finditer(r"<[^>]*\bid\s*=\s*[\"']" + re.escape(elem_id) + r"[\"'][^>]*>", page, re.I):
                mm = re.search(a + r"\s*=\s*[\"']([^\"']*)[\"']", m.group(0), re.I)
                if mm: return mm.group(1), f"{attr} @#{elem_id}"
        mm = re.search(r"\b" + a + r"\s*=\s*[\"']([^\"']*)[\"']", page, re.I)
        if mm: return mm.group(1), f"{attr} (sayfadaki ilk eleman)"
        return None, ""

    def v81_resolve_expr(self, expr, script, page, page_url, depth=0):
        e = (expr or "").strip().rstrip(";").strip()
        if not e or depth > 4: return None, ""
        m = re.fullmatch(r"([\"'`])(.*)\1", e, re.S)
        if m and "${" not in m.group(2): return m.group(2), "literal"
        if re.fullmatch(r"-?\d+(?:\.\d+)?", e): return e, "literal"
        loc = urlparse(page_url)
        if re.search(r"(?:window\.)?location\.href|document\.URL", e): return page_url, "location.href"
        if re.search(r"location\.origin", e): return f"{loc.scheme}://{loc.netloc}", "location.origin"
        if re.search(r"location\.pathname", e): return loc.path, "location.pathname"
        if re.search(r"location\.host(?:name)?\b", e): return loc.netloc, "location.host"
        elem_id = ""
        im = re.search(r"getElementById\(\s*[\"']([^\"']+)[\"']\s*\)", e) or re.search(r"querySelector\(\s*[\"']#([\w-]+)[\"']\s*\)", e)
        if im: elem_id = im.group(1)
        am = re.search(r"getAttribute\(\s*[\"'](data-[\w-]+|[\w-]+)[\"']\s*\)", e) or re.search(r"\.attr\(\s*[\"'](data-[\w-]+)[\"']\s*\)", e)
        if am:
            v, src = self.v81_attr_lookup(am.group(1), page, elem_id); return v, src
        dm = re.search(r"\.dataset\.([A-Za-z_]\w*)", e) or re.search(r"\.data\(\s*[\"']([\w-]+)[\"']\s*\)", e)
        if dm:
            name = re.sub(r"([A-Z])", lambda x: "-" + x.group(1).lower(), dm.group(1))
            v, src = self.v81_attr_lookup("data-" + name, page, elem_id); return v, src
        mm = re.search(r"meta\[name=[\"']?([\w:-]+)", e)
        if mm:
            mv = re.search(r"<meta[^>]+name=[\"']" + re.escape(mm.group(1)) + r"[\"'][^>]+content=[\"']([^\"']*)", page, re.I)
            if mv: return mv.group(1), f"meta[{mm.group(1)}]"
        # container.getAttribute(...) -> container tanimini bul
        vm = re.match(r"([A-Za-z_$][\w$]*)\s*\.\s*(getAttribute|dataset|attr|data)", e)
        if vm:
            dm2 = re.search(r"(?:const|let|var)\s+" + re.escape(vm.group(1)) + r"\s*=\s*([^;\n]+)", script)
            if dm2:
                im2 = re.search(r"getElementById\(\s*[\"']([^\"']+)[\"']\s*\)", dm2.group(1)) or re.search(r"querySelector\(\s*[\"']#([\w-]+)", dm2.group(1))
                if im2: return self.v81_resolve_expr(e.replace(vm.group(1), f"document.getElementById('{im2.group(1)}')", 1), script, page, page_url, depth + 1)
        if re.fullmatch(r"[A-Za-z_$][\w$.]*", e):
            return self.v81_resolve_var(e.split(".")[-1], script, page, page_url, depth + 1)
        return None, ""

    def v81_resolve_var(self, name, script, page, page_url, depth=0):
        n = re.escape(name)
        for src_text, where in ((script, "script"), (page, "page")):
            if not src_text: continue
            dm = re.search(r"(?:const|let|var)\s+" + n + r"\s*=\s*([^;\n]+)", src_text)
            if dm:
                v, how = self.v81_resolve_expr(dm.group(1), src_text, page, page_url, depth + 1)
                if v is not None: return v, f"{where}: {name}={_short(dm.group(1), 80)} -> {how}"
            gm = re.search(r"[\"']?\b" + n + r"[\"']?\s*[:=]\s*[\"']([^\"']+)[\"']", src_text)
            if gm: return _unescape(gm.group(1)), f"{where}: {name} global/JSON"
        low = name.lower()
        if low in ("ajaxurl", "ajax_url", "ajaxurlwp", "adminajax", "admin_ajax"):
            fm = re.search(r"https?:\\?/\\?/[^\"'\s<>]+admin-ajax\.php", page) or re.search(r"https?:\\?/\\?/[^\"'\s<>]+admin-ajax\.php", script or "")
            if fm: return _unescape(fm.group(0)), "sayfada admin-ajax.php URL'si"
            o = urlparse(page_url)
            return f"{o.scheme}://{o.netloc}/wp-admin/admin-ajax.php", "TAHMIN (WordPress varsayilani; dogrulanmali)"
        kebab = re.sub(r"([A-Z])", lambda x: "-" + x.group(1).lower(), name).lower()
        for attr in ("data-" + kebab, "data-" + low, "data-" + kebab.replace("-", "_")):
            v, src = self.v81_attr_lookup(attr, page)
            if v is not None: return v, src
        return None, ""

    def v81_run_templates(self, page, page_url, depth):
        if not self.v81_templates: return
        pending, self.v81_templates = self.v81_templates, []
        for item in pending:
            if self.final_verified: return
            c = item["ctx"]; raw = str(c.get("raw") or ""); data = str(c.get("data") or "")
            key = (raw, data, item["base"])
            if key in self.v81_template_done: continue
            self.v81_template_done.add(key)
            danger = re.search(r"report|comment|login|logout|register|signup|like|dislike|vote|rate|rating|watchlist|favorite|favourite|favori|"
                               r"subscribe|chat|message|delete|remove|update|edit|password|profile|follow|notify|progress|history|track|view|"
                               r"watched|mark_|interaction|bookmark|izlendi|izledim|listem|add_|save|seen|reaction|share|ping|heartbeat|log_", raw + " " + data, re.I)
            playerish = re.search(r"player|source|embed|video|stream|episode|bolum|iframe|watch|izle|play|get_|load_?player|alternat|server", raw + " " + data, re.I)
            meth0 = (c.get("method") or "GET").upper()
            if danger or (meth0 != "GET" and not playerish):
                self.log(f"[V81_TEMPLATE_SKIP] {meth0} {raw} -> oynatma ile ilgisiz/yan etkili istek (rapor/yorum/izleme listesi vb.) CAGRILMADI")
                continue
            if not playerish:
                self.log(f"[V81_TEMPLATE_SKIP] {meth0} {raw} -> player ile ilgisiz sablon (sayfalama/filtre), atlandi")
                continue
            names = list(dict.fromkeys(re.findall(r"\$\{\s*([^}]+?)\s*\}", raw + " " + data)))
            values = {}; unresolved = []
            for nm in names:
                v, how = self.v81_resolve_expr(nm, item["script"], page, page_url)
                if v is None and re.fullmatch(r"[A-Za-z_$][\w$]*", nm):
                    v, how = self.v81_resolve_var(nm, item["script"], page, page_url)
                if v is None:
                    unresolved.append(nm)
                else:
                    values[nm] = str(v)
                    rec = {"template": raw, "var": nm, "value": str(v), "from": how, "page": page_url}
                    self.v81_params.append(rec)
                    self.log(f"[V81_PARAM] var={nm} value={_short(v, 160)} from={how}")
            if unresolved:
                self.log(f"[V81_TEMPLATE_UNRESOLVED] vars={','.join(unresolved)} template={raw}")
                self.v81_missing_add("AJAX_TEMPLATE_VAR", f"{','.join(unresolved)} degiskeni bulunamadi -> sablon: {raw} (sayfa: {page_url})")
                continue

            def sub(s):
                return re.sub(r"\$\{\s*([^}]+?)\s*\}", lambda m: values.get(m.group(1).strip(), m.group(0)), s)
            url = urljoin(page_url, sub(raw).strip("`'\""))
            method = (c.get("method") or "GET").upper()
            form = None
            d = sub(data).strip()
            if d:
                d2 = d.strip("`'\"")
                if "=" in d2 and "{" not in d2:
                    form = dict(parse_qsl(d2, keep_blank_values=True))
                elif d2.startswith("{"):
                    form = {}
                    for km, vm in re.findall(r"([\w$]+)\s*:\s*([^,}]+)", d2):
                        v, _ = self.v81_resolve_expr(vm, item["script"], page, page_url)
                        form[km] = str(v if v is not None else vm.strip().strip("'\""))
            self.log(f"[V81_TEMPLATE_CALL] {method} {url} form={form or '-'} referer={page_url}")
            self.v81_template_calls[url] = {"template": raw, "data": data, "page": page_url, "form": form,
                                            "vars": {k: v for k, v in values.items()}}
            r = self.fetch(url, referer=page_url, ajax=True, method=method, data=form)
            if not r:
                self.v81_missing_add("AJAX_CALL_FAILED", f"{method} {url} cevap vermedi")
                continue
            body = _unescape(r["body"]).replace('\\"', '"').replace("\\n", "\n").replace("\\t", " ")
            self.log(f"[V81_TEMPLATE_RESULT] status={r['status']} ct={r['ct']} bytes={len(r['body'])} head={_short(body, 200)!r}")
            if r["status"] >= 400:
                self.v81_missing_add("AJAX_BLOCKED", f"{method} {url} status={r['status']} (header/cookie/nonce gerekebilir)")
                continue
            if self.v81_net and self.v81_net[-1]["url"] == url:
                self.v81_net[-1]["text_unescaped"] = body
            self.v81_scan_subtitles(body, page_url, "AJAX", "AJAX_RESPONSE")
            frames = list(dict.fromkeys(self.iframes(body, page_url) + re.findall(r"<iframe[^>]+(?:data-src|src)\s*=\s*[\"']([^\"']+)", body, re.I)))
            frames = [urljoin(page_url, f) for f in frames if f and not f.startswith(("about:", "javascript:"))]
            media = [u for u in self.direct_media(body, page_url) if not self.page_asset(u)]
            if body.lstrip().startswith(("{", "[")):
                try: media += self.media_urls_from_object(json.loads(r["body"]), page_url)
                except Exception: pass
            self.log(f"[V81_AJAX_RESULT] iframes={len(frames)} media={len(media)}")
            for f in frames[:6]: self.log(f"  [V81_AJAX_IFRAME] {f}")
            for mu in media[:6]: self.log(f"  [V81_AJAX_MEDIA] {mu}")
            for mu in media[:3]:
                self.verify_media(mu, page_url)
                if self.final_verified: return
            for f in frames[:4]:
                if self.is_trailer_url(f): continue
                self.player = self.player or f
                self.walk(f, depth + 1, page_url, "V81_AJAX_IFRAME")
                if self.final_verified: return
            if not frames and not media:
                self.v81_missing_add("AJAX_NO_PLAYER", f"{url} cevabinda iframe/medya yok -> cevap: {_short(body, 160)}")

    # ------------------------------------------------------------ embed follow
    def v81_embed_follow(self, u, r, referer):
        try:
            if not r or self.final_verified or u in self.visited: return
            ct = (r.get("ct") or "").lower(); head = (r.get("body") or "")[:400].lower()
            if "html" in ct or "<html" in head or "<!doctype" in head or "<script" in head:
                self.log(f"[V81_EMBED_FOLLOW] medya sanilan adres HTML dondu -> player sayfasi olarak takip: {u}")
                self.walk(u, 1, referer, "V81_EMBED_FOLLOW")
        except Exception as e:
            self.log(f"[V81_EMBED_FOLLOW_ERROR] {type(e).__name__}: {e}")

    # ------------------------------------------------ unpacked media verify
    def v81_verify_unpacked(self, unpacked, label):
        """Packer/decode ile acilan koddaki medya URL'lerini statik dogrula.
        (V75+ tarayici runtime kapali oldugu icin bu adaylar aksi halde bosa dusuyordu.)"""
        if self.final_verified: return
        m = re.search(r"https?://\S+", str(label or ""))
        page = m.group(0) if m else (getattr(self, "v81_root_url", "") or "")
        t = _unescape(unpacked)
        cands = []
        for mm in re.finditer(r"https?://[^\s\"'<>()\\]+?\.(?:m3u8|mpd|mp4)(?:\?[^\s\"'<>()\\]*)?", t, re.I):
            cands.append(mm.group(0))
        for mm in re.finditer(r"[\"']?(?:file|src|source|hls|url)[\"']?\s*:\s*[\"']([^\"']+\.(?:m3u8|mpd|mp4)[^\"']*)[\"']", t, re.I):
            cands.append(urljoin(page, mm.group(1)))
        cands = [c for c in dict.fromkeys(cands) if not self.page_asset(c)]
        if not cands: return
        self.log(f"[V81_UNPACKED_MEDIA] count={len(cands)} page={page}")
        for c in cands[:5]:
            if self.v37_ad_media_evidence(c):
                self.v81_ads.append({"url": c, "root": c, "reason": "AD_PATH", "duration_s": None})
                self.log(f"[V81_AD_REJECT] reason=AD_PATH url={c}"); continue
            self.log(f"  [V81_UNPACKED_MEDIA] verify {c} referer={page}")
            self.verify_media(c, page)
            if self.final_verified: return

    def v81_verify_text_media(self, text, page, source="MITM_FRAME"):
        """Bir cevabin icindeki (duz + packer + JSON) medya URL'lerini dogrular. Sonucu kaydeder."""
        if self.final_verified: return
        t = _unescape(text).replace('\\"', '"')
        packed = quiet_unpack(t) if "eval(function(p,a,c,k,e" in t.replace(" ", "") else []
        found = []
        t = t.replace("&quot;", '"')
        for blob in [t] + packed:
            for mm in re.finditer(r"https?://[^\s\"'<>()\\]+?\.(?:m3u8|mpd|mp4)(?:\?[^\s\"'<>()\\]*)?", blob, re.I):
                found.append(mm.group(0))
            for mm in re.finditer(r"[\"']?(?:file|src|source|hls|url)[\"']?\s*:\s*[\"']([^\"']+\.(?:m3u8|mpd|mp4)[^\"']*)[\"']", blob, re.I):
                found.append(urljoin(page, mm.group(1)))
        if t.lstrip().startswith(("{", "[")):
            try: found += self.media_urls_from_object(json.loads(t), page)
            except Exception: pass
        found = [f.replace("&quot;", "") for f in dict.fromkeys(found) if not self.page_asset(f) and not _is_noise_url(f)]
        players = re.findall(r"\b(jwplayer|videojs|Plyr|Clappr|playerjs|hls\.js|new Hls|fluidPlayer|DPlayer|ArtPlayer)\b", t + " ".join(packed), re.I)
        info = {"url": page, "source": source, "bytes": len(text), "packer": bool(packed), "media": found[:6],
                "player": sorted(set(p.lower() for p in players))[:5],
                "autostart_false": bool(re.search(r"autostart\s*[:=]\s*[\"']?false", t + " ".join(packed), re.I))}
        self.v81_frame_scan.append(info)
        self.log(f"[V81_FRAME_SCAN] {source} url={page} bytes={len(text)} packer={info['packer']} player={','.join(info['player']) or '-'} media={len(found)} autostart_false={info['autostart_false']}")
        tclean = t.replace("&quot;", '"').replace("\\/", "/")
        for f in found[:8]:
            if self.v37_ad_media_evidence(f):
                self.v81_ads.append({"url": f, "root": f, "reason": "AD_PATH", "duration_s": None}); continue
            adc = self.v81_ad_context(f, tclean)
            if adc:
                self.v81_ads.append({"url": f, "root": f, "reason": f"AD_CONTEXT({adc})", "duration_s": None})
                self.log(f"  [V81_AD_REJECT] reason=AD_CONTEXT('{adc}') url={f} -> reklam listesinde (preroll/ads), dogrulanmadi")
                continue
            self.log(f"  [V81_FRAME_MEDIA] verify {f} referer={page}")
            self.v81_media_referer.setdefault(f, page)
            self.verify_media(f, page, extra_context={"referer": page, "siteurl": f"{urlparse(page).scheme}://{urlparse(page).netloc}"})
            if self.final_verified:
                o = urlparse(page)
                self.final_playback_context.update({"url": self.final, "headers": {"User-Agent": V81_UA, "Referer": page, "Origin": f"{o.scheme}://{o.netloc}"},
                                                    "referer": page, "source": "V81_MITM_FRAME_TEXT"})
                self.log(f"[V81_FRAME_FINAL] Play'e basilmadan player kodundan bulundu: {self.final}")
                return

    AD_CONTEXT_RX = re.compile(r"pre-?roll|mid-?roll|post-?roll|[\"'&]ads?[\"'&]?\s*:|\bad[-_]?(?:video|url|tag|break|src|media)\b|vast|vmap|skip-?time|skipoffset|data-ad|reklam|sponsor|\"link\"\s*:|&quot;link&quot;", re.I)

    def v81_ad_context(self, url, text):
        """URL metinde reklam baglaminda mi geciyor? (data-preroll, ads:[...], vast, link+video ciftleri)"""
        try:
            t = str(text or "")
            for nd in (url, url.replace("/", "\\/")):
                p = t.find(nd)
                while p >= 0:
                    win = t[max(0, p - 400): p + len(nd) + 200]
                    m = self.AD_CONTEXT_RX.search(win)
                    if m: return m.group(0)
                    p = t.find(nd, p + 1)
        except Exception:
            pass
        return ""

    def v81_mp4_duration(self, url, referer=""):
        """MP4 'mvhd' kutusundan sure (sn). moov sondaysa None."""
        h = {"User-Agent": V81_UA, "Range": "bytes=0-262143"}
        if referer: h["Referer"] = referer
        try:
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=12, context=ssl._create_unverified_context()) as resp:
                raw = resp.read(262144)
        except Exception:
            return None
        i = raw.find(b"mvhd")
        if i < 0 or i + 32 > len(raw): return None
        ver = raw[i + 4]
        try:
            if ver == 1:
                ts = int.from_bytes(raw[i + 24:i + 28], "big"); du = int.from_bytes(raw[i + 28:i + 36], "big")
            else:
                ts = int.from_bytes(raw[i + 16:i + 20], "big"); du = int.from_bytes(raw[i + 20:i + 24], "big")
            return round(du / ts, 1) if ts else None
        except Exception:
            return None

    def v81_mp4_is_ad(self, url, referer=""):
        ctx = ""
        for r in self.v81_net:
            if r.get("text") and url in r["text"].replace("\\/", "/"):
                ctx = self.v81_ad_context(url, r["text"].replace("\\/", "/").replace("&quot;", '"'))
                if ctx: break
        dur = self.v81_mp4_duration(url, referer)
        self.log(f"[V81_MP4_DURATION] {dur if dur is not None else '?'} sn url={url}" + (f" reklam_baglami='{ctx}'" if ctx else ""))
        reason = ""
        if ctx: reason = f"AD_CONTEXT({ctx})"
        elif dur is not None and dur < 120: reason = f"SHORT_MP4_{dur:.0f}s"
        if reason:
            self.v81_ads.append({"url": url, "root": url, "reason": reason, "duration_s": dur})
            self.log(f"[V81_AD_REJECT] reason={reason} url={url} -> reklam/on-gosterim MP4, final secilmedi; dinleme suruyor (Chrome'da reklamlari gec/Play'e bas)")
            return True
        return False

    # ------------------------------------------------------- AES config decrypt
    def v81_try_decrypt_json(self, text, src_url=""):
        """{c|ct|cipher|data, iv, k1/k2/key...} gibi sifreli player config'lerini bilinen kaliplarla acmayi dener.
        Basarida (duz_metin, formul) dondurur. Anahtar uydurmaz: sadece cevaptaki/oturumdaki degerleri birlestirir."""
        try:
            obj = json.loads(text)
        except Exception:
            return None
        found = []
        def walk(o, path=""):
            if isinstance(o, dict):
                keys = {k.lower(): k for k in o.keys()}
                ck = next((keys[k] for k in ("c", "ct", "cipher", "ciphertext", "data", "enc", "payload", "e") if k in keys and isinstance(o[keys[k]], str)), None)
                ivk = next((keys[k] for k in ("iv", "i", "nonce") if k in keys and isinstance(o[keys[k]], str)), None)
                if ck and ivk:
                    found.append((path, o, ck, ivk))
                for k, v in o.items(): walk(v, path + "." + str(k))
            elif isinstance(o, list):
                for i, v in enumerate(o): walk(v, f"{path}[{i}]")
        walk(obj)
        for path, o, ck, ivk in found:
            c = _b64(o[ck]); iv = _b64(o[ivk])
            if not c or not iv or len(iv) != 16 or len(c) % 16: continue
            keyvals = {k: _b64(v) for k, v in o.items() if k not in (ck, ivk) and isinstance(v, str) and _b64(v) and len(_b64(v)) in (16, 24, 32)}
            # oturumdaki token'lar (or. /ajax-token {"t":"hex"})
            for r in self.v81_net[-200:]:
                tt = r.get("text") or ""
                if r.get("dest") in ("empty", "xhr") and len(tt) < 400:
                    for m in re.finditer(r'"(\w{1,12})"\s*:\s*"([0-9a-fA-F]{32}|[0-9a-fA-F]{64})"', tt):
                        try: keyvals[f"{urlparse(r['url']).path}.{m.group(1)}"] = bytes.fromhex(m.group(2))
                        except Exception: pass
            cands = []
            names = list(keyvals.keys())
            for n in names: cands.append((n, keyvals[n]))
            for a, b in itertools.combinations(names, 2):
                ka, kb = keyvals[a], keyvals[b]
                if len(ka) == len(kb):
                    cands.append((f"{a} XOR {b}", bytes(x ^ y for x, y in zip(ka, kb))))
                cands.append((f"sha256({a}+{b})", hashlib.sha256(ka + kb).digest()))
                cands.append((f"sha256({b}+{a})", hashlib.sha256(kb + ka).digest()))
            for n in names: cands.append((f"sha256({n})", hashlib.sha256(keyvals[n]).digest()))
            for name, key in cands:
                if len(key) not in (16, 24, 32): continue
                try:
                    txt = _unpad_ok(_aes_cbc(c, key, iv))
                except Exception:
                    txt = None
                if txt:
                    formula = f"AES-{len(key) * 8}-CBC(veri={path.lstrip('.')}.{ck}, iv={path.lstrip('.')}.{ivk}, key={name}) PKCS7"
                    self.log(f"[V81_DECRYPT_OK] {src_url} -> {formula} => {_short(txt, 300)}")
                    return txt, formula
            self.log(f"[V81_DECRYPT_FAIL] {src_url} sifreli alan {path}.{ck} acilamadi; denenen anahtar adaylari: {', '.join(n for n, _ in cands[:12])}")
        return None

    # -------------------------------------------------------------- HLS / ads
    def v81_hls_root(self, body, url):
        try:
            info = self.v81_hls_info.setdefault(url, {})
            variants = []
            lines = str(body or "").splitlines()
            for i, ln in enumerate(lines):
                if ln.startswith("#EXT-X-STREAM-INF"):
                    res = re.search(r"RESOLUTION=(\d+x\d+)", ln); bw = re.search(r"BANDWIDTH=(\d+)", ln)
                    nxt = next((x.strip() for x in lines[i + 1:] if x.strip() and not x.startswith("#")), "")
                    variants.append({"resolution": res.group(1) if res else "", "bandwidth": bw.group(1) if bw else "", "url": urljoin(url, nxt)})
            audio = []
            for m in re.finditer(r"#EXT-X-MEDIA:([^\n]+)", body or ""):
                a = m.group(1)
                if "TYPE=AUDIO" in a.upper():
                    lg = re.search(r'LANGUAGE="([^"]+)"', a); nm = re.search(r'NAME="([^"]+)"', a); uri = re.search(r'URI="([^"]+)"', a)
                    audio.append({"lang": lg.group(1) if lg else "", "name": nm.group(1) if nm else "", "url": urljoin(url, uri.group(1)) if uri else ""})
            keys = []
            for m in re.finditer(r"#EXT-X-KEY:([^\n]+)", body or ""):
                meth = re.search(r"METHOD=([\w-]+)", m.group(1)); uri = re.search(r'URI="([^"]+)"', m.group(1))
                if meth and meth.group(1).upper() != "NONE":
                    keys.append({"method": meth.group(1), "url": urljoin(url, uri.group(1)) if uri else ""})
            info.update({"variants": variants, "audio": audio, "keys": keys})
            if variants: self.log(f"[V81_HLS_VARIANTS] " + " | ".join(f"{v['resolution'] or '?'}@{v['bandwidth'] or '?'}" for v in variants))
            for a in audio: self.log(f"[V81_HLS_AUDIO] lang={a['lang'] or '-'} name={a['name'] or '-'} url={a['url']}")
            for k in keys: self.log(f"[V81_HLS_KEY] method={k['method']} url={k['url']} (eklentide anahtar URL'si de ayni header'larla erisilebilir olmali)")
            self.v81_scan_subtitles(body, url, "HLS_MANIFEST", "HLS_EXT_X_MEDIA")
        except Exception as e:
            self.log(f"[V81_HLS_ROOT_ERROR] {type(e).__name__}: {e}")

    def v81_ad_check(self, root_url, playlist_body, playable_url):
        """True => reklam; final secilmez."""
        try:
            durs = [float(x) for x in re.findall(r"#EXTINF:\s*([\d.]+)", playlist_body or "")]
            total = sum(durs); endlist = "#EXT-X-ENDLIST" in (playlist_body or "")
            keys = re.findall(r"#EXT-X-KEY:[^\n]*METHOD=([\w-]+)", playlist_body or "")
            info = self.v81_hls_info.setdefault(playable_url, {})
            info.update({"duration_s": round(total, 1), "segments": len(durs), "endlist": endlist})
            if keys and not any(k.upper() == "NONE" for k in keys):
                km = re.search(r'#EXT-X-KEY:[^\n]*URI="([^"]+)"', playlist_body or "")
                info.setdefault("keys", []).append({"method": keys[0], "url": urljoin(playable_url, km.group(1)) if km else ""})
                self.log(f"[V81_HLS_KEY] method={keys[0]} url={info['keys'][-1]['url']} (media playlist)")
            self.log(f"[V81_HLS_DURATION] total={total:.1f}s segments={len(durs)} endlist={endlist} live={not endlist} url={playable_url}")
            reason = ""
            if self.v37_ad_media_evidence(root_url) or self.v37_ad_media_evidence(playable_url):
                reason = "AD_PATH"
            elif endlist and 0 < total < 60:
                reason = f"SHORT_VOD_{total:.0f}s"
            if reason:
                self.v81_ads.append({"url": playable_url, "root": root_url, "reason": reason, "duration_s": round(total, 1)})
                self.log(f"[V81_AD_REJECT] reason={reason} url={playable_url} -> reklam/on-gosterim, final secilmedi; dinleme suruyor")
                return True
        except Exception as e:
            self.log(f"[V81_AD_CHECK_ERROR] {type(e).__name__}: {e}")
        return False

    # ------------------------------------------------------- MITM (F12) path
    def v81_ingest_mitm_row(self, r):
        try:
            if r.get("kind") != "net": return
            row = self.v81_record("MITM", r.get("method"), r.get("url", ""), r.get("req_headers") or {}, r.get("post", ""),
                                  r.get("status", 0), r.get("content_type", ""), r.get("text", ""),
                                  dest=r.get("dest", ""), resp_headers=r.get("resp_headers") or {},
                                  nbytes=r.get("bytes"), ts=r.get("ts"), media_kind=r.get("media_kind", ""))
            if row is None: return
            u = row["url"]; ct = row["ct"].lower(); txt = row["text"]
            ref = row["req_headers"].get("referer", "")
            if r.get("subtitle"):
                ok = row["status"] in (200, 206) and (txt.lstrip().startswith(("WEBVTT", "[Script Info]", "<?xml", "<tt", "1\n", "1\r")) or "-->" in txt[:2000])
                self.v81_sub_add(u, ref or u, "", _lang_of(u), "captions", "", "MITM_NETWORK", "NETWORK_REQUEST")
                if u in self.v81_subs:
                    self.v81_subs[u]["valid"] = bool(ok); self.v81_subs[u]["found_in"] = ref or self.v81_subs[u]["found_in"]
                    self.v81_subs[u]["req_headers"] = {k: v for k, v in row["req_headers"].items() if k in ("referer", "origin", "cookie")}
            if txt and txt.lstrip().startswith("{") and len(txt) < 20000 and re.search(r'"iv"\s*:', txt):
                dec = self.v81_try_decrypt_json(txt, u)
                if dec:
                    row["decrypted"] = dec[0]; row["decrypt_formula"] = dec[1]
                    if dec[0].startswith(("http://", "https://")) and not _is_noise_url(dec[0]):
                        self.log(f"[V81_DECRYPTED_URL] {dec[0]}")
            if txt and any(x in ct for x in ("html", "json", "javascript", "mpegurl", "text/plain")) and len(txt) < 800_000:
                self.v81_scan_subtitles(txt, row["eff_url"], "MITM_" + (row["dest"] or "RESP").upper(), "")
                if txt.lstrip().startswith("#EXTM3U"):
                    self.v81_hls_root(txt, u)
                    self.v81_force_media.add(u)
                    if row["status"] in (200, 206) and u not in self.v81_hls_tried:
                        kind = "MASTER" if "#EXT-X-STREAM-INF" in txt else ("MEDIA" if "#EXTINF" in txt else "OTHER")
                        self.log(f"[V81_HIDDEN_PLAYLIST] Content-Type={row['ct'] or '-'} ama govde #EXTM3U ({kind}) -> HLS adayi: {u}")
                        self.v81_hls_queue.append((0 if kind == "MASTER" else 1, u, ref))
                # Player frame / ajax cevabindaki medya URL'lerini Play beklemeden dogrula
                if row["dest"] in ("iframe", "document", "empty", "xhr", "") and not _is_noise_url(u) and "javascript" not in ct:
                    self.v81_mitm_text_queue.append((txt, u))
        except Exception as e:
            self.log(f"[V81_INGEST_ERROR] {type(e).__name__}: {e}")

    def v3_mitm_chrome_fallback(self, root_url):
        """V80 MITM yolu + V81: tam ag kaydi, reklam atlama, final sonrasi altyazi icin ek dinleme."""
        if self.final_verified: return True
        self.v3_mitm_fallback_used = True; self.v81_mitm_used = True
        self.log("[V3_MITM_FALLBACK] START"); mitm_proc = None
        try:
            import shutil as _shutil, socket as _socket
            ROOT = getattr(self, "v81_root_dir", None)
            from pathlib import Path
            ROOT = Path(ROOT) if ROOT else Path(__file__).resolve().parent
            mitmdump = _shutil.which("mitmdump") or _shutil.which("mitmdump.exe")
            if not mitmdump:
                self.log("[V3_MITM_FALLBACK] mitmdump bulunamadi")
                self.v81_missing_add("TOOL", "mitmdump bulunamadi -> tarayici trafigi (F12) toplanamadi; pip install mitmproxy")
                return False
            cc = [r"C:\Program Files\Google\Chrome\Application\chrome.exe", r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                  os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "Application", "chrome.exe")]
            chrome = next((p for p in cc if p and os.path.isfile(p)), None)
            if not chrome:
                self.log("[V3_MITM_FALLBACK] Chrome bulunamadi")
                self.v81_missing_add("TOOL", "Chrome bulunamadi -> tarayici trafigi toplanamadi")
                return False
            sk = _socket.socket(); sk.bind(("127.0.0.1", 0)); port = sk.getsockname()[1]; sk.close()
            work = ROOT / "v3_mitm_output"; work.mkdir(exist_ok=True); cap = work / "media_live.jsonl"; cap.unlink(missing_ok=True)
            try:
                import shutil as _sh
                for _old in work.glob("cache_*"): _sh.rmtree(_old, ignore_errors=True)
            except Exception: pass
            addon = ROOT / "v3_mitm_capture.py"
            mitm_proc = subprocess.Popen([mitmdump, "--listen-host", "127.0.0.1", "--listen-port", str(port), "-s", str(addon),
                                          "--ssl-insecure", "--set", "connection_strategy=lazy", "--set", f"resolver_capture={cap}"], cwd=str(ROOT))
            time.sleep(2)
            if mitm_proc.poll() is not None:
                self.log("[V3_MITM_FALLBACK] mitmdump kapandi"); return False
            profile = str((work / "chrome_profile").resolve())
            subprocess.Popen([chrome, "--proxy-server=http://127.0.0.1:" + str(port), "--proxy-bypass-list=<-loopback>",
                              "--disable-quic", "--user-data-dir=" + profile,
                              # V81: Chrome disk onbellegi scriptleri hic istemeden kullaniyordu -> F12 kaydinda scriptler eksik kaliyordu
                              "--disk-cache-dir=" + str((work / f"cache_{int(time.time())}").resolve()), "--disk-cache-size=1",
                              "--media-cache-size=1", "--aggressive-cache-discard", root_url])
            self.log("[V81_MITM] Chrome onbellegi kapali (her calistirmada yeni cache klasoru) -> tum scriptler/istekler kayda girer")
            self.log(f"[V3_MITM_FALLBACK] NORMAL_CHROME_OPEN original_url={root_url} proxy=127.0.0.1:{port}")
            self.log("[V3_MITM_FALLBACK] ssl-insecure + lazy + disable-quic ACTIVE")
            self.log("[V81_MITM] Acilan Chrome'da gerekiyorsa Play'e bas; 45 sn dinleniyor (final sonrasi +8 sn altyazi icin).")
            listen = int(os.environ.get("V81_LISTEN_SECONDS", "45") or 45)
            deadline = time.time() + listen; seen = set(); pos = 0; grace_until = 0
            buf = ""
            while time.time() < deadline:
                if self.final_verified and not grace_until:
                    grace_until = time.time() + 8
                    self.log("[V81_MITM] final bulundu; altyazi/ek istekler icin 8 sn daha dinleniyor")
                if grace_until and time.time() > grace_until: break
                time.sleep(.5)
                if not cap.exists(): continue
                try:
                    with cap.open("r", encoding="utf-8", errors="ignore") as f:
                        f.seek(pos); chunk = f.read(); pos = f.tell()
                except Exception:
                    continue
                buf += chunk
                lines = buf.split("\n"); buf = lines.pop()
                while self.v81_mitm_text_queue and not self.final_verified:
                    _t, _u = self.v81_mitm_text_queue.pop(0)
                    try: self.v81_verify_text_media(_t, _u, "MITM_FRAME")
                    except Exception as _e: self.log(f"[V81_FRAME_SCAN_ERROR] {type(_e).__name__}: {_e}")
                self.v81_hls_queue.sort(key=lambda x: x[0])
                while self.v81_hls_queue and not self.final_verified:
                    _p, _u, _ref = self.v81_hls_queue.pop(0)
                    if _u in self.v81_hls_tried: continue
                    self.v81_hls_tried.add(_u)
                    self.v81_media_referer.setdefault(_u, _ref)
                    self.browser_request_context.setdefault(_u, {"referer": _ref, "user-agent": V81_UA})
                    self.verify_media(_u, _ref, extra_context={"referer": _ref})
                    if self.final_verified:
                        _o = urlparse(_ref) if _ref else None
                        hh = {"User-Agent": V81_UA}
                        if _ref: hh["Referer"] = _ref; hh["Origin"] = f"{_o.scheme}://{_o.netloc}"
                        self.final_playback_context.update({"url": self.final, "headers": hh, "referer": _ref, "source": "V81_HIDDEN_PLAYLIST"})
                        self.log(f"[V81_HIDDEN_PLAYLIST_FINAL] {self.final}")
                for line in lines:
                    try: r = json.loads(line)
                    except Exception: continue
                    k = str(r.get("kind") or "")
                    if k == "net":
                        self.v81_ingest_mitm_row(r); continue
                    if self.final_verified: continue
                    u = str(r.get("url") or "")
                    if not u or u in seen or k not in ("hls", "dash", "mp4", "webm", "video", "segment_html"): continue
                    seen.add(u); h = r.get("headers") or {}
                    ref = str(h.get("referer") or h.get("Referer") or ""); origin = str(h.get("origin") or h.get("Origin") or "")
                    cookie = str(h.get("cookie") or h.get("Cookie") or ""); ua = str(h.get("user-agent") or h.get("User-Agent") or V81_UA)
                    ctx = {"referer": ref, "origin": origin, "cookie": cookie, "user-agent": ua}
                    self.browser_request_context[u] = ctx; self.browser_media_context[u] = ctx
                    self.log(f"[V3_MITM_MEDIA] {k.upper()} {u}")
                    if self.v37_ad_media_evidence(u, ref):
                        self.v81_ads.append({"url": u, "root": u, "reason": "AD_PATH_OR_REFERER", "duration_s": None})
                        self.log(f"[V81_AD_REJECT] reason=AD_PATH_OR_REFERER url={u}"); continue
                    if k == "segment_html":
                        fam = str(r.get("segment_family") or "")
                        self.log(f"[V3_MITM_DISGUISED_SEGMENT] bytes={r.get('body_bytes', 0)} family={fam} url={u}")
                        self.v3_mitm_disguised_media_seen = True
                        self.v3_mitm_disguised_media_family = fam
                        continue
                    self.v81_media_referer[u] = ref
                    ctm = str(r.get("content_type") or "").lower()
                    if k in ("hls", "dash") and ("mpegurl" in ctm or "dash+xml" in ctm):
                        self.v81_force_media.add(u)
                    self.verify_media(u, ref, extra_context={"referer": ref, "siteurl": origin})
                    if self.final_verified:
                        hh = {"User-Agent": ua}
                        if ref: hh["Referer"] = ref
                        if origin: hh["Origin"] = origin
                        if cookie: hh["Cookie"] = cookie
                        self.final_playback_context.update({"url": self.final, "headers": hh, "referer": ref, "origin": origin,
                                                            "source": "V3_FIX_MITMPROXY_NORMAL_CHROME"})
                        self.log(f"[V3_MITM_FINAL] {self.final_type} {self.final}")
            while self.v81_mitm_text_queue and not self.final_verified:
                _t, _u = self.v81_mitm_text_queue.pop(0)
                try: self.v81_verify_text_media(_t, _u, "MITM_FRAME")
                except Exception as _e: self.log(f"[V81_FRAME_SCAN_ERROR] {type(_e).__name__}: {_e}")
            if not self.final_verified:
                    self.v81_hls_queue.sort(key=lambda x: x[0])
                    while self.v81_hls_queue and not self.final_verified:
                        _p, _u, _ref = self.v81_hls_queue.pop(0)
                        if _u in self.v81_hls_tried: continue
                        self.v81_hls_tried.add(_u)
                        self.v81_media_referer.setdefault(_u, _ref)
                        self.browser_request_context.setdefault(_u, {"referer": _ref, "user-agent": V81_UA})
                        self.verify_media(_u, _ref, extra_context={"referer": _ref})
                        if self.final_verified:
                            _o = urlparse(_ref) if _ref else None
                            hh = {"User-Agent": V81_UA}
                            if _ref: hh["Referer"] = _ref; hh["Origin"] = f"{_o.scheme}://{_o.netloc}"
                            self.final_playback_context.update({"url": self.final, "headers": hh, "referer": _ref, "source": "V81_HIDDEN_PLAYLIST"})
                            self.log(f"[V81_HIDDEN_PLAYLIST_FINAL] {self.final}")
            # Segment sanilan medya geldiyse onu iceren playlist'i bul
            if not self.final_verified:
                for rej in list(self.v81_media_rejects):
                    bn = urlparse(rej["url"]).path.rsplit("/", 1)[-1]
                    if not bn: continue
                    for r2 in self.v81_net:
                        if r2.get("text", "").lstrip().startswith("#EXTM3U") and bn in r2["text"] and r2["url"] not in self.v81_hls_tried:
                            self.log(f"[V81_SEGMENT_PARENT] {bn} bir SEGMENT; onu listeleyen playlist: {r2['url']}")
                            self.v81_hls_tried.add(r2["url"]); self.v81_force_media.add(r2["url"])
                            ref2 = r2["req_headers"].get("referer", "")
                            self.verify_media(r2["url"], ref2, extra_context={"referer": ref2})
                            if self.final_verified: break
                    if self.final_verified: break
            if not self.final_verified:
                if getattr(self, "v3_mitm_disguised_media_seen", False):
                    self.log(f"[V3_MITM_MEDIA_PROOF] DISGUISED_SEGMENT_FLOW_CONFIRMED family={getattr(self, 'v3_mitm_disguised_media_family', '')}")
                    self.log("[V3_MITM_FALLBACK] MEDIA_FLOW_PROVEN_BUT_NO_STANDALONE_MANIFEST")
                else:
                    self.log("[V3_MITM_FALLBACK] NO_FINAL_MEDIA")
            mitm_rows = sum(1 for x in self.v81_net if x["src"] == "MITM")
            self.log(f"[V81_MITM] kaydedilen ag satiri={mitm_rows}")
            if mitm_rows == 0:
                self.v81_missing_add("MITM_NO_TRAFFIC", "Chrome proxy uzerinden hic trafik gelmedi (Chrome zaten acikti/profil kilitli ya da sertifika sorunu)")
            return bool(self.final_verified)
        except Exception as e:
            self.v3_mitm_fallback_error = f"{type(e).__name__}: {e}"
            self.log(f"[V3_MITM_FALLBACK_ERROR] {type(e).__name__}: {str(e)[:500]}"); return False
        finally:
            if mitm_proc is not None:
                try: mitm_proc.terminate()
                except Exception: pass

    # ------------------------------------------------------------ provenance
    def v81_row_texts(self, idx, row):
        """(text, via) listesi: duz, kacissiz, packer acilmis, base64 cozulmus."""
        if idx in self.v81_unpack_cache: return self.v81_unpack_cache[idx]
        t = row.get("text") or ""
        out = []
        if t:
            out.append((t, "PLAIN"))
            ut = _unescape(t).replace('\\"', '"')
            if ut != t: out.append((ut, "JSON_ESCAPED"))
            if row.get("text_unescaped"): out.append((row["text_unescaped"], "JSON_ESCAPED"))
            if row.get("decrypted"): out.append((row["decrypted"], "AES_DECRYPT"))
            if "eval(function(p,a,c,k,e" in t.replace(" ", ""):
                for up in quiet_unpack(t): out.append((_unescape(up), "PACKER"))
            if len(t) < 1_500_000:
                for bm in re.finditer(r"[\"']([A-Za-z0-9+/=_-]{40,})[\"']", t):
                    s = bm.group(1)
                    try:
                        dec = base64.b64decode(s + "=" * (-len(s) % 4), altchars=b"-_" if ("-" in s or "_" in s) else None).decode("utf-8", "ignore")
                    except Exception:
                        continue
                    if ("http" in dec or "/" in dec) and sum(ch.isprintable() for ch in dec) > len(dec) * 0.9:
                        out.append((dec, "BASE64"))
        self.v81_unpack_cache[idx] = out
        return out

    def v81_needles(self, u):
        exact = [u, u.replace("/", "\\/")]
        try:
            exact.append(unquote(u))
            p = urlparse(u)
            if p.query: exact.append(u.split("?", 1)[0])
            path = p.path
            weak = []
            if len(path) > 8: weak += [path, path.replace("/", "\\/")]
            toks = sorted(set(re.findall(r"[A-Za-z0-9]{16,}", path)), key=len, reverse=True)
            weak += toks[:2]
            basename = path.rsplit("/", 1)[-1]
            return list(dict.fromkeys(x for x in exact if x)), weak, basename
        except Exception:
            return exact, [], ""

    def v81_find_parent(self, child_url, child_ts, exclude):
        exact, weak, basename = self.v81_needles(child_url)
        best = None
        for idx, row in enumerate(self.v81_net):
            if row["url"] in exclude or row["url"] == child_url or row.get("eff_url") == child_url: continue
            if row["status"] and row["status"] >= 400: continue
            if child_ts and row["ts"] > child_ts + 2: continue
            row_best = None
            for text, via in self.v81_row_texts(idx, row):
                strength = 0; needle = ""
                for nd in exact:
                    if nd and nd in text: strength, needle = 3, nd; break
                if not strength:
                    for nd in weak:
                        if nd and nd in text: strength, needle = 2, nd; break
                if not strength and basename and len(basename) > 4 and text.lstrip().startswith("#EXTM3U") and basename in text:
                    strength, needle = 2, basename
                if not strength: continue
                via_rank = {"PLAIN": 3, "JSON_ESCAPED": 2, "PACKER": 1, "BASE64": 1, "AES_DECRYPT": 1}.get(via, 0)
                if row_best is None or (strength, via_rank) > row_best[0]:
                    pos = text.find(needle)
                    row_best = ((strength, via_rank), via if strength == 3 else via + "+PARTIAL",
                                text[max(0, pos - 160): pos + len(needle) + 80], needle)
            if not row_best: continue
            dest_bonus = {"document": 3, "iframe": 3, "xhr": 2, "empty": 2, "media": 2, "": 1}.get(row["dest"], 0)
            score = (row_best[0][0], dest_bonus, row["ts"])
            if best is None or score > best[0]:
                best = (score, idx, row_best[1], row_best[2], row_best[3])
        return best

    def v81_first_ts(self, url):
        ts = [r["ts"] for r in self.v81_net if r["url"] == url or r.get("eff_url") == url]
        return min(ts) if ts else None

    def v81_trace(self, final_url):
        chain = []; exclude = set(); cur = final_url; hops = 0
        proof = getattr(self, "v32_proof", {}) or {}
        root_manifest = proof.get("root") if proof.get("verified") else ""
        while cur and hops < 10:
            hops += 1; exclude.add(cur)
            if root_manifest and cur != root_manifest and cur == final_url and root_manifest != final_url:
                mrow = next((r for r in self.v81_net if r["url"] == root_manifest or r.get("eff_url") == root_manifest), None)
                chain.append({"child": cur, "parent": root_manifest, "via": "HLS_MASTER_VARIANT", "snippet": "#EXT-X-STREAM-INF -> " + cur.rsplit("/", 1)[-1],
                              "needle": cur.rsplit("/", 1)[-1], "row": mrow})
                cur = root_manifest; continue
            if cur in self.v81_template_calls:
                tc = self.v81_template_calls[cur]
                prow = next((r for r in self.v81_net if r["url"] == tc["page"] or r.get("eff_url") == tc["page"]), None)
                chain.append({"child": cur, "parent": tc["page"], "via": "AJAX_TEMPLATE", "row": prow,
                              "snippet": f"JS sablonu: {tc['template']}" + (f" body={tc['data']}" if tc.get("data") else "") +
                                         " | degiskenler: " + ", ".join(f"{k}={v}" for k, v in tc["vars"].items()),
                              "needle": ", ".join(tc["vars"].keys())})
                if tc["page"] == self.v81_root_url: break
                cur = tc["page"]; continue
            # XHR/POST istekleri: parent = istegi atan sayfa (referer). Parametre kaynaklari + istegi kuran script.
            xrow = next((r for r in self.v81_net if r["url"] == cur and r["src"] == "MITM"), None)
            if xrow and (xrow["method"] == "POST" or xrow["dest"] in ("empty", "xhr")) and xrow["req_headers"].get("referer") \
                    and not (xrow.get("media_kind") or "mpegurl" in xrow["ct"].lower() or (xrow.get("text") or "").lstrip().startswith("#EXTM3U")):
                ref = xrow["req_headers"]["referer"]
                if ref not in exclude:
                    cands_p = [r for r in self.v81_net if (r["url"] == ref or r.get("eff_url") == ref)]
                    # ayni tarayici oturumu (MITM) ve istekten ONCE gelen kopya tercih edilir; statik kopyada token farkli olabilir
                    prow = next((r for r in reversed(cands_p) if r["src"] == "MITM" and r["ts"] <= xrow["ts"]), None) or (cands_p[0] if cands_p else None)
                    ptext = (prow or {}).get("text") or ""
                    params = parse_qsl(xrow.get("post") or "", keep_blank_values=True) + parse_qsl(urlparse(cur).query, keep_blank_values=True)
                    notes, miss = [], []
                    for k, v in params:
                        if not v: continue
                        if len(v) < 4 or v.lower() in ("true", "false", "null", "get", "post"):
                            notes.append(f"{k}={v} <- sabit deger (kisa/literal)"); continue
                        pos = -1
                        for cand in (v, unquote(v), html.escape(v)):
                            pos = ptext.find(cand)
                            if pos >= 0: break
                        if pos >= 0:
                            am = None
                            for am in re.finditer(r"([\w:-]+)\s*=\s*[\"']" + re.escape(ptext[pos:pos + len(v)]), ptext[max(0, pos - 80): pos + len(v) + 2]): pass
                            where = f" (HTML ozelligi: {am.group(1)})" if am else ""
                            other = [r for r in self.v81_net if r["url"] == ref and r is not prow and r.get("text")]
                            dyn = " | DINAMIK: deger her sayfa yuklemesinde degisiyor -> eklentide her seferinde sayfadan oku" if any(v not in (o.get("text") or "") for o in other) else ""
                            notes.append(f"{k}={_short(v, 60)} <- SAYFADA{where}: {_short(ptext[max(0, pos - 120): pos + len(v) + 40], 200)!r}{dyn}"); continue
                        src = next((r["url"] for r in self.v81_net if r.get("text") and v in r["text"] and r["url"] not in (cur,)), None)
                        if src: notes.append(f"{k}={_short(v, 60)} <- sabit/JS, gectigi yer: {src}")
                        else: miss.append(f"{k}={_short(v, 60)}")
                    path = urlparse(cur).path
                    code = next((r for r in self.v81_net if r["dest"] == "script" and r.get("text") and len(path) > 3 and path in r["text"]), None)
                    if code is None and len(path) > 3 and path in ptext: code = prow
                    if code is not None:
                        pos = code["text"].find(path)
                        notes.append(f"istegi kuran kod ({code['url']}): {_short(code['text'][max(0, pos - 100): pos + 160], 260)!r}")
                    if miss:
                        notes.append("KAYNAGI BULUNAMAYAN: " + ", ".join(miss))
                        self.v81_missing_add("REQUEST_PARAM_SOURCE", f"{xrow['method']} {cur} parametreleri ({', '.join(miss)}) sayfada/scriptlerde bulunamadi -> JS ile hesaplaniyor (token/sifreleme olabilir)")
                    chain.append({"child": cur, "parent": ref, "via": "REQUEST_PARAMS_FROM_PAGE" if params and not miss else ("XHR_FROM_PAGE" if not params else "REQUEST_PARAMS_PARTIAL"),
                                  "row": prow, "snippet": " || ".join(notes), "needle": ", ".join(k for k, _ in params)})
                    if ref == self.v81_root_url: break
                    cur = ref; continue
            found = self.v81_find_parent(cur, self.v81_first_ts(cur), exclude)
            forced_ref = ""
            if found and "PARTIAL" in found[2]:
                crow2 = next((r for r in self.v81_net if r["url"] == cur and r["req_headers"].get("referer")), None)
                rhost = urlparse((crow2 or {}).get("req_headers", {}).get("referer", "")).netloc
                phost = urlparse(self.v81_net[found[1]]["url"]).netloc
                if rhost and rhost != phost:
                    framep = next((r for r in reversed(self.v81_net) if urlparse(r["url"]).netloc == rhost and r["dest"] in ("iframe", "document")
                                   and r["url"] not in exclude), None)
                    if framep is not None:
                        self.log(f"[V81_TRACE] {cur} istegini atan sayfa {framep['url']} (Referer host={rhost}); kismi eslesme ({phost}) yerine bu sayfa ara adim olarak eklendi")
                        found = None
                        forced_ref = framep["url"]
            if found:
                _, idx, via, snippet, needle = found
                row = self.v81_net[idx]
                chain.append({"child": cur, "parent": row["url"], "via": via, "snippet": snippet, "needle": needle, "row": row})
                if row["url"] == self.v81_root_url or row["url"] in exclude: break
                cur = row["url"]; continue
            crow = next((r for r in self.v81_net if r["url"] == cur and r["req_headers"].get("referer")), None)
            ref = forced_ref or (crow or {}).get("req_headers", {}).get("referer", "") or self.v81_media_referer.get(cur, "")
            # Referer sadece origin ise (https://host/) ayni host'taki son iframe/document sayfasina eslestir
            if ref and not any(r["url"] == ref or r.get("eff_url") == ref for r in self.v81_net):
                rh = urlparse(ref).netloc
                hp = next((r for r in reversed(self.v81_net) if urlparse(r["url"]).netloc == rh and r["dest"] in ("iframe", "document")), None)
                if hp is not None: ref = hp["url"]
            if ref and ref not in exclude:
                prow = next((r for r in self.v81_net if r["url"] == ref or r.get("eff_url") == ref), None)
                # POST/GET parametrelerinin degerleri sayfada geciyor mu? (ornek: e_id -> data-eid)
                params = []
                try:
                    params = parse_qsl((crow or {}).get("post") or "", keep_blank_values=True) + parse_qsl(urlparse(cur).query, keep_blank_values=True)
                except Exception:
                    params = []
                ptext = ((prow or {}).get("text") or "")
                found_params, missing_params = [], []
                for k, v in params:
                    if not v or len(v) < 3 or v.lower() in ("true", "false", "en", "tr", "get", "post"): continue
                    pos = -1
                    for cand in (v, unquote(v), html.escape(v)):
                        pos = ptext.find(cand)
                        if pos >= 0: break
                    if pos >= 0:
                        found_params.append(f"{k}={v} <- sayfada: {_short(ptext[max(0, pos - 120): pos + len(v) + 40], 220)!r}")
                    else:
                        missing_params.append(f"{k}={v}")
                still = []
                for mp in missing_params:
                    k, v = mp.split("=", 1)
                    src = next((r["url"] for r in self.v81_net if r.get("text") and v in r["text"] and r["url"] != cur), None)
                    if src: found_params.append(f"{k}={v} <- sabit deger, gectigi yer: {src}")
                    else: still.append(mp)
                missing_params = still
                if params and found_params and not missing_params:
                    chain.append({"child": cur, "parent": ref, "via": "REQUEST_PARAMS_FROM_PAGE", "row": prow,
                                  "snippet": " || ".join(found_params), "needle": ", ".join(k for k, _ in params)})
                    if ref == self.v81_root_url: break
                    cur = ref; continue
                chain.append({"child": cur, "parent": ref, "via": "REFERER_ONLY", "row": prow,
                              "snippet": (" || ".join(found_params) + (" | SAYFADA YOK: " + ", ".join(missing_params) if missing_params else "")) if params else ""})
                scripts = [r["url"] for r in self.v81_net if r["dest"] == "script" and r["req_headers"].get("referer", "") == ref][:8]
                # JS ipucu: URL'nin parcalari hangi script/sayfa metninde geciyor?
                try:
                    segs = [x for x in urlparse(cur).path.split("/") if x]
                    toks = []
                    for x in segs:
                        if len(x) >= 2 and not x.isdigit(): toks.append("/" + x + "/")
                    toks += [x for x in segs if len(x) >= 8]
                    toks = list(dict.fromkeys(toks))[:6]
                    shown = 0
                    for r3 in self.v81_net:
                        if shown >= 6: break
                        if _is_noise_url(r3["url"]) or not r3.get("text") or r3["url"] == cur: continue
                        if r3["dest"] not in ("script", "iframe", "document", "empty", "xhr", ""): continue
                        t3 = r3["text"]
                        for tk in toks:
                            p3 = t3.find(tk)
                            if p3 >= 0:
                                self.log(f"[V81_JS_HINT] '{tk}' -> {r3['url']} :: {_short(t3[max(0, p3 - 160): p3 + 160], 340)!r}")
                                shown += 1; break
                    if not shown:
                        self.log(f"[V81_JS_HINT] {cur} parcalari ({', '.join(toks)}) hicbir metinde yok -> sifreli/runtime uretim (eval/atob/WebAssembly)")
                except Exception:
                    pass
                self.v81_missing_add("JS_GENERATED_URL", f"{cur} duz metinde/packer/base64 icinde bulunamadi; {ref} sayfasinda JS ile uretiliyor. Incelenecek scriptler: {', '.join(scripts) or 'inline script'}")
                if ref == self.v81_root_url: break
                cur = ref; continue
            break
        chain.reverse()
        return chain

    # ---------------------------------------------------------- header test
    def v81_probe(self, url, headers, kind="manifest"):
        try:
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=12, context=ssl._create_unverified_context()) as resp:
                raw = resp.read(8192); st = int(getattr(resp, "status", 200) or 200); ct = resp.headers.get("Content-Type", "")
        except urllib.error.HTTPError as e:
            return False, int(e.code or 0)
        except Exception:
            return False, 0
        if kind == "manifest": return raw.lstrip().startswith(b"#EXTM3U"), st
        if kind == "subtitle":
            s = raw.decode("utf-8", "ignore").lstrip("\ufeff").lstrip()
            return (s.startswith(("WEBVTT", "[Script Info]", "<?xml", "<tt", "#EXTM3U")) or "-->" in s[:3000]), st
        ok, _ = self.v72_media_object_signature(raw, ct, url)
        return ok, st

    def v81_header_matrix(self, url, base_headers, kind):
        base = {k: v for k, v in (base_headers or {}).items() if v}
        res = {"url": url, "kind": kind, "full_ok": False, "required": [], "optional": [], "none_ok": False, "status_full": 0, "any_of": []}
        ok, st = self.v81_probe(url, base, kind)
        res["full_ok"] = ok; res["status_full"] = st
        if not ok:
            self.log(f"[V81_HEADER_TEST] kind={kind} FULL_HEADERS_FAIL status={st} url={url} (token suresi dolmus/IP-baglantili olabilir)")
            return res
        for k in list(base.keys()):
            h = {kk: vv for kk, vv in base.items() if kk != k}
            ok2, st2 = self.v81_probe(url, h, kind)
            (res["optional"] if ok2 else res["required"]).append(k)
            self.log(f"[V81_HEADER_TEST] kind={kind} without={k} -> {'OK' if ok2 else 'FAIL'} status={st2}")
        res["none_ok"], _ = self.v81_probe(url, {"User-Agent": "Mozilla/5.0"}, kind)
        if not res["required"] and not res["none_ok"]:
            # Tek tek cikarinca hepsi OK ama hic header yokken FAIL -> "en az biri" gerekli.
            for k in base:
                h = {"User-Agent": "Mozilla/5.0", k: base[k]}
                ok3, st3 = self.v81_probe(url, h, kind)
                self.log(f"[V81_HEADER_TEST] kind={kind} only={k} -> {'OK' if ok3 else 'FAIL'} status={st3}")
                if ok3: res["any_of"].append(k)
            if not res["any_of"]:
                res["required"] = list(base.keys())
        self.log(f"[V81_HEADER_TEST] kind={kind} REQUIRED={','.join(res['required']) or 'NONE'} ANY_OF={'|'.join(res['any_of']) or '-'} OPTIONAL={','.join(res['optional']) or 'NONE'} bare_ok={res['none_ok']}")
        return res

    # ------------------------------------------------------------- report
    def v81_trail_lines(self, limit=140):
        out = []; seg_count = {}
        t0 = min((r["ts"] for r in self.v81_net), default=time.time())
        for r in sorted(self.v81_net, key=lambda x: x["ts"]):
            lct = r["ct"].lower()
            if r["dest"] == "script" and r["src"] == "STATIC": continue
            is_seg = ("mp2t" in lct or "octet-stream" in lct or r.get("media_kind") in ("mp4", "video")) and not r["text"]
            if is_seg:
                h = urlparse(r["url"]).netloc; seg_count[h] = seg_count.get(h, 0) + 1; continue
            if _is_noise_url(r["url"]):
                h = "reklam/izleme:" + urlparse(r["url"]).netloc; seg_count[h] = seg_count.get(h, 0) + 1; continue
            note = "  (304: tarayici onbellekten aldi, govde YOK)" if r["status"] == 304 else ""
            if r["dest"] in ("empty", "xhr") and r.get("text") and len(r["text"]) <= 1500 and not r["text"].lstrip().startswith("#EXTM3U"):
                note += f"\n          RESPONSE: {_short(r['text'], 600)}"
            out.append(f"[V81_NET] +{r['ts'] - t0:5.1f}s {r['src']:<6} {r['method']:<4} {r['status'] or '---'} {r['dest'] or '-':<8} {_short(r['ct'], 28):<28} {r['bytes'] or 0:>8}B {_short(r['url'], 400)}" +
                       (f"  POST={_short(r['post'], 160)}" if r["post"] else "") + note)
        for h, n in seg_count.items():
            out.append(f"[V81_NET] (gizlendi: {'reklam/izleme' if h.startswith('reklam') else 'segment/binary'}) host={h.replace('reklam/izleme:', '')} count={n}")
        if len(out) > limit:
            out = out[:limit // 2] + [f"[V81_NET] ... {len(out) - limit} satir atlandi ..."] + out[-limit // 2:]
        return out

    def v81_stopped_at(self):
        net = self.v81_net
        frames = [r for r in net if r["dest"] in ("iframe",) or (r["dest"] == "document" and r["url"] != self.v81_root_url)]
        media = [r for r in net if r.get("media_kind") or "mpegurl" in r["ct"].lower()]
        blocked = [r for r in net if r["status"] in (401, 403, 429, 451, 503) and r["dest"] in ("document", "iframe", "xhr", "empty", "")]
        if getattr(self, "blocked", False) and not any(r["src"] == "MITM" for r in net):
            return "TOP_PAGE_BLOCKED", "Kok sayfa Cloudflare/WAF ile engellendi ve tarayici trafigi yok"
        if blocked:
            b = blocked[-1]
            return "REQUEST_BLOCKED", f"{b['method']} {b['url']} status={b['status']} (Referer/Origin/Cookie/nonce eksik olabilir; istek header'lari: {b['req_headers']})"
        if any(m.startswith("AJAX_TEMPLATE_VAR") for m in self.v81_missing):
            return "AJAX_TEMPLATE", "Player'i getiren ajax sablonunun degiskeni cozulmedi"
        if media:
            names = ", ".join(f"{m['url']} ({m['status']} {m['ct']})" for m in media[-4:])
            if self.v81_ads and len(self.v81_ads) >= len(media):
                return "ONLY_AD_MEDIA", f"Sadece reklam medyasi goruldu: {names}"
            rej = "; ".join(f"{x['url']} -> {x['reason']}" for x in self.v81_media_rejects[-4:])
            proof = getattr(self, "v32_proof", {}) or {}
            steps = " > ".join(f"{s.get('stage')}:{s.get('status')}{(' ' + s.get('signature')) if s.get('signature') else ''}" for s in proof.get("steps", []))
            return "MEDIA_SEEN_NOT_PROVEN", (f"Medya istegi var ama final kaniti tamamlanmadi: {names}" +
                                             (f" | RED NEDENI: {rej}" if rej else "") + (f" | KANIT ADIMLARI: {steps}" if steps else ""))
        if frames:
            last = frames[-1]
            fs = next((f for f in reversed(self.v81_frame_scan) if f["url"] == last["url"]), None)
            c304 = [r["url"] for r in net if r["status"] == 304 and not _is_noise_url(r["url"])]
            why = []
            if fs and fs.get("autostart_false"): why.append("player autostart=false -> Play'e BASILMADI (45 sn icinde)")
            if fs and fs.get("player"): why.append("player=" + ",".join(fs["player"]))
            if fs and not fs.get("media"): why.append("frame kodunda duz/packer m3u8 YOK -> URL JS/ajax ile sonradan uretiliyor")
            if c304: why.append("304 onbellek cevaplari govdesiz geldi: " + ", ".join(c304[:4]))
            return "PLAYER_FRAME_NO_MEDIA", ("Player frame yuklendi ama medya istegi yok. " + " | ".join(why) +
                                             f" | Son frame: {last['url']} | Cozum: Chrome'da Play'e bas ya da V81_LISTEN_SECONDS'i artir")
        if self.player:
            return "IFRAME_FOUND_NOT_LOADED", f"iframe bulundu ama icerigi yuklenemedi: {self.player}"
        return "NO_PLAYER_FOUND", "Sayfada iframe/ajax/player izi yok (ajax sablonu, data-* ya da JS ile uretilen player olabilir)"

    def v81_emit_report(self, root_url):
        try:
            self._v81_emit_report(root_url)
        except Exception as e:
            import traceback
            self.log(f"[V81_REPORT_ERROR] {type(e).__name__}: {e}")
            self.log(_short(traceback.format_exc(), 1500))

    def _v81_emit_report(self, root_url):
        L = self.log
        L("")
        L("=" * 30 + " V81 F12 AG KAYDI (kronolojik) " + "=" * 30)
        for ln in self.v81_trail_lines(): L(ln)

        final = self.final if self.final_verified else ""
        proof = getattr(self, "v32_proof", {}) or {}
        chain = self.v81_trace(final) if final else []

        # header testleri
        hdr_manifest = hdr_segment = None
        play_headers = {}
        if final:
            ctxh = dict((self.final_playback_context or {}).get("headers") or {})
            if not ctxh:
                rootm = proof.get("root") or final
                bctx = self.browser_media_context.get(rootm) or self.browser_request_context.get(rootm) or {}
                ref = bctx.get("referer") or self.v81_media_referer.get(rootm) or self.v81_media_referer.get(final) or ""
                ctxh = {"User-Agent": bctx.get("user-agent") or V81_UA}
                if ref: ctxh["Referer"] = ref
                if bctx.get("origin"): ctxh["Origin"] = bctx["origin"]
                if bctx.get("cookie"): ctxh["Cookie"] = bctx["cookie"]
                elif ref:
                    o = urlparse(ref); ctxh["Origin"] = f"{o.scheme}://{o.netloc}"
            play_headers = ctxh
            L("")
            L("=" * 30 + " V81 OYNATMA HEADER TESTI " + "=" * 30)
            hdr_manifest = self.v81_header_matrix(final, ctxh, "manifest")
            seg = next((s for s in proof.get("steps", []) if s.get("stage") == "segment"), None)
            if seg: hdr_segment = self.v81_header_matrix(seg["url"], ctxh, "segment")
            if hdr_manifest and not hdr_manifest["full_ok"]:
                self.v81_missing_add("PLAYBACK_REPLAY", "Final manifest kaydedilen header'larla tekrar acilamadi -> URL tek kullanimlik/IP-token'li; eklenti her oynatmada zinciri bastan yurutmeli")

        # altyazi dogrulama
        for u, info in list(self.v81_subs.items())[:15]:
            if info.get("valid") is not None: continue
            h = {"User-Agent": V81_UA}
            ref = info.get("found_in") or (play_headers.get("Referer") if play_headers else "")
            if ref: h["Referer"] = ref
            ok, st = self.v81_probe(u, h, "subtitle")
            if not ok and ref:
                ok2, st2 = self.v81_probe(u, {"User-Agent": V81_UA}, "subtitle")
                if ok2: ok, st = ok2, st2
            info["valid"] = ok; info["status"] = st
            info["needs_referer"] = bool(ref) and ok and not self.v81_probe(u, {"User-Agent": V81_UA}, "subtitle")[0]

        # stop / missing
        stopped = ("NONE", "")
        if not final:
            stopped = self.v81_stopped_at()
            self.v81_missing_add("FINAL_MEDIA", f"{stopped[0]} -> {stopped[1]}")
        if not self.v81_subs:
            scanned = ",".join(sorted(self.v81_sub_sources)) or "NONE"
            self.log(f"[V81_SUBTITLE_NOTE] Ayri altyazi dosyasi bulunamadi. Taranan kaynaklar: {scanned}. "
                     f"Hardsub (videoya gomulu) olabilir ya da altyazi Play'den sonra/dil secince yukleniyor (MITM={'EVET' if self.v81_mitm_used else 'HAYIR'}).")

        verdict = "READY" if final and not any(m.split(":")[0] in ("JS_GENERATED_URL", "PLAYBACK_REPLAY", "AJAX_TEMPLATE_VAR") for m in self.v81_missing) else ("PARTIAL" if final else "FAILED")
        L("")
        L("=" * 30 + " V81 REPO TARIFI " + "=" * 30)
        L(f"[V81_VERDICT] result={verdict} final={'HLS' if self.final_type == 'HLS' else (self.final_type or 'NONE')} "
          f"subtitles={len(self.v81_subs)} ads_rejected={len(self.v81_ads)} stopped_at={stopped[0]} missing={len(self.v81_missing)}")
        if stopped[0] != "NONE":
            L(f"[V81_STOPPED_AT] {stopped[0]} :: {stopped[1]}")

        L(f"[V81_REPO_RECIPE] ===== BASLA ===== kaynak: {root_url}")
        steps_json = []
        n = 0
        if chain:
            first_parent = chain[0]["parent"]
            if first_parent != root_url:
                n += 1
                L(f"[V81_STEP {n}] GET {root_url}  (eklentinin load()/loadLinks() data URL'si)")
                steps_json.append({"n": n, "method": "GET", "url": root_url})
            for hop in chain:
                n += 1
                row = hop.get("row") or {}
                parent = hop["parent"]
                rh = row.get("req_headers", {}) if row else {}
                L(f"[V81_STEP {n}] {row.get('method', 'GET')} {parent}")
                if row:
                    L(f"    response: status={row.get('status')} ct={row.get('ct') or '-'} bytes={row.get('bytes')} dest={row.get('dest') or '-'} src={row.get('src')}")
                    hh = {k: v for k, v in rh.items() if k in ("referer", "origin", "x-requested-with", "content-type", "authorization") or k.startswith("x-")}
                    if rh.get("cookie"): hh["cookie"] = "(" + ", ".join(c.split("=")[0].strip() for c in rh["cookie"].split(";")) + ")"
                    if hh: L(f"    request headers: " + " | ".join(f"{k}={_short(v, 120)}" for k, v in hh.items()))
                    if row.get("post"): L(f"    POST body: {_short(row['post'], 400)}")
                    sc = row.get("resp_headers", {}).get("set-cookie", "")
                    if sc: L(f"    set-cookie: {_short(sc, 200)}")
                for p in self.v81_params:
                    if p["value"] and p["value"] in parent:
                        L(f"    param: {p['var']}={p['value']}  <- {p['from']}")
                L(f"    -> sonraki URL bu cevabin icinden cikiyor  via={hop['via']}")
                if hop.get("snippet"):
                    L(f"    snippet: {_short(hop['snippet'], 900)!r}")
                    hint = {"AJAX_TEMPLATE": f"sayfadan {hop.get('needle', '')} degerlerini al, sablonu doldurup istegi at",
                            "HLS_MASTER_VARIANT": "master playlist; ExoPlayer variant'i kendisi secer (master URL'yi vermek yeterli)",
                            "PACKER": "cevaptaki eval(function(p,a,c,k,e,d)...) blogunu JsUnpacker ile ac, sonra URL'yi regex ile al",
                            "BASE64": "cevaptaki base64 metni coz, sonra URL'yi regex ile al",
                            "AES_DECRYPT": f"cevaptaki sifreli alani coz: {(row or {}).get('decrypt_formula', '')}",
                            "JSON_ESCAPED": "cevap JSON; \\/ kacislarini ac (ya da JSON parse et), sonra URL'yi al",
                            "REFERER_ONLY": "URL duz metinde yok; bu sayfanin JS'i uretiyor (V81_MISSING'e bak)",
                            "REQUEST_PARAMS_FROM_PAGE": "istek URL'si sabit; parametre degerlerini sayfadaki snippet'ten regex/selector ile al, istegi ayni method/body/header ile at",
                            "XHR_FROM_PAGE": "sayfa bu istegi parametresiz atiyor; ayni method/header ile at",
                            "REQUEST_PARAMS_PARTIAL": "bazi parametrelerin kaynagi yok (V81_MISSING) -> scriptte hesaplaniyor"}.get(hop["via"].replace("+PARTIAL", ""), "cevaptan URL'yi regex/selector ile al")
                    L(f"    extract: {hint}  (aranan: '{_short(hop.get('needle', ''), 90)}')")
                steps_json.append({"n": n, "method": row.get("method", "GET") if row else "GET", "url": parent, "via": hop["via"],
                                   "status": row.get("status") if row else None, "ct": row.get("ct") if row else None,
                                   "headers": {k: v for k, v in rh.items() if k in ("referer", "origin", "x-requested-with", "content-type")},
                                   "post": row.get("post") if row else "", "snippet": _short(hop.get("snippet", ""), 400), "next": hop["child"]})
        elif final:
            L(f"[V81_STEP] zincir cikarilamadi (ag kaydi yok). Final dogrudan statik taramadan geldi; referer={self.v81_media_referer.get(final, '-')}")
        if final:
            n += 1
            info = self.v81_hls_info.get(final, {}) or {}
            rinfo = self.v81_hls_info.get(proof.get("root") or final, {}) or {}
            L(f"[V81_STEP {n}] FINAL {self.final_type} {final}")
            if proof.get("root") and proof.get("root") != final: L(f"    master: {proof.get('root')}")
            if info: L(f"    sure={info.get('duration_s')}s segment={info.get('segments')} endlist={info.get('endlist')}")
            for v in rinfo.get("variants", []): L(f"    variant: {v['resolution'] or '?'} bw={v['bandwidth'] or '?'} {v['url']}")
            for a in rinfo.get("audio", []): L(f"    audio: lang={a['lang']} name={a['name']} {a['url']}")
            for k in (rinfo.get("keys", []) + info.get("keys", [])): L(f"    AES key: {k['method']} {k['url']}")
            seg = next((s for s in proof.get("steps", []) if s.get("stage") == "segment"), None)
            if seg:
                L(f"    segment: imza={seg.get('signature')} {seg.get('url')}")
                if seg.get("effective_url") and seg.get("effective_url") != seg.get("url"):
                    L(f"    segment redirect -> {seg.get('effective_url')} (player redirect'i takip etmeli)")
                if re.search(r"\.(?:jpe?g|png|gif|webp|html?|css|js|txt)(?:$|\?)", seg.get("url", ""), re.I):
                    L("    UYARI: segment uzantisi gizli (resim/html gibi). ExoPlayer icin M3U8 tipi + header yeterli; uzantiya gore filtreleme yapma.")
        if hdr_manifest:
            req = hdr_manifest["required"]; opt = hdr_manifest["optional"]
            if not req and hdr_manifest.get("any_of"):
                L("[V81_PLAY_HEADERS] manifest EN AZ BIRI GEREKLI: " + " VEYA ".join(f"{k}: {play_headers.get(k)}" for k in hdr_manifest["any_of"]) + "  (guvenli secim: hepsini gonder)")
            else:
                L(f"[V81_PLAY_HEADERS] manifest REQUIRED: " + (" | ".join(f"{k}: {play_headers.get(k)}" for k in req) or "YOK (header'siz acilir)"))
            if opt: L(f"[V81_PLAY_HEADERS] manifest OPTIONAL: {', '.join(opt)}")
        if hdr_segment:
            if not hdr_segment["required"] and hdr_segment.get("any_of"):
                L("[V81_PLAY_HEADERS] segment  EN AZ BIRI GEREKLI: " + " VEYA ".join(hdr_segment["any_of"]))
            else:
                L(f"[V81_PLAY_HEADERS] segment  REQUIRED: " + (" | ".join(f"{k}: {play_headers.get(k)}" for k in hdr_segment['required']) or "YOK"))
        _seen_ads = {}
        for a in self.v81_ads:
            if a["url"] not in _seen_ads or (a.get("duration_s") and not _seen_ads[a["url"]].get("duration_s")):
                _seen_ads[a["url"]] = a
        self.v81_ads = list(_seen_ads.values())
        for a in self.v81_ads:
            L(f"[V81_AD_MEDIA] reason={a['reason']} sure={a.get('duration_s')} url={a['url']}  (eklentide bu URL'yi ATLA)")
        subs_json = []
        for u, info in self.v81_subs.items():
            L(f"[V81_SUBTITLE] lang={info['lang']} label={info['label'] or '-'} format={info['format']} valid={info.get('valid')} "
              f"status={info.get('status', '-')} referer_gerekli={info.get('needs_referer', False)} kaynak={','.join(info['sources'])} found_in={info.get('found_in') or '-'} url={u}")
            subs_json.append({k: info.get(k) for k in ("url", "lang", "label", "format", "valid", "found_in", "needs_referer", "sources")})
        L(f"[V81_SUBTITLE_SUMMARY] found={len(self.v81_subs)} scanned={','.join(sorted(self.v81_sub_sources)) or 'NONE'}")
        for p in self.v81_params:
            L(f"[V81_PARAM_SOURCE] {p['var']}={_short(p['value'], 120)} <- {p['from']} (sablon: {p['template']})")
        if self.v81_missing:
            for m in self.v81_missing: L(f"[V81_MISSING] {m}")
        else:
            L("[V81_MISSING] NONE - eklenti icin gereken tum parcalar bu logda")
        L("[V81_REPO_RECIPE] ===== BITIR =====")

        rep = {
            "verdict": verdict, "root": root_url, "stopped_at": stopped[0], "stopped_detail": stopped[1],
            "final": {"type": self.final_type if final else "", "url": final, "master": proof.get("root") if final else "",
                      "hls": self.v81_hls_info.get(final, {}), "master_info": self.v81_hls_info.get(proof.get("root") or "", {})},
            "steps": steps_json, "params": self.v81_params,
            "play_headers": {"captured": play_headers,
                             "manifest_required": (hdr_manifest or {}).get("required", []),
                             "segment_required": (hdr_segment or {}).get("required", []),
                             "manifest_any_of": (hdr_manifest or {}).get("any_of", []),
                             "segment_any_of": (hdr_segment or {}).get("any_of", []),
                             "replay_ok": (hdr_manifest or {}).get("full_ok")},
            "subtitles": subs_json, "ads": self.v81_ads, "missing": self.v81_missing,
            "mitm_used": self.v81_mitm_used,
        }
        self.v81_report = rep
        L("[V81_REPO_JSON] " + json.dumps(rep, ensure_ascii=False, default=str))
