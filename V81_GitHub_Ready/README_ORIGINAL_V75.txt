RESOLVER LAB V49 - PLAYER FRAME PRIORITY

Bu sürüm V48'deki seçim hatasını düzeltir.

Kural:
- pichive / iframe.php / embed / player frame bulunursa ana sayfadaki adaylar seçim dışı kalır.
- Player frame içindeki video, #Player ve player-top-wrap güçlü öncelik alır.
- RoketDizi ana sayfasındaki büyük layout DIV'leri ağır şekilde düşürülür.
- Tek gerçek browser pointer click kullanılır.
- Sonuç media_before / media_after / delta ile ölçülür.
- delta > 0 olmadan "auto_triggered=true" yazmaz.

Beklenen test:
[V49_AUTO_PLAY] SELECTED ... frame=https://four.pichive.online/iframe.php...
[V49_AUTO_PLAY] CLICK_ONCE ... x≈434 y≈249 ...
[V49_AUTO_PLAY] CLICK_OK
[V49_AUTO_PLAY] RESULT ... delta>0 auto_triggered=true

İlk testte mouse'a hiç dokunma.


RESOLVER LAB V48 - DOM GEOMETRY AUTO PLAY

V48, V46 Clean Observer tabanını korur.

Yeni:
- Her frame'de görünür button/div/span/a/svg/video elemanlarının runtime DOM geometrisini okur.
- id/class/aria/title/text/cursor/pointer-events/z-index/bounding rect loglanır.
- Pichive/player frame içinde gerçek Play adayı puanlanır.
- Play class'ı bulunmasa bile büyük, merkezde, pointer-enabled player DIV fallback aday olabilir.
- Seçilen adayın gerçek x/y koordinatına yalnız 1 kez Playwright pointer click gönderilir.
- JS element.click(), player API/bootstrap çağrısı, pre-nav hook ve aktif media refetch YOK.
- Başarısız olursa manuel fallback korunur.

Beklenen log:
[V48_AUTO_PLAY] SEARCH_FRAME
[V48_DOM_CANDIDATE]
[V48_AUTO_PLAY] CLICK_ONCE
[V48_AUTO_PLAY] CLICK_OK
[V48_AUTO_PLAY] RESULT media_after_click=true

İlk testte mouse'a dokunma.


RESOLVER LAB V47 - CLEAN AUTO PLAY

V47, çalışan V46 Clean Observer tabanını korur.

DEĞİŞEN TEK ANA DAVRANIŞ:
- Player frame'lerinde yalnız güçlü ve görünür Play kontrolleri aranır.
- Gerçek Play kontrolü bulunursa yalnız 1 kez Playwright/CDP browser-input click yapılır.
- div.player gibi genel alanlar ASLA otomatik tıklanmaz.
- JS monkey-patch, bootstrap function trigger ve aktif media refetch geri getirilmedi.
- Tıklamadan sonra 15 saniye yalnız Network gözlenir.
- Güçlü Play bulunamazsa veya medya başlamazsa V46 manuel fallback 12 saniye açık kalır.

BEKLENEN LOG:
[V47_AUTO_PLAY] ENABLED=true
[V47_AUTO_PLAY] SEARCH ...
[V47_PLAY_CANDIDATE] ...
[V47_AUTO_PLAY] CLICK_ONCE ...
[V47_AUTO_PLAY] CLICK_OK ...
[V47_AUTO_PLAY] RESULT media_after_click=true

Ardından mevcut V46/V32 kanıt zinciri:
master/variant/media object -> FINAL_MEDIA_PROOF PASS -> FINAL_MEDIA -> FINAL_VERIFY YES.

TEST:
1) V47_REAL_CHROME_BASLAT.bat
2) BASLAT.bat
3) URL'yi analiz et.
4) İlk testte mouse'a dokunma; V47'nin kendi Play tıklamasını bekle.
5) Logu gönder.


RESOLVER LAB V46 - REAL CHROME CLEAN OBSERVER

V46 TEST AMACI
V45'te player'in Resolver müdahalesi yüzünden mi, yoksa aktif CDP bağlantısı yüzünden mi
çalışmadığını ayırmak.

REAL_CHROME modunda:
- V39 pre-navigation JS monkey patch hooklari YOK.
- V41 bootstrap function trigger YOK.
- V45 player stabilization DOM taramasi YOK.
- Otomatik action discovery/click YOK.
- m.php/segment aktif refetch/proof YOK.
- CDP Network + normal Playwright response gözlemi devam eder.
- Chrome açık kalır.
- PLAY'e kullanıcı MANUEL basar.

TEST:
1) V46_REAL_CHROME_BASLAT.bat
2) BASLAT.bat
3) URL'yi Resolver'da analiz et.
4) Chrome'da Play görünür görünmez MANUEL tıkla.
5) Refresh YAPMA.
6) Sonucu ve logu gönder.

Beklenen log:
[V44_REAL_CHROME_ATTACH] PASS
[V46_CLEAN_OBSERVER] ACTIVE=true mode=PASSIVE_CDP_NETWORK manual_play=true
[V46_CLEAN_OBSERVER] PRENAV_HOOKS=SKIPPED
[V46_CLEAN_OBSERVER] AUTO_ACTION_DISCOVERY=SKIPPED AUTO_CLICK=SKIPPED

Yorum:
- Play çalışırsa eski hook/action katmanı bozuyordu.
- Play yine çalışmaz, Resolver bitince refresh ile çalışırsa aktif CDP/devtools bağlantısı etkiliyor.

RESOLVER LAB V45 - REAL CHROME HLS HANDOFF

V45 fixes the exact break proven by the V44 log:
- Real Chrome attach stays unchanged.
- Waits for generic player hydration before action scoring.
- source2/bootstrap JSON sources are rebound to the exact Playwright Response.frame.
- m.php / .php / extensionless HLS sources are fetched in that same frame and same Chrome session.
- fetch carries native referrer/session and has same-frame XHR fallback.
- URL extension is not trusted; FINAL still requires actual #EXTM3U plus child/media-object proof.

Critical expected path:
[V44_REAL_CHROME_ATTACH] PASS
[V45_PLAYER_READY] PASS
[BROWSER_NET] 200 application/json ...source2.php
[V45_FRAME_RESPONSE_OWNER_BIND] ... source=https://four.pichive.online/m.php?v=...
[V45_JSON_HLS_HANDOFF] ...
[V43_DYNAMIC_MANIFEST] ...
[V43_BROWSER_HLS_PROOF] PASS ...
[FINAL_MEDIA] HLS ...

RESOLVER LAB V44 - REAL CHROME CDP ATTACH

YENI:
- Resolver once 127.0.0.1:9222'de kullanicinin actigi gercek Google Chrome'a baglanir.
- Var olan Chrome context/cookie/session kullanilir; gercek Chrome'a UA override uygulanmaz.
- Hedef sekme aciksa reuse edilir; degilse ayni gorunur Chrome context'inde yeni sekme acilir.
- V43 semantic JSON/HLS/frame zinciri aynen korunur.
- Port 9222 yoksa V43 headless motora otomatik fallback yapilir.
- Analiz bitince gercek Chrome kapatilmaz.

KULLANIM:
1. V44_REAL_CHROME_BASLAT.bat
2. Acilan Chrome'u kapatma.
3. BASLAT.bat
4. Resolver arayuzunden URL'yi tara.
5. Logda:
   [V44_REAL_CHROME_ATTACH] PASS
   [V44_BROWSER_MODE] REAL_CHROME_CDP
   gormelisin.
6. Kritik test source2.php: 403 yerine 200/JSON gelirse V43 zinciri otomatik devam eder.

Bu surum Cloudflare bypass kodu eklemez; normal Chrome'un kendi oturumunu kullanir.

Resolver Lab V43 - SEMANTIC FRAME MEDIA CHAIN

V42 tabani korunmustur. V43 ekleri:
- JSON player bootstrap kaynaklarini URL uzantisina gore degil type/mimeType/path semantigine gore tanir.
- type=hls veya mimeType=application/vnd.apple.mpegurl ise .php/API/extensionless file URL'sini trusted media-resolver candidate yapar.
- Semantic source'u onu ureten frameId + iframe Referer/URL ile baglar.
- Follow-up fetch top-frame yerine mumkunse exact owner iframe icinde credentials=include ile calisir.
- master.m3u8 icindeki l.php/ld.php gibi extensionless HLS child URI'leri HLS gramerine gore takip edilir.
- HLS final proof mumkun oldugunda ayni Chromium context/frame icinde yapilir; cookie/cf_clearance/browser session disina cikmaz.
- Semantic metadata tek basina FINAL vermez. FINAL icin #EXTM3U + child/media-object response kaniti gerekir.
- V42 protected bootstrap/403/Cloudflare diagnostikleri aynen korunur.

Yeni V43 loglari:
V43_CAPABILITY
V43_SEMANTIC_MEDIA_SOURCE
V43_FRAME_OWNER_BIND
V43_SEMANTIC_RESPONSE
V43_FRAME_FETCH
V43_DYNAMIC_MANIFEST
V43_HLS_CHILD
V43_BROWSER_HLS_PROOF
V43_PLAYER_HANDOFF_READY

RoketDizi/pichive orneginde beklenen mantik:
iframe.php -> source2.php JSON -> playlist.sources[].file (m.php/API vb.) -> ayni iframe/session -> master.m3u8 -> l.php/ld.php gibi HLS child -> media object -> FINAL.

Not: V43 site/domain ezberi eklemez; mekanizma geneldir.
