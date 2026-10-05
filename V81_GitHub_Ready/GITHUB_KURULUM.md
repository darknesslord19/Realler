# V81 GitHub Actions

Bu sürüm V81'in mevcut statik analiz ve resolver çekirdeğini korur. GitHub Actions modunda:

- Ubuntu runner kullanılır.
- Playwright + Chromium otomatik kurulur.
- V81'in mevcut CDP/Network gözlem katmanı kullanılır.
- `mitmdump` GitHub yolunda zorunlu değildir.
- XHR/fetch/response/iframe/player/network kanıtları mevcut V81 mantığına aktarılır.
- Sonuçlar Actions Artifact olarak `v81-report` altında yayınlanır.

## Çalıştırma

GitHub → Actions → **V81 Site Analyzer** → **Run workflow**.

`url` alanına örneğin:

`https://example.com`

verilir.

## Sonuçlar

Artifact içinde:

- `result.json`
- `v81_report.json`
- `logs.txt`
- `browser_network.json`
- `browser_requests.json`
- `browser_responses.json`

bulunur.

## Not

GitHub Actions geçici bir çalışma ortamıdır. Kalıcı servis değildir. Analizlerin tamamı workflow çalıştığı süre içinde yapılır. V81, DRM veya erişim kontrolünü aşmak için tasarlanmamıştır; yalnızca normal tarayıcı oturumunda gözlemlenebilen ve doğrulanabilen kaynakları kanıt olarak kabul eder.
