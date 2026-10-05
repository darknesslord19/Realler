# V81 GitHub Runner

Bu paket V81 site analizini GitHub Actions üzerinde Ubuntu + Python 3.12 + Playwright Chromium ile çalıştırmak için temizlenmiştir.

## Gerekli dosyalar

- `server.py` — ana analiz motoru
- `v81_layer.py` — V81 kanıt/provenance katmanı
- `repo_analyzer.py` — statik site/repo analizi
- `manual_listener.py` — tarayıcı dinleme yardımcıları
- `github_runner.py` — GitHub Actions giriş noktası
- `requirements-github.txt` — Python bağımlılıkları
- `resolver_memory.json` — resolver hafızası
- `.github/workflows/v81.yml` — Actions workflow

## Çalıştırma

GitHub → Actions → **V81 Site Analyzer** → Run workflow.

Gerekli alan:

- `url`: ör. `https://example.com`

İsteğe bağlı:

- `max_depth`: varsayılan `4`
- `max_requests`: varsayılan `32`

Çıktı `v81-report` artifact'ında bulunur.
