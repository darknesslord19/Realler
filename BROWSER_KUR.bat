@echo off
chcp 65001 >nul
title Resolver Lab V35 - Browser Kurulumu
cd /d "%~dp0"

echo ============================================================
echo Resolver Lab Local V35 - Browser Kurulumu
echo ============================================================
echo.
echo Playwright kuruluyor/guncelleniyor...
py -m pip install --upgrade pip
py -m pip install --upgrade playwright
py -m pip install --upgrade mitmproxy

if errorlevel 1 (
    echo.
    echo [HATA] Playwright kurulumu basarisiz.
    echo Python kurulumunu kontrol et.
    pause
    exit /b 1
)

echo.
echo Chromium indiriliyor...
py -m playwright install chromium

if errorlevel 1 (
    echo.
    echo [HATA] Chromium kurulumu basarisiz.
    pause
    exit /b 1
)

echo.
echo [OK] Browser kurulumu tamamlandi.
pause
