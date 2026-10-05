@echo off
setlocal
title Resolver Lab V44 - Real Chrome CDP
set "PROFILE=%~dp0chrome_v44_profile"
set "CHROME="

if exist "%ProgramFiles%\Google\Chrome\Application\chrome.exe" set "CHROME=%ProgramFiles%\Google\Chrome\Application\chrome.exe"
if exist "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" set "CHROME=%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"
if exist "%LocalAppData%\Google\Chrome\Application\chrome.exe" set "CHROME=%LocalAppData%\Google\Chrome\Application\chrome.exe"

if not defined CHROME (
  echo [V44] Google Chrome bulunamadi.
  echo chrome.exe yolunu V44_REAL_CHROME_BASLAT.bat icinde CHROME degiskenine yaz.
  pause
  exit /b 1
)

echo ============================================================
echo Resolver Lab V44 - REAL CHROME CDP
echo Chrome : %CHROME%
echo Profil : %PROFILE%
echo CDP    : http://127.0.0.1:9222
echo ============================================================
echo.
echo Acilan Chrome'u test bitene kadar kapatma.
echo Ilk kullanimda Cloudflare sayfasi gorunurse normal sekmede tamamla.
echo Sonra Resolver Lab'da URL'yi tara.
echo.

start "" "%CHROME%" --remote-debugging-port=9222 --remote-debugging-address=127.0.0.1 --user-data-dir="%PROFILE%" --no-first-run --no-default-browser-check "about:blank"
timeout /t 2 /nobreak >nul
start "" "http://127.0.0.1:9222/json/version"
endlocal
