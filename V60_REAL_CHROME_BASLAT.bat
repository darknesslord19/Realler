@echo off
setlocal
title Resolver Lab V56 - Google Chrome
set "PROFILE=%~dp0chrome_v56_profile"
set "CHROME="

if exist "%ProgramFiles%\Google\Chrome\Application\chrome.exe" set "CHROME=%ProgramFiles%\Google\Chrome\Application\chrome.exe"
if exist "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" set "CHROME=%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"
if exist "%LocalAppData%\Google\Chrome\Application\chrome.exe" set "CHROME=%LocalAppData%\Google\Chrome\Application\chrome.exe"

if not defined CHROME (
  echo [V56] Google Chrome bulunamadi.
  pause
  exit /b 1
)

echo ============================================================
echo Resolver Lab V56 - GOOGLE CHROME CDP
echo Chrome : %CHROME%
echo Profil : %PROFILE%
echo CDP    : http://127.0.0.1:9222
echo ============================================================

start "" "%CHROME%" --remote-debugging-port=9222 --remote-debugging-address=127.0.0.1 --user-data-dir="%PROFILE%" --no-first-run --no-default-browser-check "about:blank"
endlocal
