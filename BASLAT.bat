@echo off
chcp 65001 >nul
title Resolver Lab Local V81
cd /d "%~dp0"

echo ============================================================
echo Resolver Lab Local V81
echo SITE DNA + Failure Diagnostics V2 + Interaction Provenance + Final Proof Report
echo ============================================================
echo.

where py >nul 2>nul
if errorlevel 1 (
    echo [HATA] Python Launcher ^(py^) bulunamadi.
    echo Python 3 kurulu olmali.
    pause
    exit /b 1
)

py server.py

echo.
echo Resolver Lab kapandi.
pause
