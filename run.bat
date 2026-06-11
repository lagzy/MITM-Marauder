@echo off
title MITM Toolkit
cd /d "%~dp0"

:: Check for admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo ============================================================
    echo   MITM Toolkit requires Administrator privileges!
    echo.
    echo   Please right-click this file and select
    echo   "Run as Administrator"
    echo ============================================================
    echo.
    pause
    exit /b 1
)

:: Quick prereq check
python -c "import scapy" >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [!] Scapy is not installed. Running setup...
    echo.
    call setup.bat
)

:: Launch the toolkit
python mitm_app.py

pause
