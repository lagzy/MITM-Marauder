@echo off
title MITM Toolkit - Setup
cd /d "%~dp0"

echo.
echo ============================================================
echo   MITM Toolkit - Windows Setup
echo ============================================================
echo.

:: Check Python
echo [*] Checking Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python not found! Please install Python 3.10+ from https://python.org
    echo.
    pause
    exit /b 1
)
python --version
echo.

:: Install Python dependencies
echo [*] Installing Python dependencies...
python -m pip install --upgrade pip
python -m pip install scapy
echo.

:: Check Npcap
echo [*] Checking for Npcap...
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Npcap" >nul 2>&1
if %errorlevel% neq 0 (
    reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Npcap" >nul 2>&1
)

if %errorlevel% neq 0 (
    echo.
    echo [!!!] Npcap is NOT installed!
    echo.
    echo Npcap is REQUIRED for packet capture and injection.
    echo.
    echo Please download and install Npcap:
    echo   1. Go to: https://npcap.com/#download
    echo   2. Download the latest installer
    echo   3. Run the installer AS ADMINISTRATOR
    echo   4. CHECK "WinPcap API-compatible Mode" during install!
    echo.
    echo After installing Npcap, re-run this setup script.
    echo.
    start "" "https://npcap.com/#download"
) else (
    echo [✓] Npcap is installed.
)
echo.

:: Create captures directory
if not exist "captures" mkdir captures
echo [*] Created captures directory.
echo.

:: Check if running as admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!!!] This script should be run as Administrator!
    echo The MITM Toolkit requires admin privileges to run.
    echo Please re-run setup.bat from an elevated Command Prompt.
    echo   (Right-click -^> "Run as Administrator")
    echo.
) else (
    echo [✓] Running as Administrator.
)
echo.

echo ============================================================
echo   Setup Complete!
echo.
echo   To start the toolkit:
echo     python mitm_app.py
echo.
echo   IMPORTANT: Always run as Administrator!
echo ============================================================
echo.
pause
