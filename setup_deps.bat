@echo off
setlocal EnableDelayedExpansion
title CyberShield Dependency Checker & Setup

:: 1. Check Administrator Privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ================================================================
    echo  [!] ELEVATING PERMISSIONS: Requesting Administrator Rights...
    echo ================================================================
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo ================================================================
echo  [*] CYBERSHIELD DEPENDENCY CHECKER & SETUP (ADMINISTRATOR)
echo ================================================================
echo.

:: 2. Check Python Version
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] Python is NOT found on PATH!
    echo     Please install Python 3.9+ from https://www.python.org/downloads/
    start https://www.python.org/downloads/
) else (
    for /f "tokens=*" %%i in ('python --version') do echo [OK] %%i detected.
)

:: 3. Check Npcap
echo.
echo [*] Checking Npcap driver...
sc query npcap >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Npcap driver is INSTALLED and ACTIVE.
) else if exist "C:\Windows\System32\Npcap\npcap.dll" (
    echo [OK] Npcap DLL detected in C:\Windows\System32\Npcap.
) else (
    echo [!] Npcap is MISSING! Opening https://npcap.com ...
    echo     [IMPORTANT] Check 'Install Npcap in WinPcap API-Compatible Mode' during install.
    start https://npcap.com/#download
)

:: 4. Check Wireshark / tshark.exe
echo.
echo [*] Checking Wireshark / tshark.exe...
where tshark >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] tshark.exe is available on PATH.
) else if exist "C:\Program Files\Wireshark\tshark.exe" (
    echo [OK] tshark.exe detected at C:\Program Files\Wireshark\tshark.exe
) else (
    echo [!] Wireshark/tshark is MISSING! Opening https://www.wireshark.org ...
    start https://www.wireshark.org/download.html
)

:: 5. Check Nmap
echo.
echo [*] Checking Nmap...
where nmap >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] nmap.exe is available on PATH.
) else if exist "C:\Program Files (x86)\Nmap\nmap.exe" (
    echo [OK] nmap.exe detected in C:\Program Files (x86)\Nmap.
) else (
    echo [i] Nmap is optional (native Python socket scanner is active as fallback).
    echo     Download for enhanced service discovery: https://nmap.org/download.html
)

:: 6. Install Python Dependencies
echo.
echo [*] Installing Python requirements...
python -m pip install -r "%~dp0requirements.txt"
echo.

echo ================================================================
echo  [✓] Dependency check complete!
echo  To start CyberShield Web Dashboard:
echo      python main.py --web
echo ================================================================
echo.
pause
