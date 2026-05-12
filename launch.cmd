@echo off
title Wardrive Mission Control
cd /d "%~dp0"

echo.
echo  ============================================================
echo   WARDRIVE MISSION CONTROL
echo  ============================================================
echo.

:: Check Python is available
where python >nul 2>&1
if errorlevel 1 (
    echo  [X] Python not found in PATH. Install Python 3.11+ and retry.
    pause
    exit /b 1
)

:: Print Python version
for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo  [*] Runtime: %%v

:: Auto-install required packages if missing
echo  [*] Checking dependencies...
python -c "import dpkt" >nul 2>&1
if errorlevel 1 (
    echo  [!] dpkt not found -- installing...
    python -m pip install dpkt --quiet
    if errorlevel 1 (
        echo  [X] Failed to install dpkt. PCAP parsing will be disabled.
    ) else (
        echo  [+] dpkt installed.
    )
)
python -c "import openpyxl" >nul 2>&1
if errorlevel 1 (
    echo  [!] openpyxl not found -- installing...
    python -m pip install openpyxl --quiet
)

:: Check entry point exists
if not exist "%~dp0run_step3d_scene.py" (
    echo  [X] run_step3d_scene.py not found in %~dp0
    pause
    exit /b 1
)

echo  [*] Working dir: %~dp0
echo  [*] Launching...
echo.

python run_step3d_scene.py

if errorlevel 1 (
    echo.
    echo  [X] App exited with an error (code %errorlevel%).
    echo      Check the output above for details.
    pause
)
