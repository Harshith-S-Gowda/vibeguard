@echo off
setlocal
cd /d "%~dp0"
echo ======================================================================
echo    SHIPSAFE: Hardware-Aware Embedded Dependency Security
echo    The Big Hack 2.0 (Bengaluru) - Track 03: AI Research (R1)
echo ======================================================================
echo.

if exist "D:\uv\python\cpython-3.12.16-windows-x86_64-none\python.exe" (
    set "PYTHON_CMD=D:\uv\python\cpython-3.12.16-windows-x86_64-none\python.exe"
) else (
    set "PYTHON_CMD=python"
)

echo Starting ShipSafe Server on http://127.0.0.1:8000 ...
"%PYTHON_CMD%" run.py 8000
pause
