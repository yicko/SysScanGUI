@echo off
REM ============================================================
REM  Scan the local system and render an HTML report.
REM
REM  Pure ASCII + CRLF on purpose: cmd.exe decodes .bat files with
REM  the OEM codepage, so a UTF-8 saved batch gets its multi-byte
REM  characters split into fragments that cmd then tries to
REM  execute as commands. All Chinese output is produced by the
REM  Python code instead.
REM ============================================================
chcp 65001 >nul 2>&1
cd /d "%~dp0"

REM --- 1) a virtualenv sitting next to this script (recommended) ---
if exist "%~dp0.venv\Scripts\python.exe" (
    set "PY=%~dp0.venv\Scripts\python.exe"
    goto :ready
)

REM --- 2) any python / py launcher available on PATH ---
where python >nul 2>&1 && set "PY=python"
if not defined PY (
    where py >nul 2>&1 && set "PY=py"
)

:ready
if not defined PY (
    echo [ERROR] No Python interpreter found.
    echo         Install Python 3.9+ from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo ============================================
echo   System Process and Service Security Scan
echo ============================================
echo Interpreter: %PY%

"%PY%" -c "import psutil" >nul 2>&1
if errorlevel 1 (
    echo Dependencies not found - installing ...
    "%PY%" -m pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Failed to install dependencies.
        pause
        exit /b 1
    )
)

"%PY%" scan.py
if errorlevel 1 goto :fail

"%PY%" report.py --json scan_result.json --out report.html
if errorlevel 1 goto :fail

echo.
echo Done. Opening report ...
start "" "report.html"
goto :end

:fail
echo.
echo [ERROR] Scan failed. Check the messages above.

:end
echo.
pause
