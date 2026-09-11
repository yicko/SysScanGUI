@echo off
REM ============================================================
REM  Launch the SysScanGUI graphical interface.
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
    set "PYW=%~dp0.venv\Scripts\pythonw.exe"
    goto :ready
)

REM --- 2) any python / py launcher available on PATH ---
where pythonw >nul 2>&1 && set "PYW=pythonw"
where python  >nul 2>&1 && set "PY=python"
if not defined PY (
    where py >nul 2>&1 && set "PY=py"
)

:ready
if not defined PY (
    echo [ERROR] No Python interpreter found.
    echo         Install Python 3.9+ from https://www.python.org/downloads/
    echo         then run:  pip install -r requirements.txt
    pause
    exit /b 1
)

"%PY%" -c "import PySide6.QtWidgets, psutil" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Missing dependency: PySide6-Essentials and/or psutil.
    echo         Run:  pip install -r requirements.txt
    pause
    exit /b 1
)

if not defined PYW set "PYW=%PY%"
start "" "%PYW%" gui.py
exit /b 0
