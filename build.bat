@echo off
setlocal
cd /d "%~dp0"
echo ========================================
echo MAC Finder Pro - Windows EXE Builder
echo ========================================
python --version >nul 2>&1 || (echo Python 3.11+ is required.& pause & exit /b 1)
python -c "import sys; assert sys.version_info >= (3,11), 'Python 3.11 or later is required'" || (pause & exit /b 1)
python -m pip install --upgrade pip || exit /b 1
python -m pip install -r requirements.txt pyinstaller || exit /b 1
set SCAPY_FLAG=
python -c "import scapy" >nul 2>&1 && set SCAPY_FLAG=--collect-all scapy
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
python -m compileall -q main.py mac_finder tests || exit /b 1
python -m unittest discover -s tests -v || exit /b 1
python -m PyInstaller --noconfirm --clean --onefile --windowed --name MACFinder --collect-all psutil %SCAPY_FLAG% main.py
if errorlevel 1 (echo BUILD FAILED.& pause & exit /b 1)
if not exist dist\MACFinder.exe (echo EXE NOT FOUND.& pause & exit /b 1)
echo BUILD OK: dist\MACFinder.exe
pause
