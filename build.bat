@echo off
:: Build.bat - MAC Finder Windows EXE Builder
:: Requires Python 3, pip, PyInstaller

echo =========================================
echo MAC Finder - Windows EXE Builder
echo =========================================

:: Check Python installation
python --version >nul 2>&1
if errorlevel 1 (
    echo Hata: Python bulunamadi!
    echo Python'u yukleyip yeniden deneyin.
    pause
    exit /b 1
)

:: Check PyInstaller
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo PyInstaller kurulu degil. Yukleniyor...
    pip install pyinstaller
    if errorlevel 1 (
        echo Hata: PyInstaller yuklenemedi!
        pause
        exit /b 1
    )
)

:: Install dependencies
echo Bagimliliklar yukleniyor...
pip install -r requirements.txt
if errorlevel 1 (
    echo Uyarı: Bazı bagimliliklar yuklenemedi. Devam ediliyor...
)

:: Clean old build
echo Eski build dosyaları temizleniyor...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist *.spec del *.spec

:: Build EXE
echo EXE olusturuluyor...
python -m PyInstaller ^
    --name "MACFinder" ^
    --onefile ^
    --windowed ^
    --noconsole ^
    --add-data "requirements.txt;." ^
    main.py

if errorlevel 1 (
    echo Hata: Build basarisiz oldu!
    pause
    exit /b 1
)

echo =========================================
echo Basarili! EXE dosyasi: dist\MACFinder.exe
echo =========================================

pause