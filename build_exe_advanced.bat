@echo off
REM Project Revelare - Advanced PyInstaller Build Script
REM This script builds a standalone .exe with additional options

echo ========================================
echo Project Revelare - Advanced Executable Builder
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    pause
    exit /b 1
)

REM Check if PyInstaller is installed
python -c "import PyInstaller" >nul 2>&1
if errorlevel 1 (
    echo PyInstaller not found. Installing...
    pip install pyinstaller
)

echo.
echo Select build mode:
echo [1] Console mode (shows console window)
echo [2] Windowed mode (no console window)
echo [3] One-file mode (single .exe, slower startup)
echo [4] One-directory mode (faster startup, multiple files)
echo.
set /p mode="Enter choice (1-4): "

echo.
echo Cleaning previous builds...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

echo.
echo Building executable...
echo.

if "%mode%"=="1" (
    REM Console mode, one-file
    pyinstaller --onefile --console --name ProjectRevelare --add-data "revelare/web/templates;revelare/web/templates" --add-data "revelare/web/static;revelare/web/static" --hidden-import flask --hidden-import werkzeug --hidden-import jinja2 --hidden-import maxminddb revelare_launcher.py
) else if "%mode%"=="2" (
    REM Windowed mode, one-file
    pyinstaller --onefile --windowed --name ProjectRevelare --add-data "revelare/web/templates;revelare/web/templates" --add-data "revelare/web/static;revelare/web/static" --hidden-import flask --hidden-import werkzeug --hidden-import jinja2 --hidden-import maxminddb revelare_launcher.py
) else if "%mode%"=="3" (
    REM One-file mode with console
    pyinstaller --onefile --console --name ProjectRevelare --add-data "revelare/web/templates;revelare/web/templates" --add-data "revelare/web/static;revelare/web/static" --hidden-import flask --hidden-import werkzeug --hidden-import jinja2 --hidden-import maxminddb revelare_launcher.py
) else if "%mode%"=="4" (
    REM One-directory mode (faster)
    pyinstaller --onedir --console --name ProjectRevelare --add-data "revelare/web/templates;revelare/web/templates" --add-data "revelare/web/static;revelare/web/static" --hidden-import flask --hidden-import werkzeug --hidden-import jinja2 --hidden-import maxminddb revelare_launcher.py
) else (
    echo Invalid choice. Using default (console, one-file)...
    pyinstaller --onefile --console --name ProjectRevelare --add-data "revelare/web/templates;revelare/web/templates" --add-data "revelare/web/static;revelare/web/static" --hidden-import flask --hidden-import werkzeug --hidden-import jinja2 --hidden-import maxminddb revelare_launcher.py
)

if errorlevel 1 (
    echo.
    echo ERROR: Build failed!
    pause
    exit /b 1
)

echo.
echo ========================================
echo Build completed!
echo ========================================
echo.

pause
