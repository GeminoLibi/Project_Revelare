@echo off
REM Project Revelare v2.5.0 - Unified Launcher
REM Windows batch file to start Project Revelare

echo ========================================
echo   PROJECT REVELARE v2.5.0
echo      Unified Launcher
echo ========================================
echo.

cd /d "%~dp0"

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.8+ from https://python.org
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

REM Check if core dependencies are installed
python -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Core dependencies may be missing.
    echo Installing required packages...
    pip install -r requirements.txt
    echo.
)

REM Optional dependencies check
python -c "import pytesseract" >nul 2>&1
if errorlevel 1 (
    echo [INFO] OCR support not available.
    echo For OCR functionality, install Tesseract OCR and run:
    echo pip install pytesseract opencv-python
    echo.
)

python -c "import openai_whisper" >nul 2>&1
if errorlevel 1 (
    echo [INFO] Audio transcription not available.
    echo For transcription, run: pip install openai-whisper
    echo.
)

REM Launch the unified launcher
echo [INFO] Starting Project Revelare v2.5.0...
echo.
python start.py

REM Pause only if there's an error
if errorlevel 1 (
    echo.
    echo [ERROR] Project Revelare exited with an error.
    pause
)
