@echo off
REM Project Revelare - PyInstaller Build Script
REM This script builds a standalone .exe file

echo ========================================
echo Project Revelare - Executable Builder
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://www.python.org/
    pause
    exit /b 1
)

REM Check if PyInstaller is installed
python -c "import PyInstaller" >nul 2>&1
if errorlevel 1 (
    echo PyInstaller not found. Installing...
    pip install pyinstaller
    if errorlevel 1 (
        echo ERROR: Failed to install PyInstaller
        pause
        exit /b 1
    )
)

echo.
echo Cleaning previous builds...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist __pycache__ rmdir /s /q __pycache__

echo.
echo Building executable...
echo This may take several minutes...
echo.

REM Build using the spec file
pyinstaller --clean revelare.spec

if errorlevel 1 (
    echo.
    echo ERROR: Build failed!
    pause
    exit /b 1
)

echo.
echo ========================================
echo Build completed successfully!
echo.
echo Executable location: dist\ProjectRevelare.exe
echo.
echo You can now distribute this .exe file along with:
echo   - The cases folder (if it contains data)
echo   - The logs folder (if it contains data)
echo   - Any .env file (optional, for API keys)
echo.
echo Note: The .exe is standalone and includes all dependencies.
echo ========================================
echo.

pause
