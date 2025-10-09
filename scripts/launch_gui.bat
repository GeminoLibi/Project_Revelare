@echo off
echo Project Revelare v2.5.0 - Archive Explorer GUI
echo ==============================================
echo.
echo [INFO] This launcher has been integrated into the unified launcher.
echo [INFO] Use launch.bat in the project root for all functionality.
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.8+ and try again
    pause
    exit /b 1
)

REM Change to the project root directory
cd /d "%~dp0\..\.."

REM Launch the unified launcher
echo [INFO] Starting unified launcher...
python start.py

pause
