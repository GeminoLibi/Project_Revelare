@echo off
REM Create Windows Task Scheduler task for weekly case synchronization
REM Run this as Administrator

set TASK_NAME=ProjectRevelare_CaseSync
set SCRIPT_PATH=%~dp0schedule_case_sync.py
set PYTHON_PATH=python

echo Creating scheduled task: %TASK_NAME%
echo Script: %SCRIPT_PATH%
echo.

REM Delete existing task if it exists
schtasks /Delete /TN "%TASK_NAME%" /F 2>nul

REM Create new task (runs every Monday at 2 AM)
schtasks /Create /TN "%TASK_NAME%" ^
    /TR "\"%PYTHON_PATH%\" \"%SCRIPT_PATH%\"" ^
    /SC WEEKLY ^
    /D MON ^
    /ST 02:00 ^
    /RU SYSTEM ^
    /RL HIGHEST ^
    /F

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Task created successfully!
    echo Task will run every Monday at 2:00 AM
    echo.
    echo To test the task manually, run:
    echo   schtasks /Run /TN "%TASK_NAME%"
    echo.
    echo To view task details:
    echo   schtasks /Query /TN "%TASK_NAME%" /V /FO LIST
    echo.
    echo To delete the task:
    echo   schtasks /Delete /TN "%TASK_NAME%" /F
) else (
    echo.
    echo Failed to create task. Make sure you're running as Administrator.
    echo.
    echo You can also run the sync manually:
    echo   python schedule_case_sync.py
)

pause

