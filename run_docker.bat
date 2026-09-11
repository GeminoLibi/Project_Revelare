@echo off
REM Project Revelare - Docker Launcher
REM This script builds and runs Project Revelare in a Docker container
REM No Python or dependencies needed - everything is containerized!

echo ========================================
echo Project Revelare - Docker Launcher
echo ========================================
echo.

REM Check if Docker is installed
docker --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Docker is not installed or not in PATH
    echo Please install Docker Desktop from https://www.docker.com/products/docker-desktop
    pause
    exit /b 1
)

REM Check if docker-compose is available
docker-compose --version >nul 2>&1
if errorlevel 1 (
    echo WARNING: docker-compose not found, using docker compose instead
    set USE_COMPOSE=compose
) else (
    set USE_COMPOSE=docker-compose
)

echo Starting Project Revelare...
echo.

REM Build and start the container
%USE_COMPOSE% up -d --build

if errorlevel 1 (
    echo.
    echo ERROR: Failed to start container
    pause
    exit /b 1
)

echo.
echo ========================================
echo Container started successfully!
echo.
echo Web Interface: http://localhost:5000
echo.
echo To view logs: %USE_COMPOSE% logs -f
echo To stop: %USE_COMPOSE% down
echo ========================================
echo.

REM Wait a moment for the server to start
timeout /t 3 /nobreak >nul

REM Try to open browser
start http://localhost:5000

pause
