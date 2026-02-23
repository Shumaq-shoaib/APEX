@echo off
REM APEX Security Scanner - Single Run Script
REM Starts backend, frontend, and database via Docker Compose

cd /d "%~dp0"

echo.
echo ============================================
echo   APEX Security Scanner - Starting...
echo ============================================
echo.

REM Try docker compose (new) first, fallback to docker-compose (legacy)
where docker compose >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    docker compose up -d
) else (
    docker-compose up -d
)

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Failed to start APEX. Ensure Docker is installed and running.
    pause
    exit /b 1
)

echo.
echo ============================================
echo   APEX is running!
echo ============================================
echo   Frontend:  http://localhost:5173
echo   Backend:   http://localhost:8000
echo   Database:  localhost:3306
echo ============================================
echo.
echo To stop: docker compose down
echo.
pause
