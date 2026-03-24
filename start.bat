@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

echo.
echo  ╔══════════════════════════════════════════════╗
echo  ║   APEX Security Scanner - Starting...        ║
echo  ╚══════════════════════════════════════════════╝
echo.

:: ── 1. Pre-flight checks ──────────────────────────
where docker >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo  [ERROR] Docker is not installed or not in PATH.
    echo          Install Docker Desktop: https://docs.docker.com/desktop/install/windows/
    pause
    exit /b 1
)

docker info >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo  [ERROR] Docker daemon is not running. Please start Docker Desktop.
    pause
    exit /b 1
)

:: ── 2. Start services via Docker Compose ──────────
echo  [1/3] Building and starting containers...
echo.

docker compose up -d --build
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo  [ERROR] Docker Compose failed. Check the logs above.
    pause
    exit /b 1
)

:: ── 3. Health checks ──────────────────────────────
echo.
echo  [2/3] Waiting for services to become healthy...

set BACKEND_READY=0
set FRONTEND_READY=0
set MAX_ATTEMPTS=30

for /L %%i in (1,1,%MAX_ATTEMPTS%) do (
    if !BACKEND_READY! EQU 0 (
        curl -s -o nul -w "%%{http_code}" http://localhost:8000/docs | findstr /B "200" >nul 2>&1
        if !ERRORLEVEL! EQU 0 (
            set BACKEND_READY=1
            echo         Backend  ✓ ready
        )
    )
    if !FRONTEND_READY! EQU 0 (
        curl -s -o nul -w "%%{http_code}" http://localhost:5173 | findstr /B "200" >nul 2>&1
        if !ERRORLEVEL! EQU 0 (
            set FRONTEND_READY=1
            echo         Frontend ✓ ready
        )
    )
    if !BACKEND_READY! EQU 1 if !FRONTEND_READY! EQU 1 goto :health_done
    timeout /t 2 /nobreak >nul
)

:health_done

:: ── 4. Status report ──────────────────────────────
echo.
echo  [3/3] Container status:
echo  ─────────────────────────────────────────────
docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
echo.

if !BACKEND_READY! EQU 0 (
    echo  [WARN] Backend did not respond within timeout. Check: docker compose logs backend
)
if !FRONTEND_READY! EQU 0 (
    echo  [WARN] Frontend did not respond within timeout. Check: docker compose logs frontend
)

echo.
echo  ╔══════════════════════════════════════════════╗
echo  ║   APEX is running!                           ║
echo  ║                                              ║
echo  ║   Frontend:  http://localhost:5173            ║
echo  ║   Backend:   http://localhost:8000            ║
echo  ║   API Docs:  http://localhost:8000/docs       ║
echo  ║   Database:  localhost:3306                   ║
echo  ║                                              ║
echo  ║   Stop with:  stop.bat                       ║
echo  ╚══════════════════════════════════════════════╝
echo.
pause
