@echo off
cd /d "%~dp0"

echo.
echo  ╔══════════════════════════════════════════════╗
echo  ║   APEX Security Scanner - Stopping...        ║
echo  ╚══════════════════════════════════════════════╝
echo.

docker compose down
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo  [ERROR] Failed to stop services. Is Docker running?
    pause
    exit /b 1
)

echo.
echo  ╔══════════════════════════════════════════════╗
echo  ║   All APEX services stopped.                 ║
echo  ╚══════════════════════════════════════════════╝
echo.
pause
