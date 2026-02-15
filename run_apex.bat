@echo off
echo Starting APEX Security Scanner Platform (Local Mode - SQLite)...

:: 1. Start Backend Service
echo Starting Backend (FastAPI)...
start "APEX Backend (8000)" cmd /k "cd apex-dynamic-service && ..\.venv\Scripts\python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"

:: 2. Start Frontend Dashboard
echo Starting Frontend (Vite)...
start "APEX Frontend (5173)" cmd /k "cd frontend\dashboard && npm run dev"

echo.
echo APEX Platform is initializing!
echo - Frontend: http://localhost:5173
echo - Backend:  http://localhost:8000 (Wait for startup)
echo.
echo Closing this window will keep the services running in their own windows.
pause
