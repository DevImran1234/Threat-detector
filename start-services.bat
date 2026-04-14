@echo off
REM Start Multi Agentic System
 - Frontend & Backend

echo.
echo ======================================
echo Multi Agentic System
 Launcher
echo ======================================
echo.

REM Check if we're in the right directory
if not exist "frontend" (
    echo Error: frontend directory not found!
    echo Please run this script from the Agent-1 root directory
    pause
    exit /b 1
)

REM Start Backend
echo.
echo [1/2] Starting Backend (Agent-1 Pipeline)...
echo.
start "Agent-1 Backend" cmd /k "title Agent-1 Backend & .\venv\Scripts\activate.bat && python run_pipeline.py --log test"

REM Wait for backend to start
timeout /t 3 /nobreak

REM Start Frontend
echo.
echo [2/2] Starting Frontend (React Dashboard)...
echo.
cd frontend
start "MITRE Pipeline Frontend" cmd /k "title MITRE Pipeline Frontend & npm run dev"

echo.
echo ======================================
echo Services starting up...
echo ======================================
echo.
echo Frontend:  http://localhost:5173
echo Backend:   http://localhost:8000
echo.
echo Press any key to close this launcher window
echo (Services will continue running)
pause
