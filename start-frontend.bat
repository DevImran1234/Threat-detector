@echo off
REM Start the Frontend Development Server
REM This script starts the Vite dev server on port 5173

echo.
echo ====================================
echo   Multi Agentic System
 Frontend
echo ====================================
echo.
echo Starting frontend on http://localhost:5173
echo.

cd frontend

REM Check if node_modules exists
if not exist "node_modules" (
    echo Installing dependencies...
    call npm install
)

echo.
echo Starting Vite development server...
echo Press Ctrl+C to stop
echo.

call npm run dev

pause
