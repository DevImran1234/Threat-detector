#!/usr/bin/env pwsh
# Start MITRE Security Pipeline - Frontend & Backend

Write-Host "`n======================================" -ForegroundColor Cyan
Write-Host "MITRE Security Pipeline Launcher" -ForegroundColor Cyan
Write-Host "======================================`n" -ForegroundColor Cyan

# Check if we're in the right directory
if (-not (Test-Path "frontend")) {
    Write-Host "Error: frontend directory not found!" -ForegroundColor Red
    Write-Host "Please run this script from the Agent-1 root directory"
    Read-Host "Press Enter to exit"
    exit 1
}

# Display startup info
Write-Host "[*] Starting MITRE Security Pipeline Services..." -ForegroundColor Yellow

# Start Backend in a new terminal
Write-Host "[1/2] Starting Backend (Agent-1 Pipeline)..." -ForegroundColor Green
$backendProcess = Start-Process powershell -ArgumentList {
    Set-Location "c:\Users\Admin\Documents\Agent-1"
    .\venv\Scripts\Activate.ps1
    Write-Host "`n🚀 Activating Virtual Environment..." -ForegroundColor Green
    Write-Host "📊 Starting MITRE Security Pipeline..." -ForegroundColor Green
    python run_pipeline.py
    Read-Host "`nPress Enter to close this window"
} -PassThru -WindowStyle Normal

# Wait for backend to initialize
Write-Host "[*] Backend initializing..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

# Start Frontend in a new terminal
Write-Host "[2/2] Starting Frontend (React Dashboard)..." -ForegroundColor Green
$frontendProcess = Start-Process powershell -ArgumentList {
    Set-Location "c:\Users\Admin\Documents\Agent-1\frontend"
    Write-Host "`n🎨 Starting React Frontend..." -ForegroundColor Green
    npm run dev
    Read-Host "`nPress Enter to close this window"
} -PassThru -WindowStyle Normal

# Display service URLs
Write-Host "`n======================================" -ForegroundColor Cyan
Write-Host "✅ Services Starting..." -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "`n📱 Frontend:  https://localhost:5173" -ForegroundColor Cyan
Write-Host "🔌 Backend:   http://localhost:8000" -ForegroundColor Cyan
Write-Host "`n💡 Tip: Logs for both services appear in their respective windows`n" -ForegroundColor Yellow

# Wait for services to be ready
Write-Host "`n⏳ Waiting for services to be ready (usually 10-15 seconds)...`n" -ForegroundColor Yellow
Start-Sleep -Seconds 5

# Open frontend in browser
Write-Host "🌐 Opening Frontend in Browser..." -ForegroundColor Green
Start-Sleep -Seconds 2
Start-Process "http://localhost:5173"

Write-Host "`n✨ All services are running!`n" -ForegroundColor Green
Write-Host "Press CTRL+C in any terminal window to stop a service`n" -ForegroundColor Yellow
