# Start the API Server
# This script starts the FastAPI server on port 8000

Write-Host "🚀 Starting Multi Agentic System
 API Server..." -ForegroundColor Green
Write-Host "API will be available at http://localhost:8000" -ForegroundColor Cyan
Write-Host "API Documentation at http://localhost:8000/docs" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""

# Activate virtual environment
$venvPath = ".\.venv\Scripts\Activate.ps1"
if (Test-Path $venvPath) {
    Write-Host "Activating virtual environment..." -ForegroundColor Yellow
    & $venvPath
} else {
    Write-Host "Warning: Virtual environment not found at $venvPath" -ForegroundColor Red
}

# Start the API server using Python directly
Write-Host "Starting API server..." -ForegroundColor Green
python api_server.py

Write-Host "API Server stopped" -ForegroundColor Yellow
