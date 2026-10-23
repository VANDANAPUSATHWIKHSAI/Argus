# ARGUS Development Server Launcher
# Starts both Backend (FastAPI) and Frontend (Vite) concurrently

Write-Host "Starting ARGUS Backend (FastAPI on http://127.0.0.1:8000)..." -ForegroundColor Cyan
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot'; .\venv\Scripts\uvicorn.exe api.main:app --host 127.0.0.1 --port 8000 --reload --reload-dir api"

Write-Host "Starting ARGUS Frontend (Vite on http://localhost:5173)..." -ForegroundColor Green
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot\sample\FE'; npm run dev"

Write-Host "Both servers launched with auto-reload!" -ForegroundColor Yellow
