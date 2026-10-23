@echo off
echo Starting ARGUS Backend and Frontend...
start "ARGUS Backend" powershell -NoExit -Command "cd '%~dp0'; .\venv\Scripts\uvicorn.exe api.main:app --host 127.0.0.1 --port 8000 --reload --reload-dir api"
start "ARGUS Frontend" powershell -NoExit -Command "cd '%~dp0sample\FE'; npm run dev"
echo Both servers launched in separate background terminals with live reload!
