@echo off
echo ============================================================
echo   BruteShield - Brute Force Attack Detection Tool
echo ============================================================
echo.
echo Starting server at http://localhost:8000
echo Press Ctrl+C to stop.
echo.
cd /d "%~dp0backend"
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
