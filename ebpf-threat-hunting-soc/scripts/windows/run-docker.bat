@echo off
REM Run the full Docker stack (Kafka + sensor + engine + dashboard)
cd /d "%~dp0..\.."
docker version >nul 2>&1 || (echo Docker Desktop is not running. Start it and try again. & pause & goto :eof)
docker compose up --build -d || goto :eof
echo.
echo Waiting for the dashboard to come up...
timeout /t 25 /nobreak >nul
start "" http://localhost:8080
echo Dashboard: http://localhost:8080
echo Logs:      docker compose logs -f
echo Stop:      docker compose down
