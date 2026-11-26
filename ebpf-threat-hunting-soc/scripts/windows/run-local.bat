@echo off
REM Run the whole SOC in one Python process (no Docker needed)
cd /d "%~dp0..\.."
if not exist .venv (
  echo Creating virtual environment...
  python -m venv .venv || goto :nopython
)
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip >nul
pip install -r requirements.txt || goto :eof
echo.
echo Dashboard: http://localhost:8080   (press Ctrl+C to stop)
start "" http://localhost:8080
python -m soc.run_all
goto :eof
:nopython
echo Python was not found. Install Python 3.11+ from https://www.python.org/downloads/ and tick "Add python.exe to PATH".
pause
