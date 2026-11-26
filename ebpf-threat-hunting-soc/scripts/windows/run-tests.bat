@echo off
REM Run the test-suite on Windows
cd /d "%~dp0..\.."
call .venv\Scripts\activate.bat
pip install -r requirements-dev.txt
python -m pytest -q
