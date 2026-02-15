@echo off
setlocal
set PYTHONPATH=%~dp0ZAP-python
"%~dp0.venv\Scripts\python.exe" "%~dp0ZAP-python\main.py" %*
endlocal
