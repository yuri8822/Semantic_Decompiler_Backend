@echo off
REM Starts the Semantic Decompiler HTTP API on http://127.0.0.1:8765 in its own
REM console window (`cmd /k` keeps it open so errors stay readable).
REM Interactive API docs: http://127.0.0.1:8765/docs
REM Stop it with Ctrl+C in that window.

start "Semantic Decompiler API" /D "%~dp0" cmd /k python serve.py --port 8765
