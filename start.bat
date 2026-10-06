@echo off
setlocal
REM Starts the Semantic Decompiler: the backend API, and the web UI if the
REM frontend repo is checked out next to this one (..\Frontend), then opens the
REM browser. Each part runs in its own window; close it (or Ctrl+C) to stop it.
REM
REM A local llama.cpp server is launched by the backend itself: pick the model
REM and options on the web UI's "Local model" page.
REM
REM The command line works without any of this: python main.py <binary> --help

set "ROOT=%~dp0"
set "FRONTEND=%ROOT%..\Frontend"

echo Starting the backend API on http://127.0.0.1:8765
start "Semantic Decompiler API" /D "%ROOT%" cmd /k python serve.py --port 8765

if not exist "%FRONTEND%\package.json" goto no_frontend
if exist "%FRONTEND%\node_modules" goto start_ui
echo Installing frontend dependencies - first run only...
pushd "%FRONTEND%"
call npm install --no-fund --no-audit
popd

:start_ui
echo Starting the web UI on http://localhost:5173
start "Semantic Decompiler UI" /D "%FRONTEND%" cmd /k npm run dev
call :wait_for http://localhost:5173
start "" http://localhost:5173
exit /b 0

:no_frontend
echo No frontend found at %FRONTEND% - opening the API docs instead.
call :wait_for http://127.0.0.1:8765/api/health
start "" http://127.0.0.1:8765/docs
exit /b 0

REM Polls a URL until it answers, up to about a minute.
:wait_for
for /l %%i in (1,1,60) do (
  curl -s -o nul "%~1" && exit /b 0
  ping -n 2 127.0.0.1 >nul
)
echo Timed out waiting for %~1 - check the other windows for errors.
exit /b 0
