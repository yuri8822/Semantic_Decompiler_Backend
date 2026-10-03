@echo off
setlocal
REM Starts the Semantic Decompiler: the backend API, and the web UI if the
REM frontend repo is checked out next to this one (..\Frontend), then opens the
REM browser. Each part runs in its own window; close it (or Ctrl+C) to stop it.
REM
REM   start.bat            API + web UI
REM   start.bat llamacpp   also start a local llama.cpp server (MODEL below)
REM
REM The command line works without any of this: python main.py <binary> --help

REM --- llama.cpp (only used with the llamacpp argument) ------------------------
REM Full path to the GGUF to serve. This one is in the HuggingFace cache; the
REM snapshots\ entry is a symlink to the real blob, which llama follows fine.
set "MODEL=%USERPROFILE%\.cache\huggingface\hub\models--Tesslate--OmniCoder-9B-GGUF\snapshots\c06117a99179f36962d782946970726b9fc9e533\omnicoder-9b-q4_k_m.gguf"
REM Thinking on or off. When on it has a 2048-token budget, drawn from the same
REM generation budget as the answer (the llm.llamacpp.max_tokens setting).
set "THINKING=off"
REM ------------------------------------------------------------------------------

set "ROOT=%~dp0"
set "FRONTEND=%ROOT%..\Frontend"

if /i not "%~1"=="llamacpp" goto start_api
call :start_llamacpp
if errorlevel 1 exit /b 1

:start_api
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

:start_llamacpp
if not exist "%MODEL%" (
  echo llama.cpp model not found: %MODEL%
  echo Set MODEL at the top of start.bat.
  pause
  exit /b 1
)
where llama >nul 2>nul
if errorlevel 1 (
  echo `llama` is not on PATH - add your llama.cpp install to PATH.
  pause
  exit /b 1
)
echo Starting llama.cpp on http://localhost:8080
REM --reasoning-format deepseek routes thoughts to reasoning_content, never to
REM content, so a reasoning trace can't end up inside the generated C++.
start "llama.cpp server" cmd /k llama serve --model "%MODEL%" -ngl 999 -c 49152 -np 1 --reasoning %THINKING% --reasoning-budget 2048 --reasoning-format deepseek
exit /b 0
