@echo off
REM Starts a local llama.cpp server for the decompiler pipeline, in its own
REM Windows Terminal window so it keeps running independently of whatever
REM launched this script (falls back to a plain console if wt isn't present).
REM Listens on http://localhost:8080 (OpenAI-compatible API + built-in chat UI),
REM which is what config.py's LLAMACPP_BASE_URL points at.
REM
REM Expects the `llama` CLI to be a system install resolvable on PATH, and
REM MODEL to be the full path to whichever GGUF you want served. Neither the
REM engine nor any weights live in this repo.
REM
REM MODEL points into the HuggingFace cache: the snapshots/ entry is a symlink
REM to the real blob under blobs/, which llama serve follows fine. Swap in any
REM other cached GGUF by changing the repo/revision/filename below -- the
REM revision hash changes if you pull a different revision of the same repo.

set MODEL=%USERPROFILE%\.cache\huggingface\hub\models--Tesslate--OmniCoder-9B-GGUF\snapshots\c06117a99179f36962d782946970726b9fc9e533\omnicoder-9b-q4_k_m.gguf

REM Thinking switch: on or off. Restart the server after changing it.
set THINKING=off

if "%MODEL%"=="" (
  echo [start_llamacpp] Set MODEL in this script to the full path of a .gguf file first.
  exit /b 1
)

if not exist "%MODEL%" (
  echo [start_llamacpp] Model not found: %MODEL%
  echo                  Check the HuggingFace cache path / revision hash above.
  exit /b 1
)

where llama >nul 2>nul || (
  echo [start_llamacpp] `llama` not found on PATH -- add your llama.cpp install to PATH,
  echo                  or replace `llama` below with its full path.
  exit /b 1
)

REM `-NoExit` keeps the PowerShell session open after the server exits, so a
REM startup error stays readable instead of the window flashing shut.
REM The model path is single-quoted so a %USERPROFILE% containing spaces
REM still passes through as one argument.
REM
REM Thinking is controlled by THINKING above; when on, it has a hard
REM 2048-token budget:
REM   --reasoning %THINKING%  on/off, forced rather than auto-detected from the
REM                           template (OmniCoder's template supports it)
REM   --reasoning-budget 2048 real token cap; -1 (the default) is unrestricted.
REM                           Has no effect when THINKING=off
REM   --reasoning-format deepseek
REM                           thoughts go to `message.reasoning_content`, NOT
REM                           `message.content`. This matters: content is what
REM                           the pipeline writes into recovered.cpp, so the
REM                           default 'auto' is pinned here so a reasoning
REM                           trace can never end up inside the emitted C++.
REM If you change the budget, note that thinking is drawn from the SAME
REM generation budget as the answer (config.py's LLAMACPP_MAX_TOKENS).
start "" wt --title "llama.cpp Server" powershell -NoExit -Command "llama serve --model '%MODEL%' -ngl 999 -c 49152 -np 1 --reasoning %THINKING% --reasoning-budget 2048 --reasoning-format deepseek"
