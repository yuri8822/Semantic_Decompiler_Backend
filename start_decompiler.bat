@echo off
setlocal
REM Launches the Semantic Decompiler on a binary in its own console window;
REM `cmd /k` keeps the window open afterwards so errors stay readable.
REM
REM Usage (any of):
REM   - drag an .exe onto this file
REM   - start_decompiler.bat path\to\program.exe
REM   - double-click and paste/drag the path when asked
REM
REM If the binary was run before, asks whether to resume where that run
REM stopped (the default) or start over, which deletes its workspace after a
REM confirmation that defaults to no.
REM Then asks how many functions to process: try a small number (e.g. 10) on a
REM new binary to gauge time and cost; press Enter for all.
REM
REM Provider: deepseek (needs DEEPSEEK_API_KEY in .env). Others: anthropic,
REM xiaomi, ollama, llamacpp -- for local servers also add --concurrency 1.
REM Other flags (python main.py --help): --rounds N, --no-ghidra-apply,
REM --no-compile.

set "BINARY=%~1"
if not defined BINARY set /p "BINARY=Path to the executable (or drag it here): "
if not defined BINARY (
  echo No executable given.
  pause
  exit /b 1
)
REM Dragging into the prompt adds quotes; strip them, then make the path
REM absolute, since the window below starts in this script's directory.
set "BINARY=%BINARY:"=%"
for %%I in ("%BINARY%") do set "BINARY=%%~fI"
if not exist "%BINARY%" (
  echo Not found: %BINARY%
  pause
  exit /b 1
)

set "EXTRA="

REM A previous run of this binary lives in workspace\<file name without extension>.
REM Prompts use `set /p` rather than `choice`, which beeps on every invalid key.
for %%I in ("%BINARY%") do set "WORKSPACE=%~dp0workspace\%%~nI"
if not exist "%WORKSPACE%\knowledge.json" goto ask_limit
echo A previous run of this binary exists in %WORKSPACE%

:ask_mode
set "MODE="
set /p "MODE=[R]esume it or [S]tart over? (Enter = resume) "
if not defined MODE goto ask_limit
if /i "%MODE%"=="R" goto ask_limit
if /i "%MODE%"=="S" goto ask_confirm
echo Please type R or S.
goto ask_mode

:ask_confirm
set "SURE="
set /p "SURE=Start over deletes that workspace (analyses, LLM logs, output). Sure? [y/N] "
if /i not "%SURE%"=="Y" (
  echo Cancelled.
  pause
  exit /b 0
)
set "EXTRA=--restart"

:ask_limit
set "LIMIT="
set /p "LIMIT=Only process the first N functions (Enter = all): "
if defined LIMIT set "EXTRA=%EXTRA% --limit %LIMIT%"

start "Semantic Decompiler" /D "%~dp0" cmd /k python main.py "%BINARY%" --provider deepseek %EXTRA%
