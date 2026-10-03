@echo off
REM Launches the Semantic Decompiler in its own console window; `cmd /k` keeps
REM the window open afterwards so errors stay readable.
REM %~dp0 = this script's directory, so it works from anywhere.
REM
REM --provider: anthropic | xiaomi | deepseek | ollama | llamacpp
REM   Cloud providers need their API key in .env (ANTHROPIC_API_KEY,
REM   XIAOMI_API_KEY, DEEPSEEK_API_KEY). For llamacpp start the server first
REM   with start_llamacpp.bat, and pass --concurrency 1 for local servers.
REM
REM Other useful flags (python main.py --help for all):
REM   --restart          discard this binary's workspace and start over
REM                      (without it, a rerun resumes where the last one stopped)
REM   --limit N          only process the first N functions
REM   --rounds N         analyze -> apply to Ghidra -> re-decompile rounds
REM   --no-ghidra-apply  skip the Ghidra feedback loop
REM   --no-compile       skip compiler validation and the CMake build

start "Semantic Decompiler" /D "%~dp0" cmd /k python main.py "TestBinaries\Chess.exe" --provider deepseek
